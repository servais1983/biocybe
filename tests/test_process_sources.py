"""Tests des sources temps réel (proc connector Linux, Sysmon Windows)."""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import time

import pytest

from biocybe.process_monitor import ProcessMonitor, ProcessRule, load_rules
from biocybe.process_sources import (
    PROC_EVENT_EXEC,
    PROC_EVENT_FORK,
    NetlinkProcSource,
    SourceUnavailable,
    SysmonSource,
    build_source,
    parse_proc_connector,
    parse_sysmon_events,
)

# --------------------------------------------------------------------------- #
# Proc connector : décodage + traitement (sans noyau)
# --------------------------------------------------------------------------- #


def _nl_msg(what: int, body: bytes) -> bytes:
    ev = struct.pack("=IIQ", what, 0, 0) + body
    cn = struct.pack("=IIIIHH", 1, 1, 0, 0, len(ev), 0) + ev
    return struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, 0) + cn


def test_parse_proc_connector_fork_exec_and_garbage():
    data = (
        _nl_msg(PROC_EVENT_FORK, struct.pack("=IIII", 10, 10, 11, 11))
        + _nl_msg(PROC_EVENT_EXEC, struct.pack("=II", 11, 11))
        + _nl_msg(0x80000000, struct.pack("=IIII", 11, 11, 0, 0))  # exit : ignoré
    )
    assert parse_proc_connector(data) == [
        (PROC_EVENT_FORK, (10, 10, 11, 11)),
        (PROC_EVENT_EXEC, (11, 11)),
    ]
    assert parse_proc_connector(b"\x01\x02") == []
    assert parse_proc_connector(b"\xff" * 64) == []  # longueur absurde -> stop propre


def _fake_proc(root, pid, *, name, cmdline, ppid, exe=None):
    d = root / str(pid)
    d.mkdir(parents=True)
    (d / "cmdline").write_bytes(b"\0".join(c.encode() for c in cmdline) + b"\0")
    (d / "comm").write_text(name + "\n")
    (d / "status").write_text(f"Name:\t{name}\nPPid:\t{ppid}\nUid:\t0\t0\t0\t0\n")
    os.symlink(exe or f"/usr/bin/{name}", d / "exe")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="symlinks /proc Linux")
def test_netlink_handle_exec_with_parent_context(tmp_path):
    _fake_proc(tmp_path, 500, name="php-fpm", cmdline=["php-fpm: pool www"], ppid=1)
    _fake_proc(tmp_path, 501, name="sh", cmdline=["sh", "-c", "id"], ppid=500, exe="/bin/sh")
    got = []
    src = NetlinkProcSource(got.append, proc_root=tmp_path)
    src.handle(PROC_EVENT_FORK, (500, 500, 501, 501))
    ev = src.handle(PROC_EVENT_EXEC, (501, 501))
    assert got == [ev]
    assert (ev.pid, ev.ppid, ev.name, ev.exe) == (501, 500, "sh", "/bin/sh")
    assert ev.cmdline == "sh -c id"
    assert ev.parent_name == "php-fpm" and ev.username in ("root", "0")
    ids = {m.rule.rule_id for m in ProcessMonitor(load_rules(), provider=list).evaluate(ev)}
    assert "webserver_spawns_shell" in ids


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="symlinks /proc Linux")
def test_netlink_partial_event_when_process_already_gone(tmp_path):
    _fake_proc(tmp_path, 600, name="bash", cmdline=["bash"], ppid=1)
    got = []
    src = NetlinkProcSource(got.append, proc_root=tmp_path)
    src.handle(PROC_EVENT_FORK, (600, 600, 601, 601))
    ev = src.handle(PROC_EVENT_EXEC, (601, 601))  # /proc/601 n'existe pas
    assert ev is not None and ev.pid == 601 and ev.ppid == 600
    assert ev.parent_name == "bash" and ev.name == ""
    assert src.stats["partial_events"] == 1  # compté, jamais perdu en silence


def test_netlink_ignores_threads(tmp_path):
    src = NetlinkProcSource(lambda e: None, proc_root=tmp_path)
    assert src.handle(PROC_EVENT_FORK, (1, 1, 7, 6)) is None  # thread (pid != tgid)
    assert src.handle(PROC_EVENT_EXEC, (7, 6)) is None
    assert src.stats["fork_events"] == 0 and src.stats["exec_events"] == 0


_REAL_NETLINK = sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0


@pytest.mark.skipif(not _REAL_NETLINK, reason="proc connector réel : Linux + root")
def test_real_kernel_sees_millisecond_process():
    """Preuve du gain : un processus qui vit quelques ms (invisible au
    polling 2 s) est reçu du noyau."""
    got = []
    src = NetlinkProcSource(got.append)
    try:
        src.start()
    except SourceUnavailable as exc:
        pytest.skip(f"proc connector indisponible ici : {exc}")
    try:
        time.sleep(0.2)
        child = subprocess.run(["/bin/sh", "-c", "exit 0"], check=True)
        assert child.returncode == 0
        deadline = time.time() + 3
        while time.time() < deadline and not any(e.ppid == os.getpid() for e in got):
            time.sleep(0.05)
    finally:
        src.stop()
    mine = [e for e in got if e.ppid == os.getpid()]
    assert mine, f"exec du processus éphémère non reçu ({len(got)} événements vus)"
    assert src.stats["exec_events"] >= 1


# --------------------------------------------------------------------------- #
# Sysmon (parsing + signet, sans Windows)
# --------------------------------------------------------------------------- #

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _sysmon_xml(record_id: int, event_id: int = 1, **data) -> str:
    fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (
        f"<Event xmlns='{_NS}'><System><EventID>{event_id}</EventID>"
        f"<EventRecordID>{record_id}</EventRecordID></System>"
        f"<EventData>{fields}</EventData></Event>"
    )


_VSS = dict(
    ProcessId="4321",
    ParentProcessId="1234",
    Image=r"C:\Windows\System32\vssadmin.exe",
    CommandLine="vssadmin.exe delete shadows /all /quiet",
    ParentImage=r"C:\Windows\System32\cmd.exe",
    ParentCommandLine="cmd.exe /c x.bat",
    User=r"CORP\alice",
)


def test_parse_sysmon_process_create():
    xml = _sysmon_xml(42, **_VSS) + _sysmon_xml(43, event_id=3, Image="x")  # EID 3 ignoré
    events = parse_sysmon_events(xml)
    assert len(events) == 1
    rid, ev = events[0]
    assert rid == 42 and ev.pid == 4321 and ev.ppid == 1234
    assert ev.name == "vssadmin.exe" and ev.parent_name == "cmd.exe"
    assert ev.username == r"CORP\alice"
    ids = {m.rule.rule_id for m in ProcessMonitor(load_rules(), provider=list).evaluate(ev)}
    assert "shadow_copy_deletion" in ids


def test_parse_sysmon_garbage_is_safe():
    assert parse_sysmon_events("") == []
    assert parse_sysmon_events("<not xml") == []
    assert parse_sysmon_events(_sysmon_xml(1, ProcessId="abc", Image="x")) == []


class FakeWevtutil:
    def __init__(self):
        self.log: list[tuple[int, str]] = []
        self.calls: list[list[str]] = []

    def add(self, rid, **data):
        self.log.append((rid, _sysmon_xml(rid, **data)))

    def __call__(self, cmd):
        self.calls.append(cmd)
        if cmd[1] == "gl":
            return "name: Microsoft-Windows-Sysmon/Operational"
        q = next(a for a in cmd if a.startswith("/q:"))
        reverse = "/rd:true" in cmd
        count = int(next(a for a in cmd if a.startswith("/c:"))[3:])
        floor = int(q.split("EventRecordID>")[1].split("]")[0]) if "EventRecordID>" in q else -1
        items = [x for r, x in self.log if r > floor]
        items = list(reversed(items)) if reverse else items
        return "".join(items[:count])


def test_sysmon_source_bookmark_no_replay_no_duplicates():
    fake = FakeWevtutil()
    fake.add(10, **_VSS)  # historique : ne doit PAS être rejoué
    got = []
    src = SysmonSource(got.append, runner=fake)
    src.check_available()
    src._last_record = parse_sysmon_events(fake.log[-1][1])[0][0]  # signet comme start()
    assert src.poll_once() == []
    fake.add(11, **{**_VSS, "ProcessId": "1"})
    fake.add(12, **{**_VSS, "ProcessId": "2"})
    assert [e.pid for e in src.poll_once()] == [1, 2]
    assert src.poll_once() == []  # pas de doublon
    assert [e.pid for e in got] == [1, 2]


def test_sysmon_unavailable():
    def missing(cmd):
        raise FileNotFoundError("wevtutil")

    with pytest.raises(SourceUnavailable):
        SysmonSource(lambda e: None, runner=missing).check_available()


# --------------------------------------------------------------------------- #
# Sélection + repli
# --------------------------------------------------------------------------- #


def test_build_source_poll_and_unknown():
    assert build_source("poll", lambda e: None) is None
    with pytest.raises(SourceUnavailable):
        build_source("ebpf-magic", lambda e: None)


def test_monitor_falls_back_to_poll_when_source_unavailable(monkeypatch):
    from biocybe import process_sources

    def unavailable(*a, **k):
        raise SourceUnavailable("test")

    monkeypatch.setattr(process_sources, "build_source", unavailable)
    mon = ProcessMonitor(load_rules(), provider=list, source="netlink", interval=0.5)
    mon.start()
    try:
        assert mon.active_source == "poll"
    finally:
        mon.stop()


def test_monitor_routes_source_events_through_rules(monkeypatch):
    from biocybe import process_sources

    class FakeSource:
        name = "fake"

        def __init__(self, cb):
            self.cb = cb
            self.stats = {"events": 0}

        def start(self):
            pass

        def stop(self):
            pass

    holder = {}

    def build(kind, cb, **kw):
        holder["src"] = FakeSource(cb)
        return holder["src"]

    monkeypatch.setattr(process_sources, "build_source", build)
    got = []
    rule = ProcessRule("t_rt", "t", 50, {"name": "evil"})
    mon = ProcessMonitor([rule], provider=list, source="auto", on_match=got.append)
    mon.start()
    try:
        assert mon.active_source == "fake"
        from biocybe.process_monitor import ProcessEvent

        holder["src"].cb(ProcessEvent(pid=9, ppid=1, name="evil", exe="/x/evil", cmdline="evil"))
    finally:
        mon.stop()
    assert [m.event.pid for m in got] == [9]
