"""Capteur d'injection mémoire : classification, /proc factice, vrais processus, Sysmon."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from biocybe.injection_monitor import (
    InjectionMonitor,
    InjectionScanner,
    classify_region,
    parse_maps_line,
    parse_sysmon_injection_events,
)

LINUX = sys.platform.startswith("linux")


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        ("7f00-7f01 rwxp 00000000 00:00 0 ", "wx_anon"),
        ("7f00-7f01 r-xp 00000000 00:00 0", "anon_exec"),
        ("7f00-7f01 rwxs 00000000 00:01 4 /dev/zero (deleted)", "wx_anon"),  # partagé anonyme
        ("7f00-7f01 r-xp 00000000 00:01 9 /memfd:payload (deleted)", "memfd_exec"),
        ("7f00-7f01 r-xp 00000000 08:01 5 /tmp/x (deleted)", "deleted_exec"),
        ("7f00-7f01 rwxp 00000000 00:00 0 [heap]", "wx_anon"),
        ("7f00-7f01 r-xp 00000000 08:01 5 /usr/lib/libc.so.6", None),
        ("7f00-7f01 rw-p 00000000 00:00 0", None),  # non exécutable
        ("7f00-7f01 r-xp 00000000 00:00 0 [vdso]", None),
    ],
)
def test_classify_region(line, kind):
    assert classify_region(parse_maps_line(line)) == kind


def test_parse_maps_garbage():
    assert parse_maps_line("n'importe quoi") is None
    assert parse_maps_line("zz-yy r-xp 0 0 0") is None


# --------------------------------------------------------------------------- #
# /proc factice
# --------------------------------------------------------------------------- #


def _fake_proc(root, pid, *, comm, exe, maps, tracer=0, environ=b""):
    d = root / str(pid)
    d.mkdir(parents=True)
    (d / "comm").write_text(comm + "\n")
    (d / "maps").write_text(maps)
    (d / "status").write_text(f"Name:\t{comm}\nTracerPid:\t{tracer}\n")
    (d / "environ").write_bytes(environ)
    os.symlink(exe, d / "exe")


@pytest.mark.skipif(not LINUX, reason="symlinks /proc Linux")
def test_scan_fake_proc(tmp_path):
    _fake_proc(
        tmp_path,
        10,
        comm="sshd",
        exe="/usr/sbin/sshd",
        maps="5500-5600 r-xp 0 08:01 1 /usr/sbin/sshd\n7f00-7f21 rwxp 0 00:00 0\n"
        "7f30-7f31 rwxp 0 00:00 0\n",  # 2e région RWX : un seul constat par type
    )
    _fake_proc(tmp_path, 11, comm="java", exe="/usr/bin/java", maps="7f00-7f21 rwxp 0 00:00 0\n")
    _fake_proc(
        tmp_path,
        12,
        comm="runc",
        exe="/memfd:runc_cloned:/proc/self/exe (deleted)",
        maps="7f00-7f21 r-xp 0 00:01 3 /memfd:runc_cloned:/proc/self/exe (deleted)\n",
    )
    _fake_proc(tmp_path, 20, comm="python3", exe="/usr/bin/python3", maps="")
    _fake_proc(
        tmp_path, 13, comm="victim", exe="/usr/bin/victim", maps="", tracer=20
    )  # tracé par python3
    _fake_proc(tmp_path, 21, comm="gdb", exe="/usr/bin/gdb", maps="")
    _fake_proc(tmp_path, 14, comm="dev", exe="/usr/bin/dev", maps="", tracer=21)
    _fake_proc(
        tmp_path,
        15,
        comm="bash",
        exe="/bin/bash",
        maps="",
        environ=b"HOME=/root\0LD_PRELOAD=/dev/shm/libhook.so\0",
    )
    _fake_proc(
        tmp_path,
        16,
        comm="app",
        exe="/usr/bin/app",
        maps="",
        environ=b"LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2\0",
    )

    scanner = InjectionScanner(proc_root=tmp_path)
    found = {(f.pid, f.kind): f for f in scanner.scan_all()}
    assert set(found) == {
        (10, "wx_anon"),
        (13, "ptrace_attached"),
        (14, "ptrace_attached"),
        (15, "ld_preload_writable"),
    }
    assert found[(13, "ptrace_attached")].weight == 60  # traceur non-débogueur
    assert found[(14, "ptrace_attached")].weight == 20  # gdb : signal faible
    assert "T1574.006" in found[(15, "ld_preload_writable")].mitre
    assert scanner.stats["jit_skipped"] == 1 and scanner.stats["memfd_allowlisted"] == 1


@pytest.mark.skipif(not LINUX, reason="symlinks /proc Linux")
def test_monitor_reports_each_anomaly_once(tmp_path):
    _fake_proc(tmp_path, 30, comm="x", exe="/usr/bin/x", maps="7f00-7f21 rwxp 0 00:00 0\n")
    got = []
    mon = InjectionMonitor(InjectionScanner(proc_root=tmp_path), on_finding=got.append)
    mon.poll()
    mon.poll()
    assert [f.kind for f in got] == ["wx_anon"]


# --------------------------------------------------------------------------- #
# Vrais processus (Linux) : enfants inoffensifs créés par le test
# --------------------------------------------------------------------------- #


def _spawn(code: str, **kw) -> subprocess.Popen:
    p = subprocess.Popen(
        [sys.executable, "-c", code + "\nprint('ready', flush=True)\nimport time; time.sleep(20)"],
        stdout=subprocess.PIPE,
        **kw,
    )
    assert p.stdout.readline().strip() == b"ready"
    return p


@pytest.mark.skipif(not LINUX, reason="/proc réel Linux")
@pytest.mark.parametrize(
    ("code", "kind"),
    [
        (  # page RWX anonyme privée (shellcode typique)
            "import mmap; m = mmap.mmap(-1, 4096, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,"
            " prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)",
            "wx_anon",
        ),
        (  # page RWX anonyme PARTAGÉE : le noyau l'affiche '/dev/zero (deleted)'
            "import mmap; m = mmap.mmap(-1, 4096,"
            " prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)",
            "wx_anon",
        ),
        (  # code mappé exécutable depuis un memfd (fileless)
            "import mmap, os; fd = os.memfd_create('stage2'); os.ftruncate(fd, 4096);"
            " m = mmap.mmap(fd, 4096, prot=mmap.PROT_READ | mmap.PROT_EXEC)",
            "memfd_exec",
        ),
    ],
)
def test_real_process_memory_anomalies(code, kind):
    child = _spawn(code)
    try:
        kinds = {f.kind for f in InjectionScanner().scan_pid(child.pid)}
    finally:
        child.kill()
        child.wait()
    assert kind in kinds


@pytest.mark.skipif(not LINUX, reason="/proc réel Linux")
def test_real_benign_process_is_clean():
    child = _spawn("x = 1")
    try:
        assert InjectionScanner().scan_pid(child.pid) == []
    finally:
        child.kill()
        child.wait()


@pytest.mark.skipif(not LINUX, reason="/proc réel Linux")
def test_real_ld_preload_from_tmp(tmp_path):
    env = dict(os.environ, LD_PRELOAD=str(tmp_path / "absent.so"))
    child = _spawn("x = 1", env=env, stderr=subprocess.DEVNULL)
    try:
        kinds = {f.kind for f in InjectionScanner().scan_pid(child.pid)}
    finally:
        child.kill()
        child.wait()
    if not str(tmp_path).startswith(("/tmp/", "/var/tmp/")):
        pytest.skip("tmp_path hors dossier modifiable surveillé")
    assert "ld_preload_writable" in kinds


@pytest.mark.skipif(
    not (LINUX and os.geteuid() == 0), reason="ptrace réel : Linux + droits suffisants"
)
def test_real_ptrace_attach_detected():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    PTRACE_SEIZE, PTRACE_DETACH = 0x4206, 17
    child = _spawn("x = 1")
    try:
        if libc.ptrace(PTRACE_SEIZE, child.pid, None, None) != 0:
            pytest.skip(f"ptrace refusé ici (errno {ctypes.get_errno()})")
        try:
            found = [
                f for f in InjectionScanner().scan_pid(child.pid) if f.kind == "ptrace_attached"
            ]
            assert found and found[0].details["tracer_pid"] == os.getpid()
        finally:
            libc.ptrace(PTRACE_DETACH, child.pid, None, None)
    finally:
        child.kill()
        child.wait()


# --------------------------------------------------------------------------- #
# Windows : Sysmon EID 8 / 10 (parsing)
# --------------------------------------------------------------------------- #

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _ev(rid, eid, **data):
    fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (
        f"<Event xmlns='{_NS}'><System><EventID>{eid}</EventID><EventRecordID>{rid}"
        f"</EventRecordID></System><EventData>{fields}</EventData></Event>"
    )


def test_parse_sysmon_injection_events():
    xml = (
        _ev(
            1,
            8,
            SourceImage=r"C:\Users\u\AppData\Local\Temp\l.exe",
            SourceProcessId="400",
            TargetImage=r"C:\Windows\explorer.exe",
            TargetProcessId="500",
            StartFunction="",
        )
        + _ev(
            2,
            8,
            SourceImage=r"C:\Windows\System32\csrss.exe",
            SourceProcessId="4",
            TargetImage=r"C:\x.exe",
        )  # bruit système filtré
        + _ev(
            3,
            10,
            SourceImage=r"C:\t\d.exe",
            SourceProcessId="600",
            TargetImage=r"C:\Windows\System32\lsass.exe",
            GrantedAccess="0x1010",
        )
        + _ev(
            4,
            10,
            SourceImage=r"C:\t\q.exe",
            SourceProcessId="601",
            TargetImage=r"C:\Windows\System32\lsass.exe",
            GrantedAccess="0x1000",
        )  # sans lecture
    )
    got = {(rid, f.kind, f.pid) for rid, f in parse_sysmon_injection_events(xml)}
    assert got == {(1, "remote_thread", 400), (3, "lsass_access", 600)}
    assert parse_sysmon_injection_events("<x") == []


def test_sysmon_monitor_with_fake_wevtutil():
    log = [(1, _ev(1, 8, SourceImage="C:/old.exe", SourceProcessId="1", TargetImage="C:/a.exe"))]

    def runner(cmd):
        q = next(a for a in cmd if a.startswith("/q:"))
        floor = int(q.split("EventRecordID>")[1].split("]")[0]) if "EventRecordID>" in q else -1
        items = [x for r, x in log if r > floor]
        return "".join(reversed(items) if "/rd:true" in cmd else items)

    got = []
    mon = InjectionMonitor(on_finding=got.append, sysmon_runner=runner, interval=3600)
    assert mon.start() and mon.active_source == "sysmon"
    try:
        log.append(
            (2, _ev(2, 8, SourceImage="C:/new.exe", SourceProcessId="9", TargetImage="C:/b"))
        )
        mon.poll()
    finally:
        mon.stop()
    assert [f.process_name for f in got] == ["new.exe"]  # l'historique n'est pas rejoué


# --------------------------------------------------------------------------- #
# Intégration
# --------------------------------------------------------------------------- #


def test_injection_joins_process_incident():
    """Un binaire lancé depuis /tmp (procmon) qui porte une région RWX : un
    seul incident ; la chronologie montre les deux capteurs."""
    from biocybe.inflammation import (
        DangerSignal,
        InflammationEngine,
        file_entity,
        from_injection_finding,
    )

    eng = InflammationEngine(host="h")
    eng.ingest(
        DangerSignal(
            "process:exec_from_temp", "procmon", 25, entities=(file_entity("/tmp/a"), "pid:5")
        )
    )
    f = InjectionScanner().analyze_maps(5, "a", "/tmp/a", "7f00-7f21 rwxp 0 00:00 0\n")[0]
    inc = eng.ingest(from_injection_finding(f))
    assert inc is not None and inc.severity == "systemic"  # 25 + 70x1.5 > 120
    assert {"process:exec_from_temp", "memory:wx_anon"} <= set(inc.kinds)


def test_daemon_builder_and_cli(monkeypatch, capsys):
    from biocybe import cli

    assert cli._build_injection_monitor_from_config({}, None) is None
    audited, notified = [], []
    monkeypatch.setattr("biocybe.audit.audit", lambda a, **kw: audited.append(a))
    mon = cli._build_injection_monitor_from_config(
        {"injmon": {"enabled": True, "memfd_allowlist": ["agent-x"]}},
        SimpleNamespace(notify=notified.append),
    )
    assert "agent-x" in mon.scanner.memfd_allowlist
    f = mon.scanner.analyze_maps(5, "a", "/tmp/a", "7f00-7f21 rwxp 0 00:00 0\n")
    mon.handle(f)
    assert audited == ["memory_finding"] and len(notified) == 1

    if LINUX:
        rc = cli.main(["injmon", "scan", "--pid", str(os.getpid()), "--json"])
        assert rc in (0, 1)  # le process pytest peut porter des régions JIT/ctypes
        assert isinstance(json.loads(capsys.readouterr().out), list)
