"""Tests cellule NK — réponse active sur processus malveillants.

Sécurité d'abord : on teste surtout les GARDE-FOUS (refus quand
désactivée, dry-run, process protégés, seuil de confiance, downgrade
kill, rate-limit, PID recyclé). Les actions réelles psutil sont mockées
— on ne tue évidemment pas de vrais process en test.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# ----------------------------------------------------------------------
# Décision : garde-fous
# ----------------------------------------------------------------------


def test_disabled_by_default_refuses():
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig())  # enabled=False par défaut
    d = nk.evaluate(pid=1234, process_name="evil.exe", confidence=100, reason="x")
    assert d.action.value == "none"
    assert "désactivée" in d.refused_reason


def test_confidence_threshold():
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, min_confidence=90))
    d = nk.evaluate(pid=1234, process_name="evil.exe", confidence=70, reason="x")
    assert d.action.value == "none"
    assert "confidence" in d.refused_reason


def test_protected_pid_refused():
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True))
    for pid in (0, 1, 4):
        d = nk.evaluate(pid=pid, process_name="whatever", confidence=100, reason="x")
        assert d.action.value == "none"
        assert "protégé" in d.refused_reason


def test_protected_name_refused():
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True))
    for name in ("lsass.exe", "systemd", "svchost.exe", "init", "explorer.exe"):
        d = nk.evaluate(pid=5000, process_name=name, confidence=100, reason="x")
        assert d.action.value == "none", f"{name} aurait dû être protégé"
        assert "protégé" in d.refused_reason


def test_own_process_protected():
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True))
    d = nk.evaluate(pid=os.getpid(), process_name="x", confidence=100, reason="x")
    assert d.action.value == "none"
    assert "BioCybe lui-même" in d.refused_reason


def test_extra_protected_names():
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, extra_protected_names=frozenset({"nginx"})))
    d = nk.evaluate(pid=6000, process_name="nginx", confidence=100, reason="x")
    assert d.action.value == "none"


def test_kill_downgraded_without_allow_kill():
    from biocybe.nk_cells import NKAction, NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, allow_kill=False, default_action=NKAction.SUSPEND))
    d = nk.evaluate(
        pid=7000,
        process_name="malware.exe",
        confidence=100,
        reason="x",
        requested_action=NKAction.KILL,
    )
    # kill refusé → downgrade en suspend
    assert d.action == NKAction.SUSPEND
    assert "downgrade" in d.reason


def test_kill_allowed_with_opt_in():
    from biocybe.nk_cells import NKAction, NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, allow_kill=True))
    d = nk.evaluate(
        pid=7001,
        process_name="malware.exe",
        confidence=100,
        reason="x",
        requested_action=NKAction.KILL,
    )
    assert d.action == NKAction.KILL


def test_valid_decision_suspend():
    from biocybe.nk_cells import NKAction, NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True))
    d = nk.evaluate(pid=8000, process_name="malware.exe", confidence=95, reason="C2")
    assert d.action == NKAction.SUSPEND
    assert d.refused_reason is None


# ----------------------------------------------------------------------
# Exécution
# ----------------------------------------------------------------------


def test_dry_run_does_not_execute():
    from biocybe.nk_cells import NKCell, NKConfig

    audit_calls = []
    nk = NKCell(
        NKConfig(enabled=True, dry_run=True),
        audit_fn=lambda *a, **k: audit_calls.append((a, k)),
    )
    d = nk.evaluate(pid=8001, process_name="malware.exe", confidence=100, reason="x")

    with patch("psutil.Process") as mock_proc:
        d = nk.respond(d)
        # En dry-run, psutil.Process ne doit JAMAIS être appelé
        mock_proc.assert_not_called()
    assert d.executed is False
    assert d.dry_run is True
    # Audit "dry_run" enregistré
    assert any(k.get("outcome") == "dry_run" for _, k in audit_calls)


def test_real_suspend_calls_psutil():
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, dry_run=False))
    d = nk.evaluate(pid=8002, process_name="malware.exe", confidence=100, reason="x")

    fake_proc = MagicMock()
    fake_proc.name.return_value = "malware.exe"
    with patch("psutil.Process", return_value=fake_proc):
        d = nk.respond(d)
    fake_proc.suspend.assert_called_once()
    assert d.executed is True


def test_real_kill_calls_psutil_kill():
    from biocybe.nk_cells import NKAction, NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, dry_run=False, allow_kill=True))
    d = nk.evaluate(
        pid=8003,
        process_name="malware.exe",
        confidence=100,
        reason="x",
        requested_action=NKAction.KILL,
    )
    fake_proc = MagicMock()
    fake_proc.name.return_value = "malware.exe"
    with patch("psutil.Process", return_value=fake_proc):
        d = nk.respond(d)
    fake_proc.kill.assert_called_once()
    assert d.executed is True


def test_pid_recycling_refused():
    """Si le nom du process a changé entre evaluate et respond → refus."""
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, dry_run=False))
    d = nk.evaluate(pid=8004, process_name="malware.exe", confidence=100, reason="x")

    fake_proc = MagicMock()
    fake_proc.name.return_value = "innocent.exe"  # PID recyclé !
    with patch("psutil.Process", return_value=fake_proc):
        d = nk.respond(d)
    fake_proc.suspend.assert_not_called()
    assert d.executed is False
    assert "recyclé" in (d.error or "") or "recyclé" in (d.refused_reason or "")


def test_no_such_process_handled():
    import psutil

    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, dry_run=False))
    d = nk.evaluate(pid=8005, process_name="malware.exe", confidence=100, reason="x")
    with patch("psutil.Process", side_effect=psutil.NoSuchProcess(8005)):
        d = nk.respond(d)
    assert d.executed is False
    assert "déjà terminé" in d.error


def test_access_denied_handled():
    import psutil

    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, dry_run=False))
    d = nk.evaluate(pid=8006, process_name="malware.exe", confidence=100, reason="x")
    with patch("psutil.Process", side_effect=psutil.AccessDenied(8006)):
        d = nk.respond(d)
    assert d.executed is False
    assert "access denied" in d.error


def test_rate_limit():
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, dry_run=False, max_actions_per_minute=2))
    fake_proc = MagicMock()
    fake_proc.name.return_value = "malware.exe"

    executed = 0
    rate_limited = 0
    with patch("psutil.Process", return_value=fake_proc):
        for i in range(5):
            d = nk.evaluate(pid=9000 + i, process_name="malware.exe", confidence=100, reason="x")
            d = nk.respond(d)
            if d.executed:
                executed += 1
            elif d.refused_reason and "rate-limit" in d.refused_reason:
                rate_limited += 1
    assert executed == 2
    assert rate_limited == 3


def test_resume_process():
    from biocybe.nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, dry_run=False))
    fake_proc = MagicMock()
    with patch("psutil.Process", return_value=fake_proc):
        assert nk.resume_process(8007) is True
    fake_proc.resume.assert_called_once()


def test_isolate_host_uses_blocker():
    from biocybe.nk_cells import NKCell, NKConfig

    blocker = MagicMock()
    blocker.list_blocked.return_value = ["old.test"]
    nk = NKCell(NKConfig(enabled=True, dry_run=False), hosts_blocker=blocker)
    ok = nk.isolate_host("evil-c2.test")
    assert ok is True
    blocker.apply.assert_called_once()
    args = blocker.apply.call_args[0][0]
    assert "evil-c2.test" in args
    assert "old.test" in args  # préserve l'existant


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def test_cli_nk_respond_dry_run_default(monkeypatch, capsys):
    from biocybe.cli import main

    fake_proc = MagicMock()
    fake_proc.name.return_value = "evil.exe"
    with patch("psutil.Process", return_value=fake_proc):
        exit_code = main(["nk", "respond", "--pid", "12345", "--confidence", "100"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "DRY-RUN" in out
    # En dry-run, suspend ne doit pas être appelé
    fake_proc.suspend.assert_not_called()


def test_cli_nk_respond_protected_returns_1(monkeypatch, capsys):
    from biocybe.cli import main

    fake_proc = MagicMock()
    fake_proc.name.return_value = "lsass.exe"
    with patch("psutil.Process", return_value=fake_proc):
        exit_code = main(["nk", "respond", "--pid", "999", "--execute", "--confidence", "100"])
    assert exit_code == 1
    out = capsys.readouterr().out.lower()
    # "Refusee" + "lsass.exe" : le process protégé n'a pas été touché
    assert "refusee" in out and "lsass.exe" in out


def test_cli_nk_status(monkeypatch, capsys, tmp_path):
    from biocybe.cli import main

    monkeypatch.chdir(tmp_path)
    exit_code = main(["nk", "status"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "enabled" in out
    assert "dry_run" in out


def test_cli_nk_status_pid_protection(monkeypatch, capsys, tmp_path):
    from biocybe.cli import main

    monkeypatch.chdir(tmp_path)
    fake_proc = MagicMock()
    fake_proc.name.return_value = "systemd"
    with patch("psutil.Process", return_value=fake_proc):
        exit_code = main(["nk", "status", "--pid", "1", "--json"])
    assert exit_code == 0
    import json

    info = json.loads(capsys.readouterr().out)
    assert info["pid_test"]["protected"] is True
