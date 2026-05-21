"""Tests Phase 2.3.c : dashboard SOC.

La couche données (`DashboardData`) est testée à fond sans navigateur.
La construction de l'app Dash est testée si l'extra [web] est présent
(sinon skip propre).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# ----------------------------------------------------------------------
# Fixtures : crée des artefacts réalistes (quarantine, audit, feeds)
# ----------------------------------------------------------------------


def _seed_quarantine(qdir: Path):
    qdir.mkdir(parents=True, exist_ok=True)
    manifest = [
        {
            "quarantine_id": "q1",
            "original_path": "/tmp/evil.exe",
            "stored_filename": "q1.bin",
            "sha256": "a" * 64,
            "size_bytes": 1000,
            "quarantined_at": "2026-05-20T10:00:00",
            "reason": "yara:ransomware",
            "detected_by": "b_cell",
            "extra": {"family": "LockBit", "severity": "critical"},
            "encrypted": True,
        },
        {
            "quarantine_id": "q2",
            "original_path": "/tmp/adware.dll",
            "stored_filename": "q2.bin",
            "sha256": "b" * 64,
            "size_bytes": 2000,
            "quarantined_at": "2026-05-21T11:00:00",
            "reason": "hash:known",
            "detected_by": "b_cell",
            "extra": {"family": "Adware", "severity": "low"},
            "encrypted": False,
        },
    ]
    (qdir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _seed_audit(path: Path):
    from biocybe.audit import AuditLog

    path.parent.mkdir(parents=True, exist_ok=True)
    log = AuditLog(path)
    log.append(actor="cli", action="quarantine_created", outcome="success", details={"id": "q1"})
    log.append(actor="cli", action="quarantine_created", outcome="success", details={"id": "q2"})
    log.append(actor="api", action="restore_file", outcome="success", details={"id": "q1"})
    return log


def _seed_feeds(db: Path):
    from datetime import datetime

    now = datetime.now().isoformat()
    (db / "hashes").mkdir(parents=True, exist_ok=True)
    (db / "hashes" / "last_update.txt").write_text(now, encoding="utf-8")
    (db / "hashes" / "signatures.json").write_text(
        json.dumps({"a" * 64: {"family": "X"}, "b" * 64: {"family": "Y"}}), encoding="utf-8"
    )
    (db / "urlhaus").mkdir(parents=True, exist_ok=True)
    (db / "urlhaus" / "last_update.txt").write_text(now, encoding="utf-8")
    (db / "urlhaus" / "urls.json").write_text(
        json.dumps([{"url": "http://evil.test/x", "hostname": "evil.test"}]), encoding="utf-8"
    )
    (db / "urlhaus" / "hostnames.json").write_text(
        json.dumps({"evil.test": ["http://evil.test/x"]}), encoding="utf-8"
    )
    (db / "threatfox" / "by_type").mkdir(parents=True, exist_ok=True)
    (db / "threatfox" / "last_update.txt").write_text(now, encoding="utf-8")
    (db / "threatfox" / "iocs.json").write_text(json.dumps([{"id": 1}]), encoding="utf-8")
    (db / "threatfox" / "by_type" / "ip.json").write_text(
        json.dumps({"1.2.3.4:80": {"malware": "z", "confidence": 90}}), encoding="utf-8"
    )


def _config(tmp_path):
    from biocybe.dashboard.data import DashboardConfig

    return DashboardConfig(
        quarantine_dir=str(tmp_path / "quarantine"),
        audit_path=str(tmp_path / "logs" / "audit.jsonl"),
        signatures_db_path=str(tmp_path / "db" / "signatures"),
    )


# ----------------------------------------------------------------------
# Couche données
# ----------------------------------------------------------------------


def test_quarantine_summary(tmp_path):
    from biocybe.dashboard.data import DashboardData

    _seed_quarantine(tmp_path / "quarantine")
    data = DashboardData(_config(tmp_path))
    q = data.quarantine_summary()

    assert q["total"] == 2
    assert q["total_size_bytes"] == 3000
    assert q["encrypted_count"] == 1
    assert q["by_severity"]["critical"] == 1
    assert q["by_family"]["LockBit"] == 1
    # Table triée par date desc → q2 (21 mai) avant q1 (20 mai)
    assert q["table"][0]["id"] == "q2"


def test_quarantine_summary_empty(tmp_path):
    from biocybe.dashboard.data import DashboardData

    data = DashboardData(_config(tmp_path))
    q = data.quarantine_summary()
    assert q["total"] == 0
    assert q["table"] == []


def test_audit_summary_chain_ok(tmp_path):
    from biocybe.dashboard.data import DashboardData

    _seed_audit(tmp_path / "logs" / "audit.jsonl")
    data = DashboardData(_config(tmp_path))
    a = data.audit_summary()

    assert a["exists"] is True
    assert a["total"] == 3
    assert a["chain_ok"] is True
    assert a["by_action"]["quarantine_created"] == 2
    assert a["by_outcome"]["success"] == 3
    # Table triée par seq desc
    assert a["table"][0]["seq"] == 3


def test_audit_summary_detects_tampering(tmp_path):
    from biocybe.dashboard.data import DashboardData

    audit_path = tmp_path / "logs" / "audit.jsonl"
    _seed_audit(audit_path)

    # Altère une ligne du milieu → la chaîne SHA-256 doit casser
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["outcome"] = "TAMPERED"
    lines[1] = json.dumps(entry)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    data = DashboardData(_config(tmp_path))
    a = data.audit_summary()
    assert a["chain_ok"] is False
    assert a["chain_errors"]


def test_audit_summary_missing(tmp_path):
    from biocybe.dashboard.data import DashboardData

    data = DashboardData(_config(tmp_path))
    a = data.audit_summary()
    assert a["exists"] is False
    assert a["chain_ok"] is None


def test_intel_summary(tmp_path):
    from biocybe.dashboard.data import DashboardData

    _seed_feeds(tmp_path / "db" / "signatures")
    data = DashboardData(_config(tmp_path))
    i = data.intel_summary()

    assert i["all_missing"] is False
    assert i["any_stale"] is False  # feeds frais (now)
    assert i["lookup_total"] >= 2
    sources = {f["source"] for f in i["feeds"]}
    assert {"malwarebazaar", "urlhaus", "threatfox"} == sources


def test_overview_kpis(tmp_path):
    from biocybe.dashboard.data import DashboardData

    _seed_quarantine(tmp_path / "quarantine")
    _seed_audit(tmp_path / "logs" / "audit.jsonl")
    _seed_feeds(tmp_path / "db" / "signatures")
    data = DashboardData(_config(tmp_path))
    o = data.overview()

    assert o["quarantine_total"] == 2
    assert o["quarantine_worst_severity"] == "critical"
    assert o["audit_total"] == 3
    assert o["audit_chain_ok"] is True
    assert o["intel_total_iocs"] >= 2


def test_snapshot_full(tmp_path):
    from biocybe.dashboard.data import DashboardData

    _seed_quarantine(tmp_path / "quarantine")
    _seed_audit(tmp_path / "logs" / "audit.jsonl")
    _seed_feeds(tmp_path / "db" / "signatures")
    data = DashboardData(_config(tmp_path))
    snap = data.snapshot()

    assert set(snap.keys()) == {"overview", "quarantine", "audit", "intel", "memory"}
    # Sérialisable JSON (important pour export/SIEM)
    json.dumps(snap)


def test_import_dashboard_without_dash_does_not_crash():
    """`import biocybe.dashboard` doit marcher même sans l'extra [web]."""
    import biocybe.dashboard  # noqa: F401
    from biocybe.dashboard import DashboardConfig, DashboardData  # noqa: F401


# ----------------------------------------------------------------------
# Construction Dash (skip si extra [web] absent)
# ----------------------------------------------------------------------

_HAS_DASH = all(
    importlib.util.find_spec(m) is not None for m in ("dash", "plotly", "dash_bootstrap_components")
)


@pytest.mark.skipif(not _HAS_DASH, reason="extra [web] non installé")
def test_create_dashboard_builds(tmp_path):
    from biocybe.dashboard.app import create_dashboard

    _seed_quarantine(tmp_path / "quarantine")
    _seed_audit(tmp_path / "logs" / "audit.jsonl")
    _seed_feeds(tmp_path / "db" / "signatures")

    app = create_dashboard(_config(tmp_path), refresh_seconds=30)
    assert app is not None
    assert app.layout is not None
    # Le serveur Flask sous-jacent existe (déploiement WSGI)
    assert app.server is not None


@pytest.mark.skipif(not _HAS_DASH, reason="extra [web] non installé")
def test_dashboard_callbacks_registered(tmp_path):
    from biocybe.dashboard.app import create_dashboard

    app = create_dashboard(_config(tmp_path))
    # 2 callbacks : kpi-row et tab-content
    assert len(app.callback_map) >= 2


def test_cli_dashboard_serve_missing_deps_exit_2(tmp_path, monkeypatch, capsys):
    """Si serve_dashboard lève DashboardUnavailable, exit code propre."""
    if _HAS_DASH:
        pytest.skip("dash installé — ce test cible le cas deps absentes")
    from biocybe.cli import main

    monkeypatch.chdir(tmp_path)
    exit_code = main(["dashboard", "serve"])
    assert exit_code == 2
    assert "biocybe[web]" in capsys.readouterr().err
