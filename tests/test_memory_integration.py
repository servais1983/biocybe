"""Tests d'intégration mémoire immunitaire : watcher + dashboard + daemon wiring."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# ----------------------------------------------------------------------
# Watcher : suppression FP + apprentissage
# ----------------------------------------------------------------------


def _make_event(path: Path, *, malicious: bool, family="TestFam", conf=0.9):
    from biocybe.lymphocytes_b import ScanResult
    from biocybe.watcher import WatchEvent

    res = ScanResult()
    res.is_malicious = malicious
    res.confidence = conf
    res.malware_family = family
    res.severity = "high"
    ev = WatchEvent(timestamp=0.0, path=path, event_type="created")
    ev.result = res
    return ev


def test_watcher_apply_memory_suppresses_fp(tmp_path):
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory
    from biocybe.watcher import FileSystemWatcher

    f = tmp_path / "legit.exe"
    f.write_bytes(b"a legit binary wrongly flagged")
    sha = hashlib.sha256(f.read_bytes()).hexdigest()

    mem = ImmuneMemory(tmp_path / "m.db")
    mem.remember(sha, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=80)
    mem.set_disposition(sha, "sha256", "confirmed_benign")

    w = FileSystemWatcher([tmp_path], memory=mem)
    ev = _make_event(f, malicious=True)
    suppressed = w._apply_memory(str(f), ev)
    assert suppressed is True
    mem.close()


def test_watcher_apply_memory_learns(tmp_path):
    from biocybe.memory import ImmuneMemory
    from biocybe.watcher import FileSystemWatcher

    f = tmp_path / "malware.bin"
    f.write_bytes(b"evil payload")
    sha = hashlib.sha256(f.read_bytes()).hexdigest()

    mem = ImmuneMemory(tmp_path / "m.db")
    w = FileSystemWatcher([tmp_path], memory=mem)
    ev = _make_event(f, malicious=True, family="Emotet")
    suppressed = w._apply_memory(str(f), ev)
    assert suppressed is False
    rec = mem.recall(sha, "sha256")
    assert rec is not None and rec.family == "Emotet"
    mem.close()


def test_watcher_process_suppresses_fp_end_to_end(tmp_path, monkeypatch):
    """_process complet : un FP confirmé ne compte pas comme détection."""
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory
    from biocybe.watcher import FileSystemWatcher

    f = tmp_path / "tool.exe"
    f.write_bytes(b"legit admin tool")
    sha = hashlib.sha256(f.read_bytes()).hexdigest()

    mem = ImmuneMemory(tmp_path / "m.db")
    mem.remember(sha, indicator_type="sha256", verdict=VERDICT_MALICIOUS, confidence=90)
    mem.set_disposition(sha, "sha256", "confirmed_benign")

    w = FileSystemWatcher([tmp_path], memory=mem)

    # Mock la BCell pour qu'elle "détecte" le fichier
    from biocybe.lymphocytes_b import ScanResult

    def fake_scan(path):
        r = ScanResult()
        r.is_malicious = True
        r.confidence = 0.9
        r.malware_family = "FalsePositive"
        r.severity = "high"
        return r

    monkeypatch.setattr(w.cell, "scan_file_sync", fake_scan)

    w._process(str(f), "created", 0.0)
    # Détection étouffée : suppressed compté, pas detections
    assert w.stats.memory_suppressed == 1
    assert w.stats.detections == 0
    mem.close()


def test_watcher_without_memory_unaffected(tmp_path, monkeypatch):
    from biocybe.lymphocytes_b import ScanResult
    from biocybe.watcher import FileSystemWatcher

    f = tmp_path / "x.bin"
    f.write_bytes(b"payload")
    w = FileSystemWatcher([tmp_path])  # pas de mémoire

    def fake_scan(path):
        r = ScanResult()
        r.is_malicious = True
        r.confidence = 0.9
        r.severity = "high"
        return r

    monkeypatch.setattr(w.cell, "scan_file_sync", fake_scan)
    w._process(str(f), "created", 0.0)
    assert w.stats.detections == 1
    assert w.stats.memory_suppressed == 0


# ----------------------------------------------------------------------
# Dashboard : memory_summary
# ----------------------------------------------------------------------


def test_dashboard_memory_summary(tmp_path):
    from biocybe.dashboard.data import DashboardConfig, DashboardData
    from biocybe.memory import VERDICT_MALICIOUS, ImmuneMemory

    db = tmp_path / "mem.db"
    mem = ImmuneMemory(db)
    mem.remember("a" * 64, indicator_type="sha256", verdict=VERDICT_MALICIOUS, family="Emotet")
    mem.remember("b" * 64, indicator_type="sha256", verdict=VERDICT_MALICIOUS, family="Emotet")
    mem.set_disposition("b" * 64, "sha256", "confirmed_benign")
    mem.close()

    data = DashboardData(DashboardConfig(memory_db_path=str(db)))
    m = data.memory_summary()
    assert m["exists"] is True
    assert m["total"] == 2
    assert m["by_disposition"].get("confirmed_benign") == 1
    assert ("Emotet", 2) in m["top_families"]
    assert len(m["table"]) == 2


def test_dashboard_memory_summary_missing(tmp_path):
    from biocybe.dashboard.data import DashboardConfig, DashboardData

    data = DashboardData(DashboardConfig(memory_db_path=str(tmp_path / "nope.db")))
    m = data.memory_summary()
    assert m["exists"] is False
    assert m["total"] == 0


def test_dashboard_snapshot_includes_memory(tmp_path):
    from biocybe.dashboard.data import DashboardConfig, DashboardData

    data = DashboardData(DashboardConfig(memory_db_path=str(tmp_path / "nope.db")))
    snap = data.snapshot()
    assert "memory" in snap


# ----------------------------------------------------------------------
# Daemon wiring
# ----------------------------------------------------------------------


def test_build_immune_memory_disabled():
    from biocybe.cli import _build_immune_memory_from_config

    assert _build_immune_memory_from_config({}) is None
    assert _build_immune_memory_from_config({"memory": {"enabled": False}}) is None


def test_build_immune_memory_enabled(tmp_path):
    from biocybe.cli import _build_immune_memory_from_config

    db = tmp_path / "m.db"
    mem = _build_immune_memory_from_config({"memory": {"enabled": True, "db_path": str(db)}})
    assert mem is not None
    assert mem.stats()["total"] == 0
    mem.close()
