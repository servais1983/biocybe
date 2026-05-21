"""Tests intégration watcher ↔ auto-régénération (détection rafale ransomware)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _healer(tmp_path, files):
    from biocybe.regeneration import SelfHealer

    h = SelfHealer(vault_dir=tmp_path / "vault", manifest_path=tmp_path / "baseline.json")
    h.baseline(files)
    return h


def _watcher(tmp_path, healer, **kw):
    from biocybe.watcher import FileSystemWatcher

    return FileSystemWatcher([tmp_path], regen_healer=healer, **kw)


def test_drift_on_baselined_file_counted(tmp_path):
    f = tmp_path / "x.conf"
    f.write_text("sain", encoding="utf-8")
    h = _healer(tmp_path, [f])
    w = _watcher(tmp_path, h, regen_burst_threshold=5)

    f.write_text("altere", encoding="utf-8")
    w._check_regeneration(str(f))
    assert w.stats.regen_drift_detected == 1
    # Sous le seuil → pas de heal
    assert w.stats.regen_healed == 0


def test_intact_baselined_file_no_drift(tmp_path):
    f = tmp_path / "x.conf"
    f.write_text("inchangé", encoding="utf-8")
    h = _healer(tmp_path, [f])
    w = _watcher(tmp_path, h)
    w._check_regeneration(str(f))
    assert w.stats.regen_drift_detected == 0


def test_non_baselined_file_ignored(tmp_path):
    f = tmp_path / "x.conf"
    f.write_text("sain", encoding="utf-8")
    h = _healer(tmp_path, [f])
    w = _watcher(tmp_path, h)

    other = tmp_path / "autre.txt"
    other.write_text("pas dans la baseline", encoding="utf-8")
    w._check_regeneration(str(other))
    assert w.stats.regen_drift_detected == 0


def test_burst_triggers_auto_heal(tmp_path):
    """Rafale ransomware → restauration automatique de TOUS les fichiers."""
    files = []
    for i in range(6):
        f = tmp_path / f"doc{i}.txt"
        f.write_text(f"contenu sain {i}", encoding="utf-8")
        files.append(f)
    h = _healer(tmp_path, files)
    w = _watcher(tmp_path, h, regen_auto_heal=True, regen_burst_threshold=5, regen_burst_window=60)

    # "Ransomware" chiffre tout, le watcher voit les events un par un
    for f in files:
        f.write_text("CHIFFRE", encoding="utf-8")
    for f in files:
        w._check_regeneration(str(f))

    # Au 5e fichier, la rafale déclenche heal qui restaure TOUT
    assert w.stats.regen_healed >= 5
    # Tous les fichiers sont restaurés
    for i, f in enumerate(files):
        assert f.read_text(encoding="utf-8") == f"contenu sain {i}"


def test_burst_alert_only_when_auto_heal_off(tmp_path):
    """auto_heal=False : on alerte (rafale) mais on NE restaure PAS."""
    files = []
    for i in range(6):
        f = tmp_path / f"doc{i}.txt"
        f.write_text(f"sain {i}", encoding="utf-8")
        files.append(f)
    h = _healer(tmp_path, files)
    w = _watcher(tmp_path, h, regen_auto_heal=False, regen_burst_threshold=5, regen_burst_window=60)

    for f in files:
        f.write_text("CHIFFRE", encoding="utf-8")
    for f in files:
        w._check_regeneration(str(f))

    # Drift détecté mais aucune restauration (mode alerte)
    assert w.stats.regen_drift_detected == 6
    assert w.stats.regen_healed == 0
    for f in files:
        assert f.read_text(encoding="utf-8") == "CHIFFRE"  # non restauré


def test_below_threshold_no_heal(tmp_path):
    """Modification isolée (sous le seuil) → pas de heal même si auto_heal."""
    files = []
    for i in range(5):
        f = tmp_path / f"doc{i}.txt"
        f.write_text(f"sain {i}", encoding="utf-8")
        files.append(f)
    h = _healer(tmp_path, files)
    w = _watcher(tmp_path, h, regen_auto_heal=True, regen_burst_threshold=5, regen_burst_window=60)

    # Une seule modification (edit légitime) → sous le seuil de 5
    files[0].write_text("edit legitime", encoding="utf-8")
    w._check_regeneration(str(files[0]))
    assert w.stats.regen_healed == 0
    assert files[0].read_text(encoding="utf-8") == "edit legitime"  # respecté


def test_no_healer_no_effect(tmp_path, monkeypatch):
    """Sans healer, le watcher ignore la régénération."""
    from biocybe.watcher import FileSystemWatcher

    w = FileSystemWatcher([tmp_path])  # pas de regen_healer
    assert w.regen_healer is None
    # _process ne doit pas crasher sans healer
    f = tmp_path / "x.txt"
    f.write_text("data", encoding="utf-8")

    from biocybe.lymphocytes_b import ScanResult

    monkeypatch.setattr(w.cell, "scan_file_sync", lambda p: ScanResult())
    w._process(str(f), "modified", 0.0)
    assert w.stats.regen_drift_detected == 0


# ----------------------------------------------------------------------
# Wiring daemon
# ----------------------------------------------------------------------


def test_build_self_healer_disabled():
    from biocybe.cli import _build_self_healer_from_config

    assert _build_self_healer_from_config({}) is None
    assert _build_self_healer_from_config({"regeneration": {"enabled": False}}) is None


def test_build_self_healer_enabled(tmp_path):
    from biocybe.cli import _build_self_healer_from_config

    cfg = {
        "regeneration": {
            "enabled": True,
            "auto_heal": True,
            "vault": str(tmp_path / "v"),
            "manifest": str(tmp_path / "b.json"),
            "burst_threshold": 7,
            "burst_window": 15,
        }
    }
    built = _build_self_healer_from_config(cfg)
    assert built is not None
    assert built["auto_heal"] is True
    assert built["burst_threshold"] == 7
    assert built["burst_window"] == 15.0
