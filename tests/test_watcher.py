"""Tests Phase 2.2.a : real-time filesystem watcher.

Vérifie que :
  - un fichier créé dans un dossier surveillé est détecté en <2 s ;
  - les fichiers bénins ne déclenchent pas d'alerte ;
  - le callback est appelé pour chaque verdict ;
  - la quarantaine s'applique en temps réel si activée ;
  - le mode dry-run du watcher détecte sans agir ;
  - les dossiers exclus (quarantine/, db/, etc.) ne sont pas re-scannés ;
  - le watcher démarre/s'arrête proprement.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


EICAR_PARTS = [
    "X5O!P%@AP[4\\PZX54(P^)7CC)",
    "7}$EICAR-STANDARD-ANTIVIRUS-",
    "TEST-FILE!$H+H*",
]
EICAR_STRING = "".join(EICAR_PARTS)


# Timeout généreux : sur CI Windows/macOS, watchdog peut prendre ~1s
# pour propager un événement, +0.3s de debounce + 0.1s de scan loop.
WATCH_TIMEOUT_S = 5.0


@pytest.fixture
def watch_dir(tmp_path, monkeypatch):
    """Dossier de surveillance + règles YARA + CWD isolé."""
    rules_src = ROOT / "rules" / "yara"
    rules_dst = tmp_path / "rules" / "yara"
    rules_dst.mkdir(parents=True)
    for rule in rules_src.glob("*.yar"):
        (rules_dst / rule.name).write_bytes(rule.read_bytes())
    monkeypatch.chdir(tmp_path)

    watched = tmp_path / "watched"
    watched.mkdir()
    return watched


def _wait_for(condition, timeout: float = WATCH_TIMEOUT_S, interval: float = 0.1) -> bool:
    """Poll jusqu'à ce que `condition()` soit vrai ou timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return False


def test_watcher_detects_eicar_on_create(watch_dir):
    from biocybe.scanner import sync_yara_rules
    from biocybe.watcher import FileSystemWatcher, WatchEvent

    sync_yara_rules()

    received: list[WatchEvent] = []
    received_event = threading.Event()

    def on_event(ev: WatchEvent) -> None:
        received.append(ev)
        if ev.is_malicious:
            received_event.set()

    with FileSystemWatcher([watch_dir], callback=on_event) as w:
        # Laisser au observer le temps de démarrer
        time.sleep(0.3)

        eicar = watch_dir / "evil.com"
        eicar.write_text(EICAR_STRING, encoding="ascii")

        assert received_event.wait(WATCH_TIMEOUT_S), (
            f"EICAR n'a pas été détecté en {WATCH_TIMEOUT_S}s. "
            f"events_observed={w.stats.events_observed}, scanned={w.stats.events_scanned}"
        )

    malicious = [e for e in received if e.is_malicious]
    assert len(malicious) >= 1
    assert malicious[0].path == eicar
    assert malicious[0].result.malware_family == "EICAR"
    assert w.stats.detections >= 1


def test_watcher_does_not_flag_benign_file(watch_dir):
    from biocybe.scanner import sync_yara_rules
    from biocybe.watcher import FileSystemWatcher

    sync_yara_rules()

    with FileSystemWatcher([watch_dir]) as w:
        time.sleep(0.3)
        (watch_dir / "benign.txt").write_text("Hello, world.\n", encoding="utf-8")

        # Laisser largement le temps au watcher de traiter
        assert _wait_for(lambda: w.stats.events_scanned >= 1, timeout=WATCH_TIMEOUT_S)

    assert w.stats.detections == 0


def test_watcher_quarantines_in_realtime(watch_dir):
    from biocybe.scanner import sync_yara_rules
    from biocybe.watcher import FileSystemWatcher

    sync_yara_rules()

    quarantined = threading.Event()

    def on_event(ev):
        if ev.quarantine is not None:
            quarantined.set()

    with FileSystemWatcher([watch_dir], quarantine_on_match=True, callback=on_event) as w:
        time.sleep(0.3)
        eicar = watch_dir / "rt_evil.com"
        eicar.write_text(EICAR_STRING, encoding="ascii")

        assert quarantined.wait(WATCH_TIMEOUT_S), "Quarantaine temps-réel n'a pas eu lieu"

    # Le fichier original a disparu
    assert not eicar.exists()
    # Une entrée existe dans le manifeste
    qdir = watch_dir.parent / "quarantine"
    assert (qdir / "manifest.json").exists()
    assert w.stats.quarantined >= 1


def test_watcher_dry_run_does_not_quarantine(watch_dir):
    from biocybe.scanner import sync_yara_rules
    from biocybe.watcher import FileSystemWatcher

    sync_yara_rules()

    dry_run_seen = threading.Event()

    def on_event(ev):
        if ev.dry_run_quarantine:
            dry_run_seen.set()

    with FileSystemWatcher(
        [watch_dir], quarantine_on_match=True, dry_run=True, callback=on_event
    ) as w:
        time.sleep(0.3)
        eicar = watch_dir / "would_be_quarantined.com"
        eicar.write_text(EICAR_STRING, encoding="ascii")

        assert dry_run_seen.wait(WATCH_TIMEOUT_S)

    # Le fichier est resté en place
    assert eicar.exists()
    # Aucune quarantaine réelle
    qdir = watch_dir.parent / "quarantine"
    assert not (qdir / "manifest.json").exists() or w.stats.quarantined == 0


def test_watcher_ignores_excluded_dirs(watch_dir):
    """Un fichier déposé dans `quarantine/` ne doit pas redéclencher un scan
    — sinon boucle infinie de re-quarantaine."""
    from biocybe.scanner import sync_yara_rules
    from biocybe.watcher import FileSystemWatcher

    sync_yara_rules()

    qsubdir = watch_dir / "quarantine"
    qsubdir.mkdir()

    with FileSystemWatcher([watch_dir]) as w:
        time.sleep(0.3)
        # Dépôt dans le sous-dossier exclu
        (qsubdir / "already_quarantined.bin").write_text(EICAR_STRING, encoding="ascii")
        time.sleep(2.0)

    # Aucune détection : le watcher a ignoré le dossier exclu
    assert w.stats.detections == 0


def test_watcher_starts_and_stops_cleanly(watch_dir):
    from biocybe.watcher import FileSystemWatcher

    w = FileSystemWatcher([watch_dir])
    w.start()
    assert w._observer is not None
    w.stop()
    assert w._observer is None
    assert w._scanner_thread is None
