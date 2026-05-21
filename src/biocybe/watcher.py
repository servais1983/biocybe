"""Real-time filesystem watcher pour BioCybe.

Branche `watchdog` (cross-platform : inotify Linux, FSEvents macOS,
ReadDirectoryChangesW Windows) sur le pipeline de scan BioCybe.

Tout fichier créé ou modifié dans les dossiers surveillés est
analysé immédiatement par une `BCell`. C'est ce qui transforme
BioCybe d'un "AV à la demande" en un EDR temps-réel.

Utilisation programmatique :

    from biocybe.lymphocytes_b import BCell
    from biocybe.watcher import FileSystemWatcher

    bcell = BCell("rt_scanner")
    watcher = FileSystemWatcher(["/var/log", "/tmp"], cell=bcell)
    watcher.start()
    # ... le watcher tourne en arrière-plan, callbacks sur détection
    watcher.stop()

Utilisation via daemon :

    biocybe daemon --watch /var/log --watch /tmp [--quarantine]
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .isolation import QuarantineEntry, quarantine_file
from .lymphocytes_b import BCell, ScanResult

logger = logging.getLogger("biocybe.watcher")


@dataclass
class WatchEvent:
    """Un événement traité par le watcher."""

    timestamp: float
    path: Path
    event_type: str  # "created" | "modified"
    result: ScanResult | None = None
    quarantine: QuarantineEntry | None = None
    dry_run_quarantine: bool = False
    error: str | None = None

    @property
    def is_malicious(self) -> bool:
        return self.result is not None and self.result.is_malicious


# Callback : fonction appelée pour chaque verdict (malicieux ou non).
# Type alias pour faciliter l'usage côté caller.
WatchCallback = Callable[[WatchEvent], None]


class _ScanHandler(FileSystemEventHandler):
    """Handler watchdog qui empile les chemins à scanner.

    Le scan lui-même tourne dans un thread séparé pour ne pas bloquer
    le thread observer (qui doit rester réactif pour ne pas perdre
    d'événements à fort débit).
    """

    def __init__(
        self,
        queue: deque[tuple[float, str, str]],
        lock: threading.Lock,
        excluded_dirs: frozenset[str],
        excluded_suffixes: frozenset[str],
    ):
        super().__init__()
        self._queue = queue
        self._lock = lock
        self._excluded_dirs = excluded_dirs
        self._excluded_suffixes = excluded_suffixes

    def _should_skip(self, path: str) -> bool:
        p = Path(path)
        if any(part in self._excluded_dirs for part in p.parts):
            return True
        if p.suffix.lower() in self._excluded_suffixes:
            return True
        return False

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory or self._should_skip(event.src_path):
            return
        with self._lock:
            self._queue.append((time.time(), event.src_path, "created"))

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory or self._should_skip(event.src_path):
            return
        with self._lock:
            self._queue.append((time.time(), event.src_path, "modified"))


@dataclass
class WatcherStats:
    """Compteurs temps-réel exposables (Prometheus en Phase 2.3)."""

    events_observed: int = 0
    events_scanned: int = 0
    events_skipped: int = 0
    detections: int = 0
    quarantined: int = 0
    errors: int = 0
    # Détections étouffées car faux positif confirmé en mémoire immunitaire
    memory_suppressed: int = 0
    # Auto-régénération : fichiers baselinés détectés en drift / restaurés
    regen_drift_detected: int = 0
    regen_healed: int = 0
    started_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "events_observed": self.events_observed,
            "events_scanned": self.events_scanned,
            "events_skipped": self.events_skipped,
            "detections": self.detections,
            "quarantined": self.quarantined,
            "errors": self.errors,
            "memory_suppressed": self.memory_suppressed,
            "regen_drift_detected": self.regen_drift_detected,
            "regen_healed": self.regen_healed,
            "uptime_seconds": time.time() - self.started_at,
        }


# Dossiers à ne JAMAIS surveiller (sinon boucle infinie de quarantine,
# inflation de logs, écrasement de la file d'événements).
DEFAULT_WATCH_EXCLUDED_DIRS = frozenset(
    {
        "quarantine",
        "db",
        "logs",
        "models",
        "__pycache__",
        ".git",
        ".venv",
        "venv",
        "node_modules",
        ".biocybe",
    }
)

# Extensions non-pertinentes pour le scan signature (réduit la charge).
# La détection comportementale future (Lymphocyte T) pourra s'y intéresser.
DEFAULT_EXCLUDED_SUFFIXES = frozenset(
    {
        ".log",
        ".tmp",
        ".swp",
        ".lock",
        ".pyc",
    }
)


class FileSystemWatcher:
    """Surveille un ou plusieurs dossiers et scanne les fichiers en temps réel.

    Architecture :
      - 1 `watchdog.Observer` (thread géré par watchdog) écoute les
        événements filesystem et empile les chemins dans une file.
      - 1 thread "scanner" dépile, scanne via `BCell.scan_file_sync`,
        applique éventuellement la quarantaine, déclenche les callbacks.

    Le débouncing court (~0.3 s) évite de scanner 5 fois le même
    fichier pendant qu'un éditeur le réécrit.
    """

    def __init__(
        self,
        directories: list[str | Path],
        *,
        cell: BCell | None = None,
        quarantine_on_match: bool = False,
        dry_run: bool = False,
        recursive: bool = True,
        callback: WatchCallback | None = None,
        debounce_seconds: float = 0.3,
        excluded_dirs: frozenset[str] = DEFAULT_WATCH_EXCLUDED_DIRS,
        excluded_suffixes: frozenset[str] = DEFAULT_EXCLUDED_SUFFIXES,
        memory=None,
        regen_healer=None,
        regen_auto_heal: bool = False,
        regen_burst_threshold: int = 5,
        regen_burst_window: float = 10.0,
    ):
        self.directories = [Path(d).resolve() for d in directories]
        self.cell = cell or BCell("realtime_watcher")
        self.quarantine_on_match = quarantine_on_match
        self.dry_run = dry_run
        # Mémoire immunitaire optionnelle : suppression FP + apprentissage
        self.memory = memory
        # Auto-régénération : SelfHealer optionnel + détection de rafale
        # ransomware. Par défaut auto_heal=False = alerte seulement (la
        # restauration auto écrase des fichiers, donc opt-in explicite).
        self.regen_healer = regen_healer
        self.regen_auto_heal = bool(regen_auto_heal)
        self.regen_burst_threshold = int(regen_burst_threshold)
        self.regen_burst_window = float(regen_burst_window)
        self._regen_window: deque[float] = deque()
        self._regen_lock = threading.Lock()
        self.recursive = recursive
        self.callback = callback
        self.debounce_seconds = debounce_seconds

        self.stats = WatcherStats()
        self._queue: deque[tuple[float, str, str]] = deque()
        self._queue_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._observer: Observer | None = None
        self._scanner_thread: threading.Thread | None = None
        self._handler = _ScanHandler(
            self._queue, self._queue_lock, excluded_dirs, excluded_suffixes
        )

    # ---- Lifecycle ------------------------------------------------------

    def start(self) -> None:
        if self._observer is not None:
            logger.warning("Watcher déjà démarré.")
            return

        # Vérifier que les dossiers existent (sinon Observer.schedule plante).
        for d in self.directories:
            if not d.is_dir():
                logger.warning("Dossier inexistant ignoré : %s", d)

        self._observer = Observer()
        for d in self.directories:
            if d.is_dir():
                self._observer.schedule(self._handler, str(d), recursive=self.recursive)
                logger.info("Surveillance temps-réel : %s (recursive=%s)", d, self.recursive)

        self._observer.start()
        self._scanner_thread = threading.Thread(
            target=self._scanner_loop, name="biocybe-watcher-scanner", daemon=True
        )
        self._scanner_thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=timeout)
            self._observer = None
        if self._scanner_thread is not None:
            self._scanner_thread.join(timeout=timeout)
            self._scanner_thread = None
        logger.info("Watcher arrêté. Stats : %s", self.stats.to_dict())

    def __enter__(self) -> FileSystemWatcher:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---- Boucle de scan -------------------------------------------------

    def _scanner_loop(self) -> None:
        """Boucle qui dépile les événements et lance le scan.

        Implémente un débouncing simple : si le même chemin réapparaît
        dans la file pendant `debounce_seconds`, on ne scanne qu'une
        fois (le dernier événement gagne).
        """
        pending: dict[str, tuple[float, str]] = {}

        while not self._stop_event.is_set():
            # 1. Drainer la file dans pending (le plus récent gagne)
            with self._queue_lock:
                while self._queue:
                    ts, path, ev_type = self._queue.popleft()
                    self.stats.events_observed += 1
                    pending[path] = (ts, ev_type)

            # 2. Traiter les entrées dont l'event est "stable" (>= debounce)
            now = time.time()
            ready_paths = [p for p, (ts, _) in pending.items() if now - ts >= self.debounce_seconds]

            for path in ready_paths:
                ts, ev_type = pending.pop(path)
                self._process(path, ev_type, ts)

            # 3. Attendre un peu avant la prochaine itération
            self._stop_event.wait(0.1)

    def _process(self, path: str, ev_type: str, ts: float) -> None:
        ev = WatchEvent(timestamp=ts, path=Path(path), event_type=ev_type)

        try:
            # Le fichier peut avoir disparu entre l'événement et le scan
            # (création-puis-suppression rapide d'un .tmp par un éditeur).
            if not os.path.isfile(path):
                self.stats.events_skipped += 1
                return

            ev.result = self.cell.scan_file_sync(path)
            self.stats.events_scanned += 1

            # Auto-régénération : un fichier baseliné a-t-il dérivé ?
            # (indépendant de la détection malware — un ransomware chiffre
            # des fichiers sains qui ne matchent aucune signature).
            if self.regen_healer is not None:
                self._check_regeneration(path)

            # Mémoire immunitaire : suppression FP + apprentissage (réponse 2ndaire)
            if ev.is_malicious and self.memory is not None:
                if self._apply_memory(path, ev):
                    # Faux positif confirmé : on étouffe (pas de detect/quarantine)
                    self.stats.memory_suppressed += 1
                    logger.info("[RT-MEMORY] %s supprimé (faux positif confirmé)", path)
                    return

            if ev.is_malicious:
                self.stats.detections += 1
                logger.warning(
                    "[RT-DETECT] %s : famille=%s sévérité=%s",
                    path,
                    ev.result.malware_family or "inconnue",
                    ev.result.severity,
                )
                # Notification non bloquante via le hook isolation
                try:
                    from .isolation import _fire_notify

                    rule_names = [m.get("rule") for m in ev.result.matched_rules if m.get("rule")]
                    _fire_notify(
                        kind="realtime_detection",
                        severity="warning" if ev.result.severity in ("low", "medium") else "error",
                        title=f"Détection temps-réel : {Path(path).name}",
                        message=f"YARA={','.join(rule_names) or 'unknown'} "
                        f"famille={ev.result.malware_family or 'inconnue'}",
                        payload={
                            "file_path": path,
                            "family": ev.result.malware_family,
                            "severity": ev.result.severity,
                            "rules": rule_names,
                            "detected_by": self.cell.name,
                        },
                    )
                except Exception:
                    pass  # ne JAMAIS faire crasher le watcher sur une notif

                if self.quarantine_on_match:
                    if self.dry_run:
                        ev.dry_run_quarantine = True
                        logger.info("[RT-DRY-RUN] aurait mis en quarantaine : %s", path)
                    else:
                        try:
                            reason_parts = [
                                f"yara:{m.get('rule')}"
                                for m in ev.result.matched_rules
                                if m.get("rule")
                            ]
                            ev.quarantine = quarantine_file(
                                path,
                                reason=", ".join(reason_parts) or "rt_detection",
                                detected_by=self.cell.name,
                                extra={
                                    "family": ev.result.malware_family,
                                    "severity": ev.result.severity,
                                    "trigger": "realtime",
                                },
                            )
                            self.stats.quarantined += 1
                        except Exception as exc:
                            ev.error = f"quarantine_failed: {exc}"
                            self.stats.errors += 1
                            logger.error("Échec quarantaine temps-réel pour %s : %s", path, exc)

        except Exception as exc:
            ev.error = str(exc)
            self.stats.errors += 1
            logger.error("Erreur de scan temps-réel pour %s : %s", path, exc)

        if self.callback is not None:
            try:
                self.callback(ev)
            except Exception as exc:
                logger.error("Callback watcher a levé une exception : %s", exc)

    def _check_regeneration(self, path: str) -> None:
        """Détecte le drift d'un fichier baseliné + rafale ransomware.

        Si un fichier protégé par la baseline a été modifié, on l'enregistre
        dans une fenêtre glissante. Au-delà du seuil de rafale (N fichiers
        en T secondes = signature ransomware), on alerte et — si auto_heal
        est activé — on restaure les fichiers en drift depuis le coffre.
        """
        try:
            from .scanner import _sha256_of_file

            key = str(Path(path).resolve())
            entry = self.regen_healer._entries.get(key)
            if entry is None:
                return  # pas un fichier baseliné
            cur = _sha256_of_file(Path(path))
            if cur is None or cur == entry.sha256:
                return  # intact
        except Exception as exc:
            logger.error("Régénération (check %s) : %s", path, exc)
            return

        # Drift détecté sur un fichier protégé
        self.stats.regen_drift_detected += 1
        now = time.time()
        with self._regen_lock:
            self._regen_window.append(now)
            cutoff = now - self.regen_burst_window
            while self._regen_window and self._regen_window[0] < cutoff:
                self._regen_window.popleft()
            burst = len(self._regen_window) >= self.regen_burst_threshold
            window_count = len(self._regen_window)

        logger.warning(
            "[REGEN] drift sur fichier protégé : %s (%d en %.0fs)",
            path,
            window_count,
            self.regen_burst_window,
        )

        if not burst:
            return

        # Rafale = ransomware suspecté
        try:
            from .isolation import _fire_notify

            _fire_notify(
                kind="realtime_detection",
                severity="critical",
                title="Ransomware suspecté : modification de masse de fichiers protégés",
                message=f"{window_count} fichiers baselinés modifiés en "
                f"{self.regen_burst_window:.0f}s. "
                + (
                    "Régénération automatique déclenchée."
                    if self.regen_auto_heal
                    else "Lancez `biocybe regen heal --execute` pour restaurer."
                ),
                payload={"window_count": window_count, "auto_heal": self.regen_auto_heal},
            )
        except Exception:
            pass

        if self.regen_auto_heal:
            try:
                from .regeneration import HealAction

                results = self.regen_healer.heal(dry_run=False)
                healed = sum(1 for r in results if r.action == HealAction.RESTORED)
                self.stats.regen_healed += healed
                logger.warning(
                    "[REGEN] auto-restauration : %d fichier(s) restauré(s) depuis la baseline",
                    healed,
                )
                with self._regen_lock:
                    self._regen_window.clear()
            except Exception as exc:
                logger.error("[REGEN] auto-heal a échoué : %s", exc)

    def _apply_memory(self, path: str, ev) -> bool:
        """Croise une détection RT avec la mémoire immunitaire.

        Retourne True si le fichier est un faux positif confirmé (à
        étouffer). Sinon mémorise la détection et retourne False.
        """
        try:
            from .scanner import _sha256_of_file

            sha = _sha256_of_file(Path(path))
            if sha is None:
                return False
            rec = self.memory.recall(sha, "sha256")
            if rec is not None and rec.is_confirmed_benign:
                return True
            from .memory import VERDICT_MALICIOUS

            self.memory.remember(
                sha,
                indicator_type="sha256",
                verdict=VERDICT_MALICIOUS,
                confidence=round(ev.result.confidence * 100),
                family=ev.result.malware_family,
                source="watcher:realtime",
            )
        except Exception as exc:
            logger.error("Mémoire immunitaire (watcher %s) : %s", path, exc)
        return False
