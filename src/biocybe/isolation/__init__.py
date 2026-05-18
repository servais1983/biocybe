"""
Module Isolation pour BioCybe.

Confinement minimal des menaces : déplacement de fichier vers un dossier
de quarantaine, avec manifeste JSON listant chaque entrée (chemin
original, date, raison, hash).

Phase 1 : pas de chiffrement, pas de sandbox réseau. C'est une mise à
l'écart filesystem suffisante pour empêcher l'exécution accidentelle
et pour qu'un humain puisse trier.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

__version__ = "0.1.0"

logger = logging.getLogger("biocybe.isolation")

DEFAULT_QUARANTINE_DIR = "quarantine"
MANIFEST_FILENAME = "manifest.json"


# Hook de notification optionnel : callable[Event] qui sera appelé
# si défini par `set_notifier(...)`. Permet à d'autres modules
# (notamment biocybe.notify.NotifierManager) de capter les événements
# sans coupler isolation/ à notify/.
_notify_hook = None


def set_notify_hook(hook) -> None:
    """Installe un callback `hook(event)` appelé pour chaque action.

    `hook` doit être tolérant aux exceptions — un échec de notification
    ne doit JAMAIS empêcher la quarantaine de se faire.
    """
    global _notify_hook
    _notify_hook = hook


def _fire_notify(kind: str, severity: str, title: str, message: str, payload: dict) -> None:
    """Appelle le hook si défini, en avalant toute exception."""
    if _notify_hook is None:
        return
    try:
        _notify_hook(kind=kind, severity=severity, title=title, message=message, payload=payload)
    except Exception as exc:
        logger.error("Notify hook a levé une exception : %s", exc)


@dataclass
class QuarantineEntry:
    """Une entrée du manifeste de quarantaine."""

    quarantine_id: str
    original_path: str
    stored_filename: str
    sha256: str
    size_bytes: int
    quarantined_at: str
    reason: str
    detected_by: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _load_manifest(manifest_path: Path) -> list[dict[str, Any]]:
    if not manifest_path.exists():
        return []
    try:
        with manifest_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Manifeste de quarantaine illisible (%s) : %s", manifest_path, exc)
        return []


def _save_manifest(manifest_path: Path, entries: list[dict[str, Any]]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def quarantine_file(
    file_path: str | os.PathLike,
    reason: str = "manual",
    detected_by: str | None = None,
    quarantine_dir: str | os.PathLike = DEFAULT_QUARANTINE_DIR,
    extra: dict[str, Any] | None = None,
) -> QuarantineEntry:
    """Déplace un fichier vers la quarantaine et l'enregistre au manifeste.

    Args:
        file_path: chemin du fichier à mettre en quarantaine.
        reason: pourquoi (ex. "yara:EICAR_Test_File", "hash_match", "manual").
        detected_by: nom de la cellule qui a déclenché (ex. "b_cell_main").
        quarantine_dir: dossier racine de quarantaine.
        extra: métadonnées libres à joindre.

    Returns:
        L'entrée créée.

    Raises:
        FileNotFoundError: si `file_path` n'existe pas.
    """
    src = Path(file_path).resolve()
    if not src.is_file():
        raise FileNotFoundError(f"Fichier introuvable : {src}")

    qdir = Path(quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)

    file_hash = _sha256_of(src)
    timestamp = datetime.now()
    qid = f"{timestamp.strftime('%Y%m%d%H%M%S%f')}_{file_hash[:12]}"
    stored_filename = f"{qid}__{src.name}.quarantine"
    dest = qdir / stored_filename

    size = src.stat().st_size
    shutil.move(str(src), str(dest))
    # Retirer les permissions d'exécution (best effort, surtout Linux).
    try:
        os.chmod(dest, 0o600)
    except OSError as exc:
        logger.debug("chmod sur %s impossible : %s", dest, exc)

    entry = QuarantineEntry(
        quarantine_id=qid,
        original_path=str(src),
        stored_filename=stored_filename,
        sha256=file_hash,
        size_bytes=size,
        quarantined_at=timestamp.isoformat(),
        reason=reason,
        detected_by=detected_by,
        extra=extra or {},
    )

    manifest_path = qdir / MANIFEST_FILENAME
    manifest = _load_manifest(manifest_path)
    manifest.append(asdict(entry))
    _save_manifest(manifest_path, manifest)

    logger.warning(
        "Fichier mis en quarantaine : %s -> %s (raison=%s)",
        src,
        dest,
        reason,
    )

    _fire_notify(
        kind="quarantine_created",
        severity="warning",
        title=f"Quarantaine : {src.name}",
        message=f"Fichier malveillant déplacé vers {dest.name} ({reason})",
        payload={
            "original_path": str(src),
            "quarantine_id": qid,
            "sha256": file_hash,
            "reason": reason,
            "detected_by": detected_by,
            **(extra or {}),
        },
    )

    # Audit trail (no-op si pas configuré)
    try:
        from .. import audit as _audit

        _audit.audit(
            "quarantine_created",
            actor=detected_by or "biocybe",
            details={
                "quarantine_id": qid,
                "original_path": str(src),
                "stored_filename": stored_filename,
                "sha256": file_hash,
                "size_bytes": size,
                "reason": reason,
            },
        )
    except Exception as exc:
        logger.debug("audit append failed (non-fatal) : %s", exc)

    return entry


def list_quarantine(
    quarantine_dir: str | os.PathLike = DEFAULT_QUARANTINE_DIR,
) -> list[dict[str, Any]]:
    """Retourne le contenu du manifeste de quarantaine."""
    return _load_manifest(Path(quarantine_dir) / MANIFEST_FILENAME)


def get_quarantine_entry(
    quarantine_id: str,
    quarantine_dir: str | os.PathLike = DEFAULT_QUARANTINE_DIR,
) -> dict[str, Any] | None:
    """Retrouve une entrée par son ID, ou None si absente."""
    for entry in list_quarantine(quarantine_dir):
        if entry.get("quarantine_id") == quarantine_id:
            return entry
    return None


class QuarantineIntegrityError(Exception):
    """Le fichier en quarantaine ne correspond plus à son hash d'origine."""


def restore_file(
    quarantine_id: str,
    *,
    destination: str | os.PathLike | None = None,
    quarantine_dir: str | os.PathLike = DEFAULT_QUARANTINE_DIR,
    verify_hash: bool = True,
    remove_from_manifest: bool = True,
) -> Path:
    """Restaure un fichier mis en quarantaine.

    La réversibilité de la quarantaine est une exigence SOC : sans elle,
    impossible d'oser activer le mode `--quarantine` en évaluation.

    Args:
        quarantine_id: ID retourné par `quarantine_file` (présent dans
            le manifeste).
        destination: chemin de restauration. Par défaut, le chemin
            original au moment de la mise en quarantaine.
        quarantine_dir: dossier racine de quarantaine.
        verify_hash: si True (défaut), vérifie SHA-256 avant restauration ;
            lève `QuarantineIntegrityError` si divergence. Désactiver
            uniquement en cas d'investigation forensique.
        remove_from_manifest: si True (défaut), retire l'entrée du
            manifeste après restauration réussie. Mettre False pour
            garder une trace d'audit (le fichier en quarantaine est
            quand même retiré).

    Returns:
        Le chemin où le fichier a été restauré.

    Raises:
        KeyError: ID inconnu.
        FileNotFoundError: fichier en quarantaine manquant sur disque.
        QuarantineIntegrityError: hash divergent et verify_hash=True.
        FileExistsError: destination occupée.
    """
    qdir = Path(quarantine_dir)
    entry = get_quarantine_entry(quarantine_id, qdir)
    if entry is None:
        raise KeyError(f"ID de quarantaine inconnu : {quarantine_id}")

    src = qdir / entry["stored_filename"]
    if not src.is_file():
        raise FileNotFoundError(
            f"Fichier en quarantaine manquant : {src}. "
            "Le manifeste référence un fichier supprimé manuellement."
        )

    if verify_hash:
        current_hash = _sha256_of(src)
        if current_hash != entry["sha256"]:
            raise QuarantineIntegrityError(
                f"Hash divergent pour {quarantine_id} : "
                f"attendu {entry['sha256']}, observé {current_hash}"
            )

    dest = Path(destination) if destination else Path(entry["original_path"])
    if dest.exists():
        raise FileExistsError(
            f"Destination déjà occupée : {dest}. Précisez `destination=` pour restaurer ailleurs."
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    logger.warning("Fichier restauré : %s -> %s", src, dest)

    _fire_notify(
        kind="quarantine_restored",
        severity="notice",
        title=f"Restauration : {dest.name}",
        message=f"Fichier {quarantine_id} restauré vers {dest}",
        payload={
            "quarantine_id": quarantine_id,
            "restored_to": str(dest),
            "verified_hash": verify_hash,
        },
    )

    try:
        from .. import audit as _audit

        _audit.audit(
            "quarantine_restored",
            actor="biocybe.isolation",
            details={
                "quarantine_id": quarantine_id,
                "restored_to": str(dest),
                "verify_hash": verify_hash,
                "removed_from_manifest": remove_from_manifest,
            },
        )
    except Exception as exc:
        logger.debug("audit append failed (non-fatal) : %s", exc)

    if remove_from_manifest:
        manifest_path = qdir / MANIFEST_FILENAME
        manifest = _load_manifest(manifest_path)
        manifest = [e for e in manifest if e.get("quarantine_id") != quarantine_id]
        _save_manifest(manifest_path, manifest)
        logger.info("Entrée %s retirée du manifeste", quarantine_id)

    return dest


def isolate(target, level: str = "medium"):
    """Compat : ancienne API (réseau/processus). Pas encore implémentée."""
    raise NotImplementedError(
        "isolate(target, level) (réseau/processus) n'est pas encore implémenté. "
        "Pour la quarantaine de fichiers, utilise quarantine_file()."
    )
