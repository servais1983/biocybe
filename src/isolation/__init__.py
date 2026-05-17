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
from typing import Any, Dict, List, Optional

__version__ = "0.1.0"

logger = logging.getLogger("biocybe.isolation")

DEFAULT_QUARANTINE_DIR = "quarantine"
MANIFEST_FILENAME = "manifest.json"


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
    detected_by: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


def _load_manifest(manifest_path: Path) -> List[Dict[str, Any]]:
    if not manifest_path.exists():
        return []
    try:
        with manifest_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Manifeste de quarantaine illisible (%s) : %s", manifest_path, exc)
        return []


def _save_manifest(manifest_path: Path, entries: List[Dict[str, Any]]) -> None:
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
    detected_by: Optional[str] = None,
    quarantine_dir: str | os.PathLike = DEFAULT_QUARANTINE_DIR,
    extra: Optional[Dict[str, Any]] = None,
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
        src, dest, reason,
    )
    return entry


def list_quarantine(quarantine_dir: str | os.PathLike = DEFAULT_QUARANTINE_DIR) -> List[Dict[str, Any]]:
    """Retourne le contenu du manifeste de quarantaine."""
    return _load_manifest(Path(quarantine_dir) / MANIFEST_FILENAME)


def isolate(target, level: str = "medium"):
    """Compat : ancienne API (réseau/processus). Pas encore implémentée."""
    raise NotImplementedError(
        "isolate(target, level) (réseau/processus) n'est pas encore implémenté. "
        "Pour la quarantaine de fichiers, utilise quarantine_file()."
    )
