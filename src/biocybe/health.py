"""Santé du process daemon.

Le conteneur n'a pas d'endpoint HTTP tant que les métriques ne sont pas
activées (extra ``web``). Un fichier heartbeat, écrit par la boucle
principale, permet au HEALTHCHECK Docker de voir un daemon bloqué
sans sonder le réseau.
"""

from __future__ import annotations

import os
import time
from pathlib import Path


def heartbeat_path() -> Path | None:
    raw = os.environ.get("BIOCYBE_HEARTBEAT_FILE", "").strip()
    if not raw:
        return None
    return Path(raw)


def write_heartbeat(path: str | Path | None = None) -> bool:
    """Écrit l'horodatage courant. False si aucun chemin ou FS en lecture seule."""
    target = Path(path) if path is not None else heartbeat_path()
    if target is None:
        return False
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(f"{time.time():.3f}\n", encoding="ascii")
        os.replace(tmp, target)
    except OSError:
        return False
    return True


def heartbeat_is_fresh(path: str | Path, *, max_age: float = 60.0) -> bool:
    """True si le fichier existe et a été touché il y a moins de ``max_age`` secondes."""
    try:
        age = time.time() - Path(path).stat().st_mtime
    except OSError:
        return False
    return age <= max_age
