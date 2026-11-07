"""HEALTHCHECK de l'image BioCybe.

Ne contacte un URL que si ``BIOCYBE_HEALTHCHECK_URL`` est défini
(l'API de ce conteneur). Sinon il regarde le heartbeat local du daemon.
Sans aucune des deux variables, le check réussit : l'image sert aussi
aux commandes one-shot (``biocybe --help``, ``scan``).
"""

from __future__ import annotations

import os
from urllib.parse import urlparse


def main() -> int:
    heartbeat = os.environ.get("BIOCYBE_HEARTBEAT_FILE", "").strip()
    if heartbeat:
        from biocybe.health import heartbeat_is_fresh

        return 0 if heartbeat_is_fresh(heartbeat, max_age=60.0) else 1

    url = os.environ.get("BIOCYBE_HEALTHCHECK_URL", "").strip()
    if url:
        import urllib.request

        parsed = urlparse(url)
        # Uniquement l'API de ce conteneur. Pas de file: ni d'hôte distant.
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
            "127.0.0.1",
            "localhost",
        }:
            return 1
        try:
            with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310
                return 0 if response.status == 200 else 1
        except Exception:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
