"""Client abuse.ch MalwareBazaar pour BioCybe.

Récupère les signatures hash (sha256/sha1/md5) d'échantillons récents
et les pousse dans `SignatureDatabase` de BioCybe.

Auth :
  Depuis 2024, abuse.ch impose une `Auth-Key` (gratuite, à demander
  sur https://auth.abuse.ch). On lit la clé via la variable
  d'environnement `ABUSECH_AUTH_KEY` ou via le paramètre `auth_key`.
  Sans clé, l'appel API retourne 401 et on lève `AbuseChAuthMissing`.

API utilisée :
  POST https://mb-api.abuse.ch/api/v1/
  Form data: query=get_recent&selector={time|100|1000}

Réponse JSON :
  { "query_status": "ok", "data": [ {sha256_hash, sha1_hash, md5_hash,
                                     signature, file_type, ...}, ... ] }

Doc : https://bazaar.abuse.ch/api/
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger("biocybe.intel.abusech")

DEFAULT_API_URL = "https://mb-api.abuse.ch/api/v1/"
DEFAULT_TIMEOUT_S = 30


class AbuseChAuthMissing(Exception):
    """Pas de clé Auth-Key abuse.ch disponible.

    Demander sur https://auth.abuse.ch (gratuit), puis exporter :
        export ABUSECH_AUTH_KEY="..."
    """


class AbuseChAPIError(Exception):
    """Erreur retournée par l'API (query_status != 'ok')."""


@dataclass
class MalwareSample:
    """Un échantillon MalwareBazaar (sous-ensemble utile pour BioCybe)."""

    sha256: str
    sha1: str | None
    md5: str | None
    signature: str | None  # famille de malware (Emotet, Cobalt, etc.)
    file_type: str | None
    file_name: str | None
    file_size: int | None
    first_seen: str | None
    tags: list[str]

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> MalwareSample:
        return cls(
            sha256=raw.get("sha256_hash", ""),
            sha1=raw.get("sha1_hash"),
            md5=raw.get("md5_hash"),
            signature=raw.get("signature"),
            file_type=raw.get("file_type"),
            file_name=raw.get("file_name"),
            file_size=raw.get("file_size"),
            first_seen=raw.get("first_seen"),
            tags=list(raw.get("tags", []) or []),
        )

    def to_signature_entry(self) -> dict[str, Any]:
        """Format compatible avec SignatureDatabase de BioCybe."""
        return {
            "family": self.signature or "unknown",
            "severity": "high",
            "source": "abuse.ch/MalwareBazaar",
            "first_seen": self.first_seen,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "tags": self.tags,
        }


class MalwareBazaarClient:
    """Client minimal pour l'API MalwareBazaar d'abuse.ch."""

    def __init__(
        self,
        auth_key: str | None = None,
        api_url: str = DEFAULT_API_URL,
        timeout: float = DEFAULT_TIMEOUT_S,
        session: requests.Session | None = None,
    ):
        self.auth_key = auth_key or os.environ.get("ABUSECH_AUTH_KEY")
        self.api_url = api_url
        self.timeout = timeout
        self.session = session or requests.Session()

    def _headers(self) -> dict[str, str]:
        if not self.auth_key:
            raise AbuseChAuthMissing(
                "Pas d'Auth-Key abuse.ch. Demande-la gratuitement sur "
                "https://auth.abuse.ch puis exporte ABUSECH_AUTH_KEY=..."
            )
        # User-Agent identifiable : abuse.ch demande qu'on ne se cache pas.
        return {
            "Auth-Key": self.auth_key,
            "User-Agent": "BioCybe/0.2 (+https://github.com/servais1983/biocybe)",
        }

    def get_recent(self, selector: str = "time") -> list[MalwareSample]:
        """Récupère les échantillons récents.

        Args:
            selector: 'time' (60 dernières min), '100' (100 derniers),
                      '1000' (1000 derniers). Voir la doc abuse.ch.
        """
        data = {"query": "get_recent", "selector": selector}
        resp = self.session.post(
            self.api_url, data=data, headers=self._headers(), timeout=self.timeout
        )
        resp.raise_for_status()
        payload = resp.json()

        status = payload.get("query_status")
        if status != "ok":
            raise AbuseChAPIError(f"MalwareBazaar a répondu : {status}")

        samples = [MalwareSample.from_api(item) for item in payload.get("data", [])]
        logger.info(
            "MalwareBazaar : %d échantillons récupérés (selector=%s)", len(samples), selector
        )
        return samples


def update_signatures_from_malwarebazaar(
    db_path: str | Path = "db/signatures",
    *,
    selector: str = "100",
    auth_key: str | None = None,
    client: MalwareBazaarClient | None = None,
) -> dict[str, int]:
    """Met à jour `db/signatures/hashes/signatures.json` depuis MalwareBazaar.

    Returns:
        Compteurs : {"fetched", "added", "updated", "total"}.

    Raises:
        AbuseChAuthMissing: pas de clé.
        AbuseChAPIError: l'API a renvoyé une erreur métier.
        requests.HTTPError: erreur HTTP (401, 429, etc.).
    """
    client = client or MalwareBazaarClient(auth_key=auth_key)
    samples = client.get_recent(selector=selector)

    db_path = Path(db_path)
    hashes_dir = db_path / "hashes"
    hashes_dir.mkdir(parents=True, exist_ok=True)
    sig_file = hashes_dir / "signatures.json"

    if sig_file.exists():
        with sig_file.open("r", encoding="utf-8") as f:
            try:
                existing: dict[str, dict[str, Any]] = json.load(f)
            except json.JSONDecodeError:
                logger.warning("signatures.json corrompu, écrasement.")
                existing = {}
    else:
        existing = {}

    added = updated = 0
    for sample in samples:
        entry = sample.to_signature_entry()
        # On indexe par chaque hash disponible (sha256/sha1/md5) pour
        # accélérer les check_file_hash quel que soit l'algo demandé.
        for h in filter(None, (sample.sha256, sample.sha1, sample.md5)):
            entry_with_hash = dict(entry, hash=h)
            if h in existing:
                if existing[h] != entry_with_hash:
                    existing[h] = entry_with_hash
                    updated += 1
            else:
                existing[h] = entry_with_hash
                added += 1

    with sig_file.open("w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False, sort_keys=True)

    # Timestamp de dernière mise à jour
    (db_path / "last_update.txt").write_text(datetime.now().isoformat(), encoding="utf-8")

    stats = {
        "fetched": len(samples),
        "added": added,
        "updated": updated,
        "total": len(existing),
    }
    logger.info(
        "Mise à jour MalwareBazaar : %d récupérés, %d ajoutés, %d mis à jour, "
        "%d signatures totales.",
        stats["fetched"],
        stats["added"],
        stats["updated"],
        stats["total"],
    )
    return stats
