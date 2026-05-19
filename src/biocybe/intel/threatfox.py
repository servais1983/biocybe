"""Client abuse.ch ThreatFox pour BioCybe — feed d'IOCs structurés.

ThreatFox partage des **indicateurs de compromission (IOCs)** au format
JSON structuré : URLs, domaines, IPs, hashes, etc., chacun avec une
famille de malware associée et un confidence score.

C'est complémentaire de MalwareBazaar (qui se focalise sur les
échantillons de fichiers) et URLhaus (URLs distribuant des malwares).
ThreatFox couvre TOUS les types d'IOC (C2, infrastructure, hashes).

Cas d'usage BioCybe :
  - Enrichir la base de hashes (en plus de MalwareBazaar)
  - Constituer une blocklist IPs/domaines pour la cellule réseau (Phase 3.e+)
  - Lookup rapide "ce hash/IP/URL est-il connu malveillant ?"

API : POST https://threatfox-api.abuse.ch/api/v1/
Auth : Auth-Key abuse.ch obligatoire (idem MalwareBazaar)
Doc : https://threatfox.abuse.ch/api/
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from .abusech import AbuseChAPIError, AbuseChAuthMissing

logger = logging.getLogger("biocybe.intel.threatfox")

DEFAULT_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
DEFAULT_TIMEOUT_S = 30


@dataclass
class ThreatFoxIOC:
    """Un IOC ThreatFox (sous-ensemble utile)."""

    ioc_id: str
    ioc_type: str  # "url" | "domain" | "ip:port" | "md5_hash" | "sha256_hash" | ...
    ioc_value: str
    threat_type: str  # "payload" | "c2_server" | "botnet_cc" | ...
    malware: str  # famille
    confidence_level: int  # 0-100
    first_seen: str
    last_seen: str
    tags: list[str]

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ThreatFoxIOC:
        return cls(
            ioc_id=str(raw.get("id", "")),
            ioc_type=raw.get("ioc_type", ""),
            ioc_value=raw.get("ioc", ""),
            threat_type=raw.get("threat_type", ""),
            malware=raw.get("malware_printable") or raw.get("malware") or "unknown",
            confidence_level=int(raw.get("confidence_level", 0) or 0),
            first_seen=raw.get("first_seen", ""),
            last_seen=raw.get("last_seen", "") or raw.get("first_seen", ""),
            tags=list(raw.get("tags", []) or []),
        )


class ThreatFoxClient:
    """Client minimal pour l'API ThreatFox d'abuse.ch."""

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
        return {
            "Auth-Key": self.auth_key,
            "User-Agent": "BioCybe/0.2 (+https://github.com/servais1983/biocybe)",
        }

    def get_recent(self, days: int = 1) -> list[ThreatFoxIOC]:
        """Récupère les IOCs des N derniers jours (max 7 d'après abuse.ch)."""
        days = max(1, min(7, int(days)))
        payload = {"query": "get_iocs", "days": days}
        resp = self.session.post(
            self.api_url,
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")
        if status != "ok":
            raise AbuseChAPIError(f"ThreatFox a répondu : {status}")
        iocs = [ThreatFoxIOC.from_api(item) for item in data.get("data", [])]
        logger.info("ThreatFox : %d IOCs récupérés sur %d jour(s)", len(iocs), days)
        return iocs


def update_threatfox_iocs(
    db_path: str | Path = "db/signatures",
    *,
    days: int = 1,
    auth_key: str | None = None,
    client: ThreatFoxClient | None = None,
) -> dict[str, int]:
    """Met à jour `db/signatures/threatfox/recent.json` depuis ThreatFox.

    Stocke aussi des index par type d'IOC pour lookup rapide :
      - `threatfox/by_type/hash.json`     : sha256/md5 → metadata
      - `threatfox/by_type/url.json`      : URL → metadata
      - `threatfox/by_type/domain.json`   : domain → metadata
      - `threatfox/by_type/ip.json`       : IP:port → metadata

    Returns:
        Compteurs : {"fetched", "by_type_counts": {...}}.
    """
    client = client or ThreatFoxClient(auth_key=auth_key)
    iocs = client.get_recent(days=days)

    db_path = Path(db_path)
    tf_dir = db_path / "threatfox"
    by_type_dir = tf_dir / "by_type"
    by_type_dir.mkdir(parents=True, exist_ok=True)

    # Dump brut
    raw_file = tf_dir / "iocs.json"
    serialized = [asdict(i) for i in iocs]
    with raw_file.open("w", encoding="utf-8") as f:
        json.dump(serialized, f, indent=2, ensure_ascii=False)

    # Index par type. ThreatFox utilise des noms granulaires :
    # sha256_hash, md5_hash, sha1_hash, url, domain, ip:port, etc.
    # On regroupe en catégories logiques pour BioCybe.
    type_buckets: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    def _bucket_for(ioc_type: str) -> str:
        if "hash" in ioc_type:
            return "hash"
        if ioc_type == "url":
            return "url"
        if ioc_type == "domain":
            return "domain"
        if ioc_type.startswith("ip"):
            return "ip"
        return "other"

    by_type_counts: dict[str, int] = defaultdict(int)
    for ioc in iocs:
        bucket = _bucket_for(ioc.ioc_type)
        type_buckets[bucket][ioc.ioc_value] = {
            "malware": ioc.malware,
            "threat_type": ioc.threat_type,
            "confidence": ioc.confidence_level,
            "first_seen": ioc.first_seen,
            "tags": ioc.tags,
            "source": "abuse.ch/ThreatFox",
        }
        by_type_counts[bucket] += 1

    for bucket, mapping in type_buckets.items():
        out = by_type_dir / f"{bucket}.json"
        with out.open("w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2, ensure_ascii=False, sort_keys=True)

    (tf_dir / "last_update.txt").write_text(datetime.now().isoformat(), encoding="utf-8")

    stats = {
        "fetched": len(iocs),
        "by_type_counts": dict(by_type_counts),
    }
    logger.info(
        "ThreatFox update : %d IOCs (%s).",
        stats["fetched"],
        stats["by_type_counts"],
    )
    return stats


__all__ = [
    "AbuseChAPIError",
    "AbuseChAuthMissing",
    "ThreatFoxClient",
    "ThreatFoxIOC",
    "update_threatfox_iocs",
]
