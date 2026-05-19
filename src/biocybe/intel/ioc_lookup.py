"""Moteur de lookup IOC pour BioCybe — exploite les feeds URLhaus + ThreatFox.

Charge en mémoire les index générés par `update_urlhaus_iocs` et
`update_threatfox_iocs` (Phase 3.d) pour fournir un lookup O(1) sur :
  - hashes (sha256/md5/sha1) — agrégés depuis ThreatFox `by_type/hash.json`
    et MalwareBazaar `hashes/signatures.json`
  - hostnames — depuis URLhaus `hostnames.json` et ThreatFox `by_type/domain.json`
  - URLs complètes — depuis URLhaus `urls.json` (clé URL exacte)
  - IPs (avec ou sans port) — depuis ThreatFox `by_type/ip.json`

Conçu pour être **chargé une fois au démarrage** d'un processus
(scanner, daemon, API) et interrogé pendant toute sa vie. Recharge
volontaire via `reload()` après un `intel update`.

Fail-safe : si un fichier d'index n'existe pas (feeds jamais
récupérés), le bucket correspondant reste vide ; le lookup renvoie
None sans crasher. C'est important pour les déploiements neufs où
seulement certaines sources sont configurées.

Exemple :
    lookup = IOCLookup.from_db("db/signatures")
    if hit := lookup.lookup_hostname("evil.example.com"):
        # hit = {"source": "abuse.ch/URLhaus", "malware": "...", ...}
"""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("biocybe.intel.lookup")


@dataclass
class IOCHit:
    """Résultat d'un lookup IOC positif."""

    ioc_type: str  # "hash" | "hostname" | "url" | "ip"
    value: str  # la valeur cherchée (normalisée)
    source: str  # "abuse.ch/URLhaus" | "abuse.ch/ThreatFox" | ...
    malware: str = "unknown"
    threat_type: str = ""
    confidence: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "malware": self.malware,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class IOCLookup:
    """Moteur de lookup IOC chargé en mémoire.

    Construit via `IOCLookup.from_db(path)` qui agrège les feeds
    présents sur disque. Si aucun feed n'a été récupéré, l'instance
    est vide (tous les `lookup_*` renvoient None) ; c'est la sémantique
    attendue pour un déploiement neuf.

    Thread-safe en lecture (dicts immutables après `from_db`). Pour
    rafraîchir après un `intel update`, appeler `reload()` ou
    reconstruire l'instance.
    """

    def __init__(
        self,
        db_path: str | Path = "db/signatures",
        *,
        hashes: dict[str, dict[str, Any]] | None = None,
        hostnames: dict[str, dict[str, Any]] | None = None,
        urls: dict[str, dict[str, Any]] | None = None,
        ips: dict[str, dict[str, Any]] | None = None,
    ):
        self.db_path = Path(db_path)
        self._hashes: dict[str, dict[str, Any]] = hashes or {}
        self._hostnames: dict[str, dict[str, Any]] = hostnames or {}
        self._urls: dict[str, dict[str, Any]] = urls or {}
        self._ips: dict[str, dict[str, Any]] = ips or {}

    @classmethod
    def from_db(cls, db_path: str | Path = "db/signatures") -> IOCLookup:
        """Charge tous les index disponibles depuis `db_path`.

        Sources fusionnées :
          - `hashes/signatures.json` (MalwareBazaar — Phase 2.2.b)
          - `threatfox/by_type/hash.json` (ThreatFox — Phase 3.d)
          - `urlhaus/hostnames.json` (URLhaus — Phase 3.d)
          - `urlhaus/urls.json` (URLhaus — Phase 3.d)
          - `threatfox/by_type/domain.json` (ThreatFox — Phase 3.d)
          - `threatfox/by_type/ip.json` (ThreatFox — Phase 3.d)

        Conflit de clé : un IOC peut apparaître dans plusieurs feeds.
        On garde la valeur de la plus haute confiance, ou la première
        rencontrée si pas de confidence.
        """
        instance = cls(db_path=db_path)
        instance.reload()
        return instance

    # ------------------------------------------------------------------
    # Chargement et fusion
    # ------------------------------------------------------------------

    def reload(self) -> dict[str, int]:
        """Recharge tous les index depuis le disque. Retourne les compteurs.

        Idempotent : peut être appelé périodiquement après un `intel
        update` pour rafraîchir sans redémarrer le processus.
        """
        hashes: dict[str, dict[str, Any]] = {}
        hostnames: dict[str, dict[str, Any]] = {}
        urls: dict[str, dict[str, Any]] = {}
        ips: dict[str, dict[str, Any]] = {}

        # MalwareBazaar : signatures.json est un dict hash → metadata
        mb_file = self.db_path / "hashes" / "signatures.json"
        for k, v in _safe_load_json(mb_file).items():
            hashes[k.lower()] = _normalize_mb_entry(v)

        # ThreatFox : index by_type
        tf_hash = self.db_path / "threatfox" / "by_type" / "hash.json"
        for k, v in _safe_load_json(tf_hash).items():
            _merge_keep_best(hashes, k.lower(), _normalize_tf_entry(v))

        tf_domain = self.db_path / "threatfox" / "by_type" / "domain.json"
        for k, v in _safe_load_json(tf_domain).items():
            _merge_keep_best(hostnames, k.lower(), _normalize_tf_entry(v))

        tf_ip = self.db_path / "threatfox" / "by_type" / "ip.json"
        for k, v in _safe_load_json(tf_ip).items():
            # ThreatFox stocke souvent "ip:port" — on indexe les deux
            entry = _normalize_tf_entry(v)
            _merge_keep_best(ips, k.lower(), entry)
            if ":" in k:
                ip_only = k.split(":", 1)[0]
                _merge_keep_best(ips, ip_only.lower(), entry)

        # URLhaus : hostnames index (hostname → [urls])
        uh_hosts = self.db_path / "urlhaus" / "hostnames.json"
        for hostname, url_list in _safe_load_json(uh_hosts).items():
            entry = {
                "source": "abuse.ch/URLhaus",
                "malware": "unknown",
                "threat_type": "malware_distribution",
                "confidence": 75,  # URLhaus implicite — URLs validées par CSIRT
                "url_count": len(url_list) if isinstance(url_list, list) else 0,
            }
            _merge_keep_best(hostnames, hostname.lower(), entry)

        # URLhaus : urls.json (liste d'objets URLHausEntry sérialisés)
        uh_urls = self.db_path / "urlhaus" / "urls.json"
        urls_data = _safe_load_json(uh_urls, default_list=True)
        if isinstance(urls_data, list):
            for item in urls_data:
                if not isinstance(item, dict):
                    continue
                url_value = item.get("url", "")
                if not url_value:
                    continue
                urls[url_value] = {
                    "source": "abuse.ch/URLhaus",
                    "malware": "unknown",
                    "threat_type": item.get("threat", "malware_distribution"),
                    "confidence": 75,
                    "hostname": item.get("hostname", ""),
                    "url_status": item.get("url_status", ""),
                    "date_added": item.get("date_added", ""),
                    "tags": item.get("tags", []),
                }

        self._hashes = hashes
        self._hostnames = hostnames
        self._urls = urls
        self._ips = ips

        stats = self.stats()
        logger.info(
            "IOCLookup chargé : %d hashes, %d hostnames, %d urls, %d ips",
            stats["hashes"],
            stats["hostnames"],
            stats["urls"],
            stats["ips"],
        )
        return stats

    def stats(self) -> dict[str, int]:
        """Compteurs par type d'IOC chargé."""
        return {
            "hashes": len(self._hashes),
            "hostnames": len(self._hostnames),
            "urls": len(self._urls),
            "ips": len(self._ips),
        }

    @property
    def total(self) -> int:
        return sum(self.stats().values())

    # ------------------------------------------------------------------
    # API de lookup
    # ------------------------------------------------------------------

    def lookup_hash(self, value: str) -> IOCHit | None:
        if not value:
            return None
        v = value.strip().lower()
        meta = self._hashes.get(v)
        if not meta:
            return None
        return IOCHit(
            ioc_type="hash",
            value=v,
            source=meta.get("source", "unknown"),
            malware=meta.get("malware") or meta.get("family") or "unknown",
            threat_type=meta.get("threat_type", ""),
            confidence=int(meta.get("confidence", 0) or 0),
            metadata=meta,
        )

    def lookup_hostname(self, value: str) -> IOCHit | None:
        if not value:
            return None
        v = value.strip().lower().rstrip(".")
        # On essaie d'abord le hostname exact, puis les domaines parents
        # (foo.bar.evil.com → bar.evil.com → evil.com). Cela permet de
        # détecter un sous-domaine non encore indexé d'un domaine connu
        # malveillant. Garde-fou : on s'arrête à 2 niveaux pour éviter
        # de matcher les TLDs.
        if v in self._hostnames:
            return self._make_host_hit(v, self._hostnames[v])
        parts = v.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._hostnames:
                hit = self._make_host_hit(v, self._hostnames[parent])
                hit.metadata = {**hit.metadata, "matched_parent_domain": parent}
                return hit
        return None

    def _make_host_hit(self, value: str, meta: dict[str, Any]) -> IOCHit:
        return IOCHit(
            ioc_type="hostname",
            value=value,
            source=meta.get("source", "unknown"),
            malware=meta.get("malware") or "unknown",
            threat_type=meta.get("threat_type", ""),
            confidence=int(meta.get("confidence", 0) or 0),
            metadata=meta,
        )

    def lookup_url(self, value: str) -> IOCHit | None:
        if not value:
            return None
        # Match exact d'abord
        if value in self._urls:
            meta = self._urls[value]
            return IOCHit(
                ioc_type="url",
                value=value,
                source=meta.get("source", "unknown"),
                malware=meta.get("malware") or "unknown",
                threat_type=meta.get("threat_type", ""),
                confidence=int(meta.get("confidence", 0) or 0),
                metadata=meta,
            )
        # Sinon, fallback sur le hostname extrait
        try:
            host = urlparse(value).hostname or ""
        except Exception:
            host = ""
        if host:
            host_hit = self.lookup_hostname(host)
            if host_hit:
                host_hit.metadata = {
                    **host_hit.metadata,
                    "matched_via": "hostname_of_url",
                    "original_url": value,
                }
                return host_hit
        return None

    def lookup_ip(self, value: str) -> IOCHit | None:
        if not value:
            return None
        v = value.strip().lower()
        # Tente direct, puis sans port
        meta = self._ips.get(v)
        if not meta and ":" in v:
            meta = self._ips.get(v.split(":", 1)[0])
        if not meta:
            return None
        return IOCHit(
            ioc_type="ip",
            value=v,
            source=meta.get("source", "unknown"),
            malware=meta.get("malware") or "unknown",
            threat_type=meta.get("threat_type", ""),
            confidence=int(meta.get("confidence", 0) or 0),
            metadata=meta,
        )

    def lookup_auto(self, value: str) -> IOCHit | None:
        """Devine le type d'IOC et appelle le bon lookup.

        Heuristique :
          - 32/40/64 hex chars → hash
          - commence par http:// ou https:// → url
          - parsable comme IP → ip
          - sinon → hostname
        """
        if not value:
            return None
        v = value.strip()

        # Hash : 32 (md5), 40 (sha1), 64 (sha256) caractères hex
        if len(v) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v):
            return self.lookup_hash(v)

        # URL
        if v.lower().startswith(("http://", "https://", "ftp://")):
            return self.lookup_url(v)

        # IP (avec ou sans port, IPv4 ou IPv6)
        candidate = v.split(":", 1)[0] if v.count(":") == 1 else v
        try:
            ipaddress.ip_address(candidate)
            return self.lookup_ip(v)
        except ValueError:
            pass

        # Hostname par défaut
        return self.lookup_hostname(v)


# ----------------------------------------------------------------------
# Helpers internes
# ----------------------------------------------------------------------


def _safe_load_json(path: Path, *, default_list: bool = False) -> Any:
    """Charge un JSON ; renvoie {} (ou [] si default_list) si absent/corrompu."""
    if not path.exists():
        return [] if default_list else {}
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("IOCLookup : impossible de charger %s : %s", path, exc)
        return [] if default_list else {}


def _normalize_mb_entry(raw: Any) -> dict[str, Any]:
    """Normalise une entrée MalwareBazaar vers le format commun."""
    if not isinstance(raw, dict):
        return {"source": "abuse.ch/MalwareBazaar", "malware": "unknown"}
    return {
        "source": raw.get("source", "abuse.ch/MalwareBazaar"),
        "malware": raw.get("family") or raw.get("malware") or "unknown",
        "threat_type": raw.get("threat_type", "malware_sample"),
        "confidence": int(raw.get("confidence", 90) or 90),  # MB validé manuellement
        "first_seen": raw.get("first_seen", ""),
        "tags": raw.get("tags", []),
        "file_type": raw.get("file_type", ""),
    }


def _normalize_tf_entry(raw: Any) -> dict[str, Any]:
    """Normalise une entrée ThreatFox by_type vers le format commun."""
    if not isinstance(raw, dict):
        return {"source": "abuse.ch/ThreatFox", "malware": "unknown"}
    return {
        "source": raw.get("source", "abuse.ch/ThreatFox"),
        "malware": raw.get("malware", "unknown"),
        "threat_type": raw.get("threat_type", ""),
        "confidence": int(raw.get("confidence", 0) or 0),
        "first_seen": raw.get("first_seen", ""),
        "tags": raw.get("tags", []),
    }


def _merge_keep_best(
    target: dict[str, dict[str, Any]],
    key: str,
    new_entry: dict[str, Any],
) -> None:
    """Insère `new_entry` sous `key` en gardant la plus haute confidence."""
    existing = target.get(key)
    if existing is None:
        target[key] = new_entry
        return
    if int(new_entry.get("confidence", 0) or 0) > int(existing.get("confidence", 0) or 0):
        target[key] = new_entry


__all__ = [
    "IOCHit",
    "IOCLookup",
]
