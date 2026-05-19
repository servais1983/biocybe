"""Sentinelle réseau — détecte les IOCs réseau dans des fichiers texte/binaires.

Phase 3.e : exploite les feeds URLhaus + ThreatFox (Phase 3.d) pour
détecter quand un fichier contient des indicateurs réseau connus
malveillants (URLs C2, domaines de phishing, IPs de botnet, hashes
référencés…).

Pourquoi c'est utile concrètement :
  - Un script PowerShell ou .vbs téléchargé contient l'URL du payload —
    on la détecte AVANT que le fichier soit exécuté.
  - Un dump mémoire / pcap converti / log contient l'IP du C2 — on la
    flagge immédiatement.
  - Un fichier de config volé contient des hashes ou domaines référencés
    dans ThreatFox — alerte de threat hunting.

Complémentaire de BCell (qui détecte les patterns YARA / signatures
hash du fichier lui-même). NetworkSentinel détecte ce dont le fichier
**parle**, pas ce qu'il **est**.

Design :
  - Pas de DNS lookup, pas de résolution active. Tout est statique :
    extraction par regex, match en mémoire contre IOCLookup.
  - Cap de lecture (50 MB par défaut) pour éviter OOM sur gros fichiers.
  - Décodage best-effort UTF-8 puis fallback Latin-1, pour traiter les
    fichiers binaires comme un flux d'octets sans crash.
  - Déduplication des hits par (type, value) — on signale une fois
    chaque IOC unique trouvé, même s'il apparaît plusieurs fois.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from .intel.ioc_lookup import IOCHit, IOCLookup

logger = logging.getLogger("biocybe.network_sentinel")

# Plafond de lecture par fichier : protection mémoire. Au-delà on tronque.
# 50 MB couvre largement les scripts, configs, logs, executables courants.
DEFAULT_MAX_BYTES = 50 * 1024 * 1024


# ----------------------------------------------------------------------
# Regex d'extraction d'IOCs
# ----------------------------------------------------------------------

# Toutes les regex utilisent re.ASCII : les IOCs abuse.ch sont en ASCII,
# et ce flag garantit que `\b` considère uniquement les caractères ASCII
# comme "word", critique pour parser correctement le contenu binaire.
# Sans ça, `\xfe`/`\xff` (latin-1 = lettres accentuées) sont word chars
# et `\b10.20.30.40` ne matche pas si précédé d'un octet binaire haut.

# URL : capture http(s)/ftp avec hostname, port optionnel, path optionnel.
# Délibérément permissif côté path pour matcher les URLs avec query string.
# On s'arrête sur whitespace ou caractères de fin de chaîne courants.
_URL_RE = re.compile(
    r"""\b(?:https?|ftp)://      # schéma
        [^\s<>"'`(){}\[\]]+      # tout ce qui n'est pas un délimiteur
    """,
    re.VERBOSE | re.IGNORECASE | re.ASCII,
)

# IPv4 avec port optionnel. La validation finale est faite par ipaddress
# côté lookup, donc on est laxistes ici (faux positifs filtrés en aval).
_IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b",
    re.ASCII,
)

# Hostnames "FQDN-likes" : labels alphanum séparés par points, TLD ≥ 2 chars.
# Évite de matcher les nombres décimaux et les versions logicielles.
_HOSTNAME_RE = re.compile(
    r"""\b
        (?=.{4,253}\b)                            # taille totale 4..253
        (?!\d+\.\d+\.\d+\.\d+\b)                  # pas une IPv4
        [a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?      # premier label
        (?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,}  # labels intermédiaires
        \.[a-z]{2,24}                             # TLD lettres uniquement
        \b
    """,
    re.VERBOSE | re.IGNORECASE | re.ASCII,
)

# Hashes : MD5 (32), SHA1 (40), SHA256 (64) — séquences hex isolées.
_HASH_RE = re.compile(
    r"\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b",
    re.IGNORECASE | re.ASCII,
)

# TLDs / domaines à ignorer (anti-faux-positifs courants dans le code source,
# documentation, manifest, etc.) — ces hostnames seront extraits mais NE
# seront PAS interrogés contre le lookup (économie d'appels + clarté).
_HOSTNAME_DENYLIST = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        "localhost.localdomain",
        "github.com",
        "raw.githubusercontent.com",
        "github.io",
        "gitlab.com",
        "bitbucket.org",
        "stackoverflow.com",
        "python.org",
        "pypi.org",
        "anaconda.org",
        "docker.com",
        "docker.io",
        "ubuntu.com",
        "debian.org",
        "kernel.org",
        "google.com",
        "googleapis.com",
        "microsoft.com",
        "windows.com",
        "apple.com",
        "mozilla.org",
        "w3.org",
        "schemas.xmlsoap.org",
        "schemas.microsoft.com",
        "w3schools.com",
        "wikipedia.org",
        "cloudflare.com",
        "amazonaws.com",
    }
)


@dataclass
class NetworkScanResult:
    """Résultat d'un scan réseau sur un fichier."""

    path: Path
    iocs_found: list[IOCHit] = field(default_factory=list)
    extracted_counts: dict[str, int] = field(default_factory=dict)
    bytes_scanned: int = 0
    truncated: bool = False
    error: str | None = None

    @property
    def is_malicious(self) -> bool:
        return bool(self.iocs_found)

    @property
    def max_confidence(self) -> int:
        if not self.iocs_found:
            return 0
        return max(h.confidence for h in self.iocs_found)

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "iocs_found": [h.to_dict() for h in self.iocs_found],
            "extracted_counts": self.extracted_counts,
            "bytes_scanned": self.bytes_scanned,
            "truncated": self.truncated,
            "error": self.error,
        }


class NetworkSentinel:
    """Détecteur d'IOCs réseau dans le contenu des fichiers.

    Pattern d'usage :
        sentinel = NetworkSentinel.from_db("db/signatures")
        result = sentinel.scan_file("/path/to/file")
        if result.is_malicious:
            for hit in result.iocs_found:
                logger.warning("IOC %s : %s (%s)", hit.ioc_type, hit.value, hit.source)
    """

    def __init__(
        self,
        lookup: IOCLookup,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        hostname_denylist: frozenset[str] = _HOSTNAME_DENYLIST,
    ):
        self.lookup = lookup
        self.max_bytes = int(max_bytes)
        self.hostname_denylist = hostname_denylist

    @classmethod
    def from_db(
        cls, db_path: str | Path = "db/signatures", **kwargs
    ) -> NetworkSentinel:
        return cls(IOCLookup.from_db(db_path), **kwargs)

    # ------------------------------------------------------------------
    # Scan fichier
    # ------------------------------------------------------------------

    def scan_file(self, path: str | Path) -> NetworkScanResult:
        """Scanne un fichier à la recherche d'IOCs réseau connus."""
        p = Path(path)
        result = NetworkScanResult(path=p)

        if not p.is_file():
            result.error = f"not_a_file: {p}"
            return result

        # Si le lookup est vide (pas de feeds importés), aucun match
        # possible — on évite la lecture du fichier pour gagner du temps.
        if self.lookup.total == 0:
            result.error = "ioc_lookup_empty"
            return result

        try:
            with p.open("rb") as fh:
                blob = fh.read(self.max_bytes + 1)
        except OSError as exc:
            result.error = f"read_error: {exc}"
            return result

        if len(blob) > self.max_bytes:
            result.truncated = True
            blob = blob[: self.max_bytes]
        result.bytes_scanned = len(blob)

        # Décodage best-effort. Latin-1 mappe tout octet vers un code
        # point unique → garanti sans IndexError même sur binaires.
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            text = blob.decode("latin-1", errors="replace")

        return self.scan_text(text, result)

    def scan_text(
        self, text: str, result: NetworkScanResult | None = None
    ) -> NetworkScanResult:
        """Scanne un blob texte. Réutilisable indépendamment de `scan_file`."""
        if result is None:
            result = NetworkScanResult(path=Path("<text>"))

        hits: dict[tuple[str, str], IOCHit] = {}

        # 1) URLs complètes (priorité — on évite de dédupliquer leur
        # hostname si on a déjà flaggé l'URL complète). Les URLs dont
        # le hostname est en denylist ne sont PAS interrogées : c'est
        # le principe du denylist (github.com, googleapis.com, etc.).
        from urllib.parse import urlparse as _urlparse

        urls = set(_URL_RE.findall(text))
        result.extracted_counts["urls"] = len(urls)
        urls_matched_hosts: set[str] = set()
        for url in urls:
            try:
                host = (_urlparse(url).hostname or "").lower()
            except Exception:
                host = ""
            if host and host in self.hostname_denylist:
                continue
            hit = self.lookup.lookup_url(url)
            if hit:
                hits[(hit.ioc_type, hit.value)] = hit
                # Mémorise le hostname extrait pour éviter doublon en phase 2
                if hit.metadata.get("hostname"):
                    urls_matched_hosts.add(str(hit.metadata["hostname"]).lower())

        # 2) IPv4 (avec ou sans port)
        ips = set(_IPV4_RE.findall(text))
        result.extracted_counts["ips"] = len(ips)
        for ip in ips:
            hit = self.lookup.lookup_ip(ip)
            if hit:
                hits[(hit.ioc_type, hit.value)] = hit

        # 3) Hashes
        hashes = set(m.lower() for m in _HASH_RE.findall(text))
        result.extracted_counts["hashes"] = len(hashes)
        for h in hashes:
            hit = self.lookup.lookup_hash(h)
            if hit:
                hits[(hit.ioc_type, hit.value)] = hit

        # 4) Hostnames (denylist appliqué)
        hostnames = set()
        for raw_host in _HOSTNAME_RE.findall(text):
            host = raw_host.lower().rstrip(".")
            if host in self.hostname_denylist:
                continue
            if host in urls_matched_hosts:
                # Déjà couvert par une URL — pas de doublon
                continue
            hostnames.add(host)
        result.extracted_counts["hostnames"] = len(hostnames)
        for host in hostnames:
            hit = self.lookup.lookup_hostname(host)
            if hit:
                hits[(hit.ioc_type, hit.value)] = hit

        result.iocs_found = sorted(
            hits.values(),
            key=lambda h: (-h.confidence, h.ioc_type, h.value),
        )
        return result


__all__ = [
    "DEFAULT_MAX_BYTES",
    "NetworkScanResult",
    "NetworkSentinel",
]
