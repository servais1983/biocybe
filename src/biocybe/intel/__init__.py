"""Threat Intelligence pour BioCybe.

Connecteurs vers des sources de signatures et d'indicateurs publics
gratuits, en priorité abuse.ch (MalwareBazaar, URLhaus, ThreatFox)
qui fournissent des milliers d'IOCs par jour, qualité validée par
la communauté CSIRT mondiale.

Module utilisable via :
  - CLI : `biocybe intel update [--source malwarebazaar] [...]`
  - Programmatique : `from biocybe.intel import update_signatures`
"""

from .abusech import (
    AbuseChAPIError,
    AbuseChAuthMissing,
    MalwareBazaarClient,
    update_signatures_from_malwarebazaar,
)
from .rules import (
    KNOWN_SOURCES,
    DownloadResult,
    VerifyResult,
    YaraRuleSource,
    download_source,
    list_sources,
    verify_source,
)
from .threatfox import (
    ThreatFoxClient,
    ThreatFoxIOC,
    update_threatfox_iocs,
)
from .urlhaus import (
    URLhausClient,
    URLHausEntry,
    update_urlhaus_iocs,
)

__all__ = [
    "KNOWN_SOURCES",
    "AbuseChAPIError",
    "AbuseChAuthMissing",
    "DownloadResult",
    "MalwareBazaarClient",
    "ThreatFoxClient",
    "ThreatFoxIOC",
    "URLHausEntry",
    "URLhausClient",
    "VerifyResult",
    "YaraRuleSource",
    "download_source",
    "list_sources",
    "update_signatures_from_malwarebazaar",
    "update_threatfox_iocs",
    "update_urlhaus_iocs",
    "verify_source",
]
