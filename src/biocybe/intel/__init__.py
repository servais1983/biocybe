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
    AbuseChAuthMissing,
    MalwareBazaarClient,
    update_signatures_from_malwarebazaar,
)

__all__ = [
    "AbuseChAuthMissing",
    "MalwareBazaarClient",
    "update_signatures_from_malwarebazaar",
]
