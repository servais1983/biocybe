"""Tests Phase 3.e : moteur de lookup IOC.

Couvre :
  - chargement multi-feeds (MB + URLhaus + ThreatFox)
  - lookup hash / hostname / url / ip
  - lookup_auto (heuristique de type)
  - fail-safe : fichiers absents → instance vide, pas de crash
  - merge keep-best : conflit de clé garde le plus confident
  - parent domain match (sous-domaine d'un hôte connu)
  - reload() idempotent
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _seed_db(db_path: Path) -> None:
    """Crée des fixtures minimales reproduisant la sortie des update_*."""
    # MalwareBazaar
    mb_dir = db_path / "hashes"
    mb_dir.mkdir(parents=True, exist_ok=True)
    (mb_dir / "signatures.json").write_text(
        json.dumps(
            {
                "a" * 64: {
                    "family": "TrickBot",
                    "source": "abuse.ch/MalwareBazaar",
                    "first_seen": "2026-05-01",
                    "tags": ["banker"],
                },
                "b" * 32: {
                    "family": "Emotet",
                    "source": "abuse.ch/MalwareBazaar",
                },
            }
        ),
        encoding="utf-8",
    )

    # URLhaus
    uh_dir = db_path / "urlhaus"
    uh_dir.mkdir(parents=True, exist_ok=True)
    (uh_dir / "hostnames.json").write_text(
        json.dumps({"evil.example.org": ["http://evil.example.org/x.exe"]}),
        encoding="utf-8",
    )
    (uh_dir / "urls.json").write_text(
        json.dumps(
            [
                {
                    "url_id": "u1",
                    "url": "http://evil.example.org/payload.exe",
                    "hostname": "evil.example.org",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": ["loader"],
                    "date_added": "2026-05-01 10:00:00",
                }
            ]
        ),
        encoding="utf-8",
    )

    # ThreatFox
    tf_dir = db_path / "threatfox" / "by_type"
    tf_dir.mkdir(parents=True, exist_ok=True)
    (tf_dir / "hash.json").write_text(
        json.dumps(
            {
                "c" * 64: {
                    "malware": "Cobalt Strike",
                    "threat_type": "payload",
                    "confidence": 100,
                    "source": "abuse.ch/ThreatFox",
                    "first_seen": "2026-05-02",
                    "tags": [],
                }
            }
        ),
        encoding="utf-8",
    )
    (tf_dir / "domain.json").write_text(
        json.dumps(
            {
                "bad-c2.test": {
                    "malware": "Cobalt Strike",
                    "threat_type": "c2_server",
                    "confidence": 90,
                    "source": "abuse.ch/ThreatFox",
                }
            }
        ),
        encoding="utf-8",
    )
    (tf_dir / "ip.json").write_text(
        json.dumps(
            {
                "1.2.3.4:443": {
                    "malware": "AsyncRAT",
                    "threat_type": "c2_server",
                    "confidence": 75,
                    "source": "abuse.ch/ThreatFox",
                }
            }
        ),
        encoding="utf-8",
    )


def test_loads_all_feeds(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    _seed_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)

    stats = lookup.stats()
    assert stats["hashes"] == 3  # 2 MB + 1 TF
    # URLhaus + ThreatFox domain
    assert stats["hostnames"] == 2
    assert stats["urls"] == 1
    # IPs: '1.2.3.4:443' + '1.2.3.4' (indexé en double pour fallback)
    assert stats["ips"] == 2


def test_lookup_hash(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    _seed_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)

    hit = lookup.lookup_hash("a" * 64)
    assert hit is not None
    assert hit.ioc_type == "hash"
    assert hit.malware == "TrickBot"
    assert "MalwareBazaar" in hit.source

    # Case-insensitive
    hit2 = lookup.lookup_hash(("a" * 64).upper())
    assert hit2 is not None
    assert hit2.malware == "TrickBot"

    assert lookup.lookup_hash("nope") is None
    assert lookup.lookup_hash("") is None


def test_lookup_hostname_exact_and_parent(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    _seed_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)

    # Exact match
    hit = lookup.lookup_hostname("evil.example.org")
    assert hit is not None
    assert hit.ioc_type == "hostname"
    assert "URLhaus" in hit.source

    # Sous-domaine d'un domaine connu malveillant
    hit = lookup.lookup_hostname("foo.bar.bad-c2.test")
    assert hit is not None
    assert hit.metadata["matched_parent_domain"] == "bad-c2.test"

    # Pas de match pour TLD bare
    assert lookup.lookup_hostname("test") is None


def test_lookup_url_exact_and_via_host(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    _seed_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)

    # URL exacte
    hit = lookup.lookup_url("http://evil.example.org/payload.exe")
    assert hit is not None
    assert hit.ioc_type == "url"

    # URL non indexée, mais hostname connu → match via hostname
    hit = lookup.lookup_url("http://evil.example.org/other-path")
    assert hit is not None
    assert hit.metadata["matched_via"] == "hostname_of_url"


def test_lookup_ip_with_and_without_port(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    _seed_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)

    assert lookup.lookup_ip("1.2.3.4:443") is not None
    assert lookup.lookup_ip("1.2.3.4") is not None  # fallback sans port
    assert lookup.lookup_ip("9.9.9.9") is None


def test_lookup_auto_detects_type(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    _seed_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)

    # Hash sha256
    hit = lookup.lookup_auto("a" * 64)
    assert hit is not None and hit.ioc_type == "hash"

    # URL
    hit = lookup.lookup_auto("http://evil.example.org/payload.exe")
    assert hit is not None and hit.ioc_type == "url"

    # IP
    hit = lookup.lookup_auto("1.2.3.4")
    assert hit is not None and hit.ioc_type == "ip"

    # Hostname
    hit = lookup.lookup_auto("evil.example.org")
    assert hit is not None and hit.ioc_type == "hostname"


def test_empty_db_no_crash(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    # Aucun fichier dans tmp_path — instance vide
    lookup = IOCLookup.from_db(tmp_path)
    assert lookup.total == 0
    assert lookup.lookup_hash("a" * 64) is None
    assert lookup.lookup_hostname("anything.tld") is None
    assert lookup.lookup_url("http://x.test/") is None
    assert lookup.lookup_ip("1.1.1.1") is None


def test_corrupted_json_is_safe(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    (tmp_path / "hashes").mkdir()
    (tmp_path / "hashes" / "signatures.json").write_text("{ not json", encoding="utf-8")

    # Ne doit pas crasher
    lookup = IOCLookup.from_db(tmp_path)
    assert lookup.stats()["hashes"] == 0


def test_reload_is_idempotent(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    _seed_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)
    before = lookup.total
    lookup.reload()
    assert lookup.total == before


def test_merge_keep_best_keeps_higher_confidence(tmp_path):
    """Si un hash apparaît dans MB ET ThreatFox, on garde celui avec
    la plus haute confidence."""
    from biocybe.intel.ioc_lookup import IOCLookup

    # MB : confidence implicite 90
    mb_dir = tmp_path / "hashes"
    mb_dir.mkdir(parents=True)
    (mb_dir / "signatures.json").write_text(
        json.dumps({"a" * 64: {"family": "MB-Family", "source": "abuse.ch/MalwareBazaar"}}),
        encoding="utf-8",
    )
    # ThreatFox : confidence 100 → doit l'emporter
    tf_dir = tmp_path / "threatfox" / "by_type"
    tf_dir.mkdir(parents=True)
    (tf_dir / "hash.json").write_text(
        json.dumps(
            {
                "a" * 64: {
                    "malware": "TF-Family",
                    "confidence": 100,
                    "source": "abuse.ch/ThreatFox",
                }
            }
        ),
        encoding="utf-8",
    )

    lookup = IOCLookup.from_db(tmp_path)
    hit = lookup.lookup_hash("a" * 64)
    assert hit is not None
    assert hit.malware == "TF-Family"
    assert hit.confidence == 100
