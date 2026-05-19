"""Tests Phase 3.d : client ThreatFox.

HTTP mocké. Vérifie le parsing JSON, l'indexation par type d'IOC,
et l'écriture des artefacts dans `db/signatures/threatfox/`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _fake_response(payload: dict, status: int = 200):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload
    if status >= 400:
        from requests import HTTPError

        r.raise_for_status.side_effect = HTTPError(f"{status}")
    else:
        r.raise_for_status.return_value = None
    return r


SAMPLE_THREATFOX_PAYLOAD = {
    "query_status": "ok",
    "data": [
        {
            "id": "999001",
            "ioc": "evil-c2.example.com",
            "ioc_type": "domain",
            "threat_type": "c2_server",
            "malware_printable": "Cobalt Strike",
            "confidence_level": 90,
            "first_seen": "2026-05-19 00:00:00",
            "last_seen": "2026-05-19 12:00:00",
            "tags": ["c2", "redteam"],
        },
        {
            "id": "999002",
            "ioc": "1.2.3.4:8443",
            "ioc_type": "ip:port",
            "threat_type": "c2_server",
            "malware_printable": "Cobalt Strike",
            "confidence_level": 95,
            "first_seen": "2026-05-19 01:00:00",
            "last_seen": "2026-05-19 12:00:00",
            "tags": ["c2"],
        },
        {
            "id": "999003",
            "ioc": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            "ioc_type": "sha256_hash",
            "threat_type": "payload",
            "malware_printable": "Emotet",
            "confidence_level": 75,
            "first_seen": "2026-05-19 02:00:00",
            "tags": ["loader"],
        },
        {
            "id": "999004",
            "ioc": "http://drop.example.org/stage2.bin",
            "ioc_type": "url",
            "threat_type": "payload",
            "malware_printable": "TrickBot",
            "confidence_level": 80,
            "first_seen": "2026-05-19 03:00:00",
            "tags": ["banker"],
        },
    ],
}


# --------------------------------------------------------------------- #
# ThreatFoxClient.get_recent
# --------------------------------------------------------------------- #


def test_get_recent_parses_iocs():
    from biocybe.intel.threatfox import ThreatFoxClient

    session = MagicMock()
    session.post.return_value = _fake_response(SAMPLE_THREATFOX_PAYLOAD)
    client = ThreatFoxClient(auth_key="test-key", session=session)

    iocs = client.get_recent(days=1)
    assert len(iocs) == 4
    types = {i.ioc_type for i in iocs}
    assert {"domain", "ip:port", "sha256_hash", "url"} == types
    cobalt = [i for i in iocs if i.malware == "Cobalt Strike"]
    assert len(cobalt) == 2
    assert cobalt[0].confidence_level >= 90


def test_get_recent_sends_auth_header():
    from biocybe.intel.threatfox import ThreatFoxClient

    session = MagicMock()
    session.post.return_value = _fake_response(SAMPLE_THREATFOX_PAYLOAD)
    client = ThreatFoxClient(auth_key="my-token", session=session)
    client.get_recent(days=3)
    _args, kwargs = session.post.call_args
    assert kwargs["headers"]["Auth-Key"] == "my-token"
    assert kwargs["json"] == {"query": "get_iocs", "days": 3}


def test_get_recent_days_clamped():
    """ThreatFox supporte 1-7 jours. On clamp côté client."""
    from biocybe.intel.threatfox import ThreatFoxClient

    session = MagicMock()
    session.post.return_value = _fake_response(SAMPLE_THREATFOX_PAYLOAD)
    client = ThreatFoxClient(auth_key="k", session=session)
    client.get_recent(days=99)
    _args, kwargs = session.post.call_args
    assert kwargs["json"]["days"] == 7
    client.get_recent(days=0)
    _args, kwargs = session.post.call_args
    assert kwargs["json"]["days"] == 1


def test_auth_missing_raises():
    from biocybe.intel.threatfox import AbuseChAuthMissing, ThreatFoxClient

    client = ThreatFoxClient(auth_key=None)
    # Force pas d'env var
    import os

    if "ABUSECH_AUTH_KEY" in os.environ:
        del os.environ["ABUSECH_AUTH_KEY"]
    client.auth_key = None
    with pytest.raises(AbuseChAuthMissing):
        client.get_recent()


def test_api_error_status_raises():
    from biocybe.intel.threatfox import AbuseChAPIError, ThreatFoxClient

    session = MagicMock()
    session.post.return_value = _fake_response({"query_status": "no_result"})
    client = ThreatFoxClient(auth_key="k", session=session)
    with pytest.raises(AbuseChAPIError, match="no_result"):
        client.get_recent()


# --------------------------------------------------------------------- #
# update_threatfox_iocs : indexation par type
# --------------------------------------------------------------------- #


def test_update_writes_by_type_indexes(tmp_path):
    from biocybe.intel.threatfox import ThreatFoxClient, update_threatfox_iocs

    session = MagicMock()
    session.post.return_value = _fake_response(SAMPLE_THREATFOX_PAYLOAD)
    client = ThreatFoxClient(auth_key="k", session=session)
    stats = update_threatfox_iocs(db_path=tmp_path, client=client)

    assert stats["fetched"] == 4
    bt = stats["by_type_counts"]
    assert bt["domain"] == 1
    assert bt["ip"] == 1
    assert bt["hash"] == 1
    assert bt["url"] == 1

    # Vérifie les fichiers index
    by_type_dir = tmp_path / "threatfox" / "by_type"
    assert (by_type_dir / "domain.json").exists()
    assert (by_type_dir / "ip.json").exists()
    assert (by_type_dir / "hash.json").exists()
    assert (by_type_dir / "url.json").exists()

    # Vérifie le contenu de l'index hash
    hash_idx = json.loads((by_type_dir / "hash.json").read_text(encoding="utf-8"))
    sha = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    assert sha in hash_idx
    assert hash_idx[sha]["malware"] == "Emotet"
    assert hash_idx[sha]["source"] == "abuse.ch/ThreatFox"


def test_update_writes_raw_iocs_json(tmp_path):
    from biocybe.intel.threatfox import ThreatFoxClient, update_threatfox_iocs

    session = MagicMock()
    session.post.return_value = _fake_response(SAMPLE_THREATFOX_PAYLOAD)
    client = ThreatFoxClient(auth_key="k", session=session)
    update_threatfox_iocs(db_path=tmp_path, client=client)

    raw_file = tmp_path / "threatfox" / "iocs.json"
    assert raw_file.exists()
    data = json.loads(raw_file.read_text(encoding="utf-8"))
    assert len(data) == 4


# --------------------------------------------------------------------- #
# CLI : intel update --source threatfox
# --------------------------------------------------------------------- #


def test_cli_intel_update_threatfox_auth_missing(monkeypatch, tmp_path, capsys):
    from biocybe.cli import main

    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    exit_code = main(["intel", "update", "--source", "threatfox"])
    assert exit_code == 1  # any_error
    err = capsys.readouterr().err
    assert "auth manquante" in err.lower()
