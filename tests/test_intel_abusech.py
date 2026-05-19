"""Tests Phase 2.2.b : client MalwareBazaar abuse.ch.

Mocke entièrement l'API (pas d'appel réseau) :
  - réponses correctes → parsing + dump dans signatures.json
  - 401 sans clé → AbuseChAuthMissing claire
  - query_status != 'ok' → AbuseChAPIError
  - update idempotent : seconde passe n'ajoute rien si rien n'a changé
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
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    if status >= 400:
        from requests import HTTPError

        resp.raise_for_status.side_effect = HTTPError(f"{status}")
    else:
        resp.raise_for_status.return_value = None
    return resp


SAMPLE_API_PAYLOAD = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": "a" * 64,
            "sha1_hash": "b" * 40,
            "md5_hash": "c" * 32,
            "signature": "TrickBot",
            "file_type": "exe",
            "file_name": "trick.exe",
            "file_size": 123456,
            "first_seen": "2026-05-01 10:00:00",
            "tags": ["banker", "trojan"],
        },
        {
            "sha256_hash": "d" * 64,
            "sha1_hash": None,
            "md5_hash": "e" * 32,
            "signature": "Emotet",
            "file_type": "exe",
            "file_name": "emo.exe",
            "file_size": 80000,
            "first_seen": "2026-05-02 09:30:00",
            "tags": ["loader"],
        },
    ],
}


def test_get_recent_parses_payload(monkeypatch):
    from biocybe.intel.abusech import MalwareBazaarClient

    session = MagicMock()
    session.post.return_value = _fake_response(SAMPLE_API_PAYLOAD)
    client = MalwareBazaarClient(auth_key="test-key", session=session)

    samples = client.get_recent(selector="100")
    assert len(samples) == 2
    assert samples[0].signature == "TrickBot"
    assert samples[0].sha256 == "a" * 64
    assert samples[0].md5 == "c" * 32
    assert samples[1].signature == "Emotet"
    assert samples[1].sha1 is None

    # Vérifie l'appel : Auth-Key passé en header
    _args, kwargs = session.post.call_args
    assert kwargs["headers"]["Auth-Key"] == "test-key"
    assert kwargs["headers"]["User-Agent"].startswith("BioCybe/")
    assert kwargs["data"] == {"query": "get_recent", "selector": "100"}


def test_auth_missing_raises_clear_error(monkeypatch):
    from biocybe.intel.abusech import AbuseChAuthMissing, MalwareBazaarClient

    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    client = MalwareBazaarClient()
    with pytest.raises(AbuseChAuthMissing, match=r"auth\.abuse\.ch"):
        client.get_recent()


def test_api_error_status_raises(monkeypatch):
    from biocybe.intel.abusech import AbuseChAPIError, MalwareBazaarClient

    session = MagicMock()
    session.post.return_value = _fake_response({"query_status": "limit_exceeded"})
    client = MalwareBazaarClient(auth_key="test-key", session=session)

    with pytest.raises(AbuseChAPIError, match="limit_exceeded"):
        client.get_recent()


def test_update_signatures_writes_db(tmp_path):
    from biocybe.intel.abusech import MalwareBazaarClient, update_signatures_from_malwarebazaar

    session = MagicMock()
    session.post.return_value = _fake_response(SAMPLE_API_PAYLOAD)
    client = MalwareBazaarClient(auth_key="test-key", session=session)

    stats = update_signatures_from_malwarebazaar(db_path=tmp_path, client=client)

    assert stats["fetched"] == 2
    # 2 samples : (sha256+sha1+md5) + (sha256+md5) = 5 hashes uniques
    assert stats["added"] == 5
    assert stats["updated"] == 0
    assert stats["total"] == 5

    sig_file = tmp_path / "hashes" / "signatures.json"
    assert sig_file.exists()
    data = json.loads(sig_file.read_text(encoding="utf-8"))
    assert ("a" * 64) in data
    assert data["a" * 64]["family"] == "TrickBot"
    assert data["a" * 64]["source"] == "abuse.ch/MalwareBazaar"


def test_update_signatures_is_idempotent(tmp_path):
    from biocybe.intel.abusech import MalwareBazaarClient, update_signatures_from_malwarebazaar

    session = MagicMock()
    session.post.return_value = _fake_response(SAMPLE_API_PAYLOAD)
    client = MalwareBazaarClient(auth_key="test-key", session=session)

    update_signatures_from_malwarebazaar(db_path=tmp_path, client=client)
    # 2e passe avec exactement le même payload
    session.post.return_value = _fake_response(SAMPLE_API_PAYLOAD)
    stats2 = update_signatures_from_malwarebazaar(db_path=tmp_path, client=client)

    assert stats2["added"] == 0  # déjà connus
    assert stats2["updated"] == 0
    assert stats2["total"] == 5


def test_update_signatures_detects_changes(tmp_path):
    from biocybe.intel.abusech import MalwareBazaarClient, update_signatures_from_malwarebazaar

    session = MagicMock()
    session.post.return_value = _fake_response(SAMPLE_API_PAYLOAD)
    client = MalwareBazaarClient(auth_key="test-key", session=session)
    update_signatures_from_malwarebazaar(db_path=tmp_path, client=client)

    # Le même hash mais reclassé dans une autre famille
    modified = {
        "query_status": "ok",
        "data": [
            {**SAMPLE_API_PAYLOAD["data"][0], "signature": "TrickBot-v2"},
        ],
    }
    session.post.return_value = _fake_response(modified)
    stats = update_signatures_from_malwarebazaar(db_path=tmp_path, client=client)

    # 3 hashes du sample modifié sont updatés (sha256+sha1+md5)
    assert stats["updated"] == 3
    assert stats["added"] == 0


def test_cli_intel_update_auth_missing(monkeypatch, tmp_path, capsys):
    from biocybe.cli import main

    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    exit_code = main(["intel", "update"])
    # Phase 3.d : sémantique multi-source — exit 1 si AU MOINS UNE
    # source en erreur (peu importe le code spécifique).
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "auth manquante" in err.lower()
