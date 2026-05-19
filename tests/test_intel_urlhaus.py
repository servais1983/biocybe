"""Tests Phase 3.d : client URLhaus.

HTTP mocké. Vérifie le parsing du CSV URLhaus (avec header commenté),
l'extraction des hostnames, et l'écriture des artefacts JSON dans
`db/signatures/urlhaus/`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# CSV URLhaus typique. Le vrai feed commence par des lignes "# ..."
# qu'on doit ignorer. Le header "id,..." est dans la fonctionnalité
# csv.DictReader(fieldnames=...).
SAMPLE_URLHAUS_CSV = """\
# URLhaus public CSV feed
# Generated 2026-05-19
1234567,2026-05-19 08:00:00,http://evil.example.com/payload.exe,online,2026-05-19 08:00:00,malware_download,emotet,https://urlhaus.abuse.ch/url/1234567/,csirt_reporter
1234568,2026-05-19 08:01:00,http://bad.example.org/c2,offline,2026-05-19 07:30:00,c2_server,trickbot,https://urlhaus.abuse.ch/url/1234568/,abusech
1234569,2026-05-19 08:02:00,https://malicious.example.net/dropper.bin,online,,malware_download,unknown,https://urlhaus.abuse.ch/url/1234569/,researcher
"""


def _fake_response(status: int, content: bytes):
    r = MagicMock()
    r.status_code = status
    r.content = content
    if status >= 400:
        from requests import HTTPError

        r.raise_for_status.side_effect = HTTPError(f"{status}")
    else:
        r.raise_for_status.return_value = None
    return r


# --------------------------------------------------------------------- #
# URLhausClient.fetch_recent
# --------------------------------------------------------------------- #


def test_fetch_recent_parses_csv_skips_comments():
    from biocybe.intel.urlhaus import URLhausClient

    session = MagicMock()
    session.get.return_value = _fake_response(200, SAMPLE_URLHAUS_CSV.encode())
    client = URLhausClient(session=session)

    entries = client.fetch_recent()
    assert len(entries) == 3
    first = entries[0]
    assert first.url_id == "1234567"
    assert first.url == "http://evil.example.com/payload.exe"
    assert first.hostname == "evil.example.com"
    assert first.url_status == "online"
    assert first.threat == "malware_download"
    assert "emotet" in first.tags


def test_fetch_recent_extracts_hostname_correctly():
    from biocybe.intel.urlhaus import URLhausClient

    session = MagicMock()
    session.get.return_value = _fake_response(200, SAMPLE_URLHAUS_CSV.encode())
    client = URLhausClient(session=session)
    entries = client.fetch_recent()
    hostnames = [e.hostname for e in entries]
    assert "evil.example.com" in hostnames
    assert "bad.example.org" in hostnames
    assert "malicious.example.net" in hostnames


def test_fetch_recent_no_auth_required_by_default(monkeypatch):
    """URLhaus CSV recent est public — pas besoin d'Auth-Key."""
    from biocybe.intel.urlhaus import URLhausClient

    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    session = MagicMock()
    session.get.return_value = _fake_response(200, SAMPLE_URLHAUS_CSV.encode())
    client = URLhausClient(session=session)
    entries = client.fetch_recent()
    assert len(entries) == 3
    # Vérifie qu'on n'a pas envoyé d'Auth-Key
    _args, kwargs = session.get.call_args
    assert "Auth-Key" not in kwargs.get("headers", {})


def test_fetch_recent_sends_auth_key_when_set(monkeypatch):
    from biocybe.intel.urlhaus import URLhausClient

    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-auth-key-123")
    session = MagicMock()
    session.get.return_value = _fake_response(200, SAMPLE_URLHAUS_CSV.encode())
    client = URLhausClient(session=session)
    client.fetch_recent()
    _args, kwargs = session.get.call_args
    assert kwargs["headers"]["Auth-Key"] == "test-auth-key-123"


def test_fetch_recent_oversized_csv_refused():
    from biocybe.intel import urlhaus as urlhaus_mod

    session = MagicMock()
    big = b"a" * (urlhaus_mod.MAX_CSV_SIZE_BYTES + 1)
    session.get.return_value = _fake_response(200, big)
    client = urlhaus_mod.URLhausClient(session=session)
    with pytest.raises(ValueError, match="anormalement gros"):
        client.fetch_recent()


def test_fetch_recent_empty_csv_raises():
    from biocybe.intel.urlhaus import AbuseChAPIError, URLhausClient

    session = MagicMock()
    # Que des commentaires
    session.get.return_value = _fake_response(200, b"# header only\n# nothing else\n")
    client = URLhausClient(session=session)
    with pytest.raises(AbuseChAPIError, match="vide"):
        client.fetch_recent()


# --------------------------------------------------------------------- #
# update_urlhaus_iocs : écriture des artefacts
# --------------------------------------------------------------------- #


def test_update_writes_urls_and_hostnames_index(tmp_path):
    from biocybe.intel.urlhaus import URLhausClient, update_urlhaus_iocs

    session = MagicMock()
    session.get.return_value = _fake_response(200, SAMPLE_URLHAUS_CSV.encode())
    client = URLhausClient(session=session)
    stats = update_urlhaus_iocs(db_path=tmp_path, client=client)

    assert stats["fetched"] == 3
    assert stats["unique_hostnames"] == 3
    assert stats["online"] == 2

    urls_file = tmp_path / "urlhaus" / "urls.json"
    hosts_file = tmp_path / "urlhaus" / "hostnames.json"
    assert urls_file.exists()
    assert hosts_file.exists()

    urls = json.loads(urls_file.read_text(encoding="utf-8"))
    assert len(urls) == 3
    hosts = json.loads(hosts_file.read_text(encoding="utf-8"))
    assert "evil.example.com" in hosts
    assert hosts["evil.example.com"] == ["http://evil.example.com/payload.exe"]


def test_update_writes_last_update_timestamp(tmp_path):
    from biocybe.intel.urlhaus import URLhausClient, update_urlhaus_iocs

    session = MagicMock()
    session.get.return_value = _fake_response(200, SAMPLE_URLHAUS_CSV.encode())
    client = URLhausClient(session=session)
    update_urlhaus_iocs(db_path=tmp_path, client=client)

    last_update = tmp_path / "urlhaus" / "last_update.txt"
    assert last_update.exists()
    ts = last_update.read_text(encoding="utf-8").strip()
    assert ts.startswith("20")  # ISO format YYYY-...
