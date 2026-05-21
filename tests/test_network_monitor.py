"""Tests Phase 3.f : NetworkMonitor + HostsBlocker.

Mocke entièrement psutil.net_connections — pas d'appel système réseau
réel. Couvre :
  - snapshot avec match IOC
  - snapshot avec connexions bénignes
  - dédup / rate-limit anti-storm
  - filtres IP locales (loopback, link-local)
  - HostsBlocker : apply / clear / list / status, validation hostnames,
    écriture atomique, backup, idempotent
  - CLI : netmon scan, netmon block status
"""

from __future__ import annotations

import json
import sys
from collections import namedtuple
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# Fake psutil sconn pour mocker net_connections()
FakeAddr = namedtuple("FakeAddr", ["ip", "port"])
FakeConn = namedtuple("FakeConn", ["laddr", "raddr", "status", "pid"])


def _fake_conn(remote_ip, remote_port, pid=1234, status="ESTABLISHED"):
    return FakeConn(
        laddr=FakeAddr("192.168.1.10", 50000),
        raddr=FakeAddr(remote_ip, remote_port),
        status=status,
        pid=pid,
    )


def _seed_lookup_db(db_path: Path):
    """Index ThreatFox IP + URLhaus hostname."""
    tf = db_path / "threatfox" / "by_type"
    tf.mkdir(parents=True, exist_ok=True)
    (tf / "ip.json").write_text(
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
    uh = db_path / "urlhaus"
    uh.mkdir(parents=True, exist_ok=True)
    (uh / "hostnames.json").write_text(
        json.dumps({"bad-c2.test": ["http://bad-c2.test/x"]}),
        encoding="utf-8",
    )


# ----------------------------------------------------------------------
# NetworkMonitor
# ----------------------------------------------------------------------


def test_snapshot_detects_malicious_ip(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup
    from biocybe.network_monitor import NetworkMonitor

    _seed_lookup_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)
    monitor = NetworkMonitor(lookup)

    fake_conns = [
        _fake_conn("10.20.30.40", 8080),  # IOC connu
        _fake_conn("8.8.8.8", 443),  # bénin
    ]
    with patch("psutil.net_connections", return_value=fake_conns):
        with patch(
            "biocybe.network_monitor._safe_process_info",
            return_value=("powershell.exe", "C:\\Windows\\..."),
        ):
            records = monitor.snapshot()

    assert len(records) == 2
    malicious = [r for r in records if r.is_malicious]
    assert len(malicious) == 1
    assert malicious[0].remote_ip == "10.20.30.40"
    assert malicious[0].hit.malware == "Cobalt Strike"
    assert malicious[0].process_name == "powershell.exe"


def test_snapshot_skips_loopback_and_link_local(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup
    from biocybe.network_monitor import NetworkMonitor

    _seed_lookup_db(tmp_path)
    monitor = NetworkMonitor(IOCLookup.from_db(tmp_path))

    fake_conns = [
        _fake_conn("127.0.0.1", 80),
        _fake_conn("169.254.1.1", 80),  # link-local
        _fake_conn("224.0.0.1", 80),  # multicast
        _fake_conn("8.8.8.8", 53),  # public, bénin
    ]
    with patch("psutil.net_connections", return_value=fake_conns):
        with patch(
            "biocybe.network_monitor._safe_process_info",
            return_value=("python", "/usr/bin/python"),
        ):
            records = monitor.snapshot()

    # Seul 8.8.8.8 reste — les 3 autres sont locales et filtrées
    assert len(records) == 1
    assert records[0].remote_ip == "8.8.8.8"


def test_snapshot_ignores_listen_state(tmp_path):
    """Les sockets LISTEN n'ont pas de raddr et doivent être ignorés."""
    from biocybe.intel.ioc_lookup import IOCLookup
    from biocybe.network_monitor import NetworkMonitor

    _seed_lookup_db(tmp_path)
    monitor = NetworkMonitor(IOCLookup.from_db(tmp_path))

    listen_conn = FakeConn(
        laddr=FakeAddr("0.0.0.0", 8080),
        raddr=None,
        status="LISTEN",
        pid=1,
    )
    with patch("psutil.net_connections", return_value=[listen_conn]):
        records = monitor.snapshot()

    assert records == []


def test_rate_limit_anti_storm(tmp_path):
    """Si la même connexion IOC apparaît 100x, on n'alerte que N fois/heure."""
    from biocybe.intel.ioc_lookup import IOCLookup
    from biocybe.network_monitor import ConnectionRecord, NetworkMonitor

    _seed_lookup_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)
    monitor = NetworkMonitor(lookup, max_alerts_per_key_per_hour=3)

    hit = lookup.lookup_ip("10.20.30.40:8080")
    assert hit is not None
    record = ConnectionRecord(
        pid=1234,
        process_name="x",
        process_exe="",
        laddr="",
        raddr="10.20.30.40:8080",
        remote_ip="10.20.30.40",
        remote_port=8080,
        status="ESTABLISHED",
        hit=hit,
    )

    # 3 premières alertes passent, suivantes bloquées
    assert monitor._should_alert(record) is True
    assert monitor._should_alert(record) is True
    assert monitor._should_alert(record) is True
    assert monitor._should_alert(record) is False
    assert monitor._should_alert(record) is False


def test_on_match_callback_invoked(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup
    from biocybe.network_monitor import NetworkMonitor

    _seed_lookup_db(tmp_path)
    lookup = IOCLookup.from_db(tmp_path)

    captured = []
    monitor = NetworkMonitor(lookup, interval=0.5, on_match=lambda r: captured.append(r))

    fake_conns = [_fake_conn("10.20.30.40", 8080)]
    with patch("psutil.net_connections", return_value=fake_conns):
        with patch(
            "biocybe.network_monitor._safe_process_info",
            return_value=("evil.exe", ""),
        ):
            monitor.start()
            # Wait up to 2s for the loop to fire at least once
            import time as _time

            for _ in range(20):
                if captured:
                    break
                _time.sleep(0.1)
            monitor.stop()

    assert len(captured) >= 1
    assert captured[0].hit.malware == "Cobalt Strike"


def test_access_denied_does_not_crash(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup
    from biocybe.network_monitor import NetworkMonitor

    _seed_lookup_db(tmp_path)
    monitor = NetworkMonitor(IOCLookup.from_db(tmp_path))

    import psutil as _psutil

    with patch("psutil.net_connections", side_effect=_psutil.AccessDenied("nope")):
        records = monitor.snapshot()

    assert records == []


# ----------------------------------------------------------------------
# HostsBlocker
# ----------------------------------------------------------------------


def test_hosts_blocker_apply_writes_section(tmp_path):
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    blocker = HostsBlocker(hosts)
    stats = blocker.apply(["evil1.test", "bad-c2.test"])

    content = hosts.read_text(encoding="utf-8")
    assert "127.0.0.1 localhost" in content  # contenu préservé
    assert "BIOCYBE-IOC-BLOCK START" in content
    assert "BIOCYBE-IOC-BLOCK END" in content
    assert "0.0.0.0\tevil1.test" in content
    assert "0.0.0.0\tbad-c2.test" in content
    assert stats.blocked == ["evil1.test", "bad-c2.test"]


def test_hosts_blocker_clear_removes_section(tmp_path):
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    blocker = HostsBlocker(hosts)
    blocker.apply(["evil1.test", "evil2.test"])

    removed = blocker.clear()
    assert removed == 2
    content = hosts.read_text(encoding="utf-8")
    assert "BIOCYBE" not in content
    assert "evil1.test" not in content
    assert "127.0.0.1 localhost" in content


def test_hosts_blocker_idempotent(tmp_path):
    """Apply x2 avec mêmes données → état identique."""
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    blocker = HostsBlocker(hosts)

    blocker.apply(["a.test", "b.test"])
    first = hosts.read_text(encoding="utf-8")
    blocker.apply(["a.test", "b.test"])
    second = hosts.read_text(encoding="utf-8")

    # Le bloc régénéré contient un timestamp, donc les fichiers peuvent
    # différer sur cette ligne. Mais les entrées sinkhole doivent être
    # identiques et n'apparaitre qu'une seule fois.
    assert first.count("a.test") == 1
    assert second.count("a.test") == 1
    assert second.count("BIOCYBE-IOC-BLOCK START") == 1


def test_hosts_blocker_rejects_invalid(tmp_path):
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    hosts.write_text("", encoding="utf-8")
    blocker = HostsBlocker(hosts)

    stats = blocker.apply(
        [
            "good.test",
            "localhost",  # refusé
            "no-dot",  # refusé (single label)
            "bad host with spaces.test",  # refusé
            "*.wildcard.test",  # refusé (wildcard)
            "evil\nnewline.test",  # refusé (injection)
            ".starts-with-dot.test",  # refusé
            "valid-host.test",
        ]
    )
    assert "good.test" in stats.blocked
    assert "valid-host.test" in stats.blocked
    assert len(stats.skipped_invalid) >= 5
    content = hosts.read_text(encoding="utf-8")
    assert "localhost" not in [
        line.split()[-1] for line in content.splitlines() if line.startswith("0.0.0.0")
    ]


def test_hosts_blocker_backup_created(tmp_path):
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    original = "127.0.0.1 localhost\n# my custom entry\n"
    hosts.write_text(original, encoding="utf-8")
    blocker = HostsBlocker(hosts)
    blocker.apply(["evil.test"])

    assert blocker.backup_path.exists()
    assert blocker.backup_path.read_text(encoding="utf-8") == original


def test_hosts_blocker_list_blocked(tmp_path):
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    hosts.write_text("", encoding="utf-8")
    blocker = HostsBlocker(hosts)
    blocker.apply(["a.test", "b.test", "c.test"])

    listed = blocker.list_blocked()
    assert sorted(listed) == ["a.test", "b.test", "c.test"]


def test_hosts_blocker_status(tmp_path):
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    hosts.write_text("", encoding="utf-8")
    blocker = HostsBlocker(hosts)
    blocker.apply(["a.test", "b.test"])

    status = blocker.status()
    assert status["blocked_count"] == 2
    assert status["exists"] is True
    assert status["writable"] is True
    assert "a.test" in status["blocked_sample"]


def test_hosts_blocker_apply_empty_clears_section(tmp_path):
    """apply([]) après un apply non-vide retire la section."""
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    blocker = HostsBlocker(hosts)
    blocker.apply(["evil.test"])
    blocker.apply([])

    content = hosts.read_text(encoding="utf-8")
    assert "BIOCYBE" not in content
    assert "evil.test" not in content
    assert "127.0.0.1 localhost" in content


def test_hosts_blocker_preserves_existing_content(tmp_path):
    """Une section pré-existante non-BioCybe doit être conservée."""
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    pre = "127.0.0.1 localhost\n192.168.1.5 myserver.local\n# custom comment\n"
    hosts.write_text(pre, encoding="utf-8")
    blocker = HostsBlocker(hosts)
    blocker.apply(["evil.test"])

    content = hosts.read_text(encoding="utf-8")
    assert "myserver.local" in content
    assert "# custom comment" in content
    assert "evil.test" in content


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def test_cli_netmon_scan_no_iocs_loaded(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    monkeypatch.chdir(tmp_path)
    exit_code = main(["netmon", "scan"])
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "intel update" in err


def test_cli_netmon_scan_detects_match(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    _seed_lookup_db(tmp_path / "db" / "signatures")
    monkeypatch.chdir(tmp_path)

    fake_conns = [_fake_conn("10.20.30.40", 8080)]
    with patch("psutil.net_connections", return_value=fake_conns):
        with patch(
            "biocybe.network_monitor._safe_process_info",
            return_value=("test.exe", "/tmp/test"),
        ):
            exit_code = main(["netmon", "scan", "--json"])

    assert exit_code == 1  # IOC trouvé
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["malicious_count"] == 1
    assert payload["records"][0]["hit"]["malware"] == "Cobalt Strike"


def test_cli_netmon_block_apply_requires_yes(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    _seed_lookup_db(tmp_path / "db" / "signatures")
    monkeypatch.chdir(tmp_path)
    hosts = tmp_path / "hosts"
    hosts.write_text("", encoding="utf-8")

    exit_code = main(["netmon", "block", "apply", "--hosts-path", str(hosts)])
    assert exit_code == 2  # refusé sans --yes
    assert "--yes" in capsys.readouterr().err


def test_cli_netmon_block_apply_with_yes(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    _seed_lookup_db(tmp_path / "db" / "signatures")
    monkeypatch.chdir(tmp_path)
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    exit_code = main(
        [
            "netmon",
            "block",
            "apply",
            "--hosts-path",
            str(hosts),
            "--yes",
            "--min-confidence",
            "50",
        ]
    )
    assert exit_code == 0
    content = hosts.read_text(encoding="utf-8")
    assert "BIOCYBE-IOC-BLOCK START" in content
    assert "bad-c2.test" in content


def test_cli_netmon_block_status(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    hosts = tmp_path / "hosts"
    hosts.write_text("", encoding="utf-8")
    # Apply quelques entries via le blocker direct
    from biocybe.network_monitor import HostsBlocker

    HostsBlocker(hosts).apply(["x.test", "y.test"])

    monkeypatch.chdir(tmp_path)
    exit_code = main(["netmon", "block", "status", "--hosts-path", str(hosts), "--json"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["blocked_count"] == 2


def test_cli_netmon_block_clear(tmp_path, monkeypatch):
    from biocybe.cli import main
    from biocybe.network_monitor import HostsBlocker

    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    HostsBlocker(hosts).apply(["x.test", "y.test"])

    monkeypatch.chdir(tmp_path)
    exit_code = main(["netmon", "block", "clear", "--hosts-path", str(hosts), "--yes"])
    assert exit_code == 0
    content = hosts.read_text(encoding="utf-8")
    assert "BIOCYBE" not in content
    assert "127.0.0.1 localhost" in content
