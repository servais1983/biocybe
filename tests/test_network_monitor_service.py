"""Tests Phase 3.h : NetworkMonitorService + wiring daemon.

Couvre :
  - construction depuis db_path, expose ioc_total
  - maybe_reload : recharge quand last_update.txt change, no-op sinon
  - le monitor voit les nouveaux IOCs après reload (mutation in-place)
  - _build_network_monitor_service_from_config : activation config/CLI,
    callback on_match qui audit + notifie
"""

from __future__ import annotations

import json
import sys
from collections import namedtuple
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

FakeAddr = namedtuple("FakeAddr", ["ip", "port"])
FakeConn = namedtuple("FakeConn", ["laddr", "raddr", "status", "pid"])


def _fake_conn(remote_ip, remote_port, pid=4321):
    return FakeConn(
        laddr=FakeAddr("192.168.1.5", 5000),
        raddr=FakeAddr(remote_ip, remote_port),
        status="ESTABLISHED",
        pid=pid,
    )


def _seed_feed(db: Path, ip_map: dict, ts: datetime | None = None):
    ts = ts or datetime.now()
    tf = db / "threatfox" / "by_type"
    tf.mkdir(parents=True, exist_ok=True)
    (tf / "ip.json").write_text(json.dumps(ip_map), encoding="utf-8")
    (db / "threatfox" / "last_update.txt").write_text(ts.isoformat(), encoding="utf-8")


# ----------------------------------------------------------------------
# NetworkMonitorService
# ----------------------------------------------------------------------


def test_service_construction_and_total(tmp_path):
    from biocybe.network_monitor import NetworkMonitorService

    _seed_feed(
        tmp_path,
        {"10.0.0.1:443": {"malware": "X", "confidence": 90, "source": "abuse.ch/ThreatFox"}},
    )
    svc = NetworkMonitorService(tmp_path, interval=1.0)
    # 10.0.0.1:443 + 10.0.0.1 (indexé en double) = 2
    assert svc.ioc_total == 2


def test_maybe_reload_noop_when_unchanged(tmp_path):
    from biocybe.network_monitor import NetworkMonitorService

    _seed_feed(tmp_path, {"10.0.0.1:443": {"malware": "X", "confidence": 90}})
    svc = NetworkMonitorService(tmp_path)
    assert svc.maybe_reload() is False  # rien n'a changé


def test_maybe_reload_picks_up_new_iocs(tmp_path):
    from biocybe.network_monitor import NetworkMonitorService

    _seed_feed(
        tmp_path,
        {"10.0.0.1:443": {"malware": "X", "confidence": 90}},
        ts=datetime(2026, 5, 21, 10, 0, 0),
    )
    svc = NetworkMonitorService(tmp_path)
    before = svc.ioc_total

    # Nouveau feed avec un IOC de plus + timestamp différent
    _seed_feed(
        tmp_path,
        {
            "10.0.0.1:443": {"malware": "X", "confidence": 90},
            "10.0.0.2:80": {"malware": "Y", "confidence": 80},
        },
        ts=datetime(2026, 5, 21, 16, 0, 0),
    )
    assert svc.maybe_reload() is True
    assert svc.ioc_total > before
    # Le monitor (même objet lookup) voit le nouvel IOC
    assert svc.monitor.lookup.lookup_ip("10.0.0.2:80") is not None


def test_monitor_uses_reloaded_lookup_in_snapshot(tmp_path):
    from biocybe.network_monitor import NetworkMonitorService

    _seed_feed(
        tmp_path,
        {"10.0.0.1:443": {"malware": "X", "confidence": 90}},
        ts=datetime(2026, 5, 21, 10, 0, 0),
    )
    svc = NetworkMonitorService(tmp_path)

    # Ajoute un IOC + reload
    _seed_feed(
        tmp_path,
        {
            "10.0.0.1:443": {"malware": "X", "confidence": 90},
            "203.0.113.5:8080": {"malware": "Cobalt", "confidence": 100},
        },
        ts=datetime(2026, 5, 21, 18, 0, 0),
    )
    svc.maybe_reload()

    fake = [_fake_conn("203.0.113.5", 8080)]
    with patch("psutil.net_connections", return_value=fake):
        with patch("biocybe.network_monitor._safe_process_info", return_value=("x.exe", "")):
            records = svc.monitor.snapshot()
    malicious = [r for r in records if r.is_malicious]
    assert len(malicious) == 1
    assert malicious[0].hit.malware == "Cobalt"


# ----------------------------------------------------------------------
# Wiring daemon : _build_network_monitor_service_from_config
# ----------------------------------------------------------------------


def test_build_service_disabled_returns_none(tmp_path):
    from biocybe.cli import _build_network_monitor_service_from_config

    # Pas de section netmon, pas de flag CLI
    svc = _build_network_monitor_service_from_config({}, None, cli_args=None)
    assert svc is None


def test_build_service_enabled_via_config(tmp_path, monkeypatch):
    from biocybe.cli import _build_network_monitor_service_from_config

    _seed_feed(tmp_path, {"10.0.0.1:443": {"malware": "X", "confidence": 90}})
    config = {"netmon": {"enabled": True, "db_path": str(tmp_path), "interval": 2}}
    svc = _build_network_monitor_service_from_config(config, None, cli_args=None)
    assert svc is not None
    assert svc.ioc_total >= 1


def test_build_service_enabled_via_cli_flag(tmp_path):
    import argparse

    from biocybe.cli import _build_network_monitor_service_from_config

    _seed_feed(tmp_path, {"10.0.0.1:443": {"malware": "X", "confidence": 90}})
    args = argparse.Namespace(netmon=True, netmon_interval=3.0)
    config = {"netmon": {"db_path": str(tmp_path)}}
    svc = _build_network_monitor_service_from_config(config, None, cli_args=args)
    assert svc is not None
    assert svc.monitor.interval == 3.0


def test_on_match_writes_audit_and_notifies(tmp_path):
    """Le callback on_match doit auditer ET notifier."""
    import argparse

    from biocybe.audit import AuditLog, set_default
    from biocybe.cli import _build_network_monitor_service_from_config

    _seed_feed(
        tmp_path,
        {
            "203.0.113.9:443": {
                "malware": "Emotet",
                "confidence": 95,
                "source": "abuse.ch/ThreatFox",
            }
        },
    )

    # Installe un audit log réel dans tmp
    audit_path = tmp_path / "audit.jsonl"
    set_default(AuditLog(audit_path))

    # Faux NotifierManager qui capture les events
    captured = []

    class FakeMgr:
        def notify(self, event):
            captured.append(event)

    args = argparse.Namespace(netmon=True, netmon_interval=1.0)
    config = {"netmon": {"db_path": str(tmp_path)}}
    svc = _build_network_monitor_service_from_config(config, FakeMgr(), cli_args=args)

    # Simule un match en appelant directement le callback du monitor
    fake = [_fake_conn("203.0.113.9", 443)]
    with patch("psutil.net_connections", return_value=fake):
        with patch(
            "biocybe.network_monitor._safe_process_info",
            return_value=("powershell.exe", "C:\\ps.exe"),
        ):
            records = svc.monitor.snapshot()
            malicious = [r for r in records if r.is_malicious]
            assert malicious
            svc.monitor.on_match(malicious[0])

    # Audit : une entrée network_ioc_detected
    log = AuditLog(audit_path)
    entries = log.read_all()
    assert any(e.action == "network_ioc_detected" for e in entries)
    detected = next(e for e in entries if e.action == "network_ioc_detected")
    assert detected.details["malware"] == "Emotet"
    assert detected.details["process_name"] == "powershell.exe"

    # Notify : un event émis, sévérité critical (conf 95 >= 90)
    assert len(captured) == 1
    assert captured[0].severity.value == "critical"

    set_default(None)  # cleanup


def test_on_match_severity_warning_below_90(tmp_path):
    import argparse

    from biocybe.cli import _build_network_monitor_service_from_config

    _seed_feed(
        tmp_path,
        {"203.0.113.9:443": {"malware": "Adware", "confidence": 70, "source": "x"}},
    )
    captured = []

    class FakeMgr:
        def notify(self, event):
            captured.append(event)

    args = argparse.Namespace(netmon=True, netmon_interval=1.0)
    svc = _build_network_monitor_service_from_config(
        {"netmon": {"db_path": str(tmp_path)}}, FakeMgr(), cli_args=args
    )
    fake = [_fake_conn("203.0.113.9", 443)]
    with patch("psutil.net_connections", return_value=fake):
        with patch("biocybe.network_monitor._safe_process_info", return_value=("a", "")):
            rec = next(r for r in svc.monitor.snapshot() if r.is_malicious)
            svc.monitor.on_match(rec)
    assert captured[0].severity.value == "warning"
