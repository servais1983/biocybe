"""Couverture du macrophage avec un psutil factice. Aucun processus n'est lancé."""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from types import SimpleNamespace

import psutil

import biocybe.macrophages.macrophage as mac
from biocybe.biocybe_core.core import CellMessage
from biocybe.macrophages.macrophage import (
    MacrophageCell,
    SystemMonitor,
    create_cells,
    suspicious_command_reason,
)


class _Proc:
    def __init__(self, pid):
        self.pid = pid

    def name(self):
        if self.pid == 2:
            raise psutil.AccessDenied(self.pid)
        if self.pid == 3:
            raise psutil.ZombieProcess(self.pid)
        return "tool"

    def create_time(self):
        return datetime.now().timestamp()

    def username(self):
        if self.pid == 4:
            raise psutil.NoSuchProcess(self.pid)
        return "lab"

    def status(self):
        return "sleeping"

    def cpu_percent(self):
        return 0.1

    def memory_percent(self):
        return 0.1

    def cmdline(self):
        if self.pid == 5:
            raise psutil.AccessDenied(self.pid)
        if self.pid in (6, 7):
            return ["chmod", "777", "notes.txt"]
        return ["tool"]


class _Addr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


def _install(monkeypatch, *, cpu=10.0, freq=True, disk_io=True, net_io=True, pids=None, conns=None):
    class _IO:
        def _asdict(self):
            return {"read": 1}

    monkeypatch.setattr(mac.psutil, "cpu_percent", lambda interval=None: cpu)
    monkeypatch.setattr(mac.psutil, "cpu_count", lambda: 2)
    monkeypatch.setattr(
        mac.psutil, "cpu_freq", lambda: SimpleNamespace(current=1000) if freq else None
    )
    monkeypatch.setattr(
        mac.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(total=100, available=80, percent=20),
    )
    monkeypatch.setattr(mac.psutil, "swap_memory", lambda: SimpleNamespace(percent=0))
    monkeypatch.setattr(mac.psutil, "disk_usage", lambda path: SimpleNamespace(percent=10))
    monkeypatch.setattr(mac.psutil, "disk_io_counters", lambda: _IO() if disk_io else None)
    monkeypatch.setattr(mac.psutil, "net_io_counters", lambda: _IO() if net_io else None)
    monkeypatch.setattr(mac.psutil, "net_connections", lambda: conns if conns is not None else [])
    monkeypatch.setattr(mac.psutil, "pids", lambda: pids if pids is not None else [])
    monkeypatch.setattr(mac.psutil, "Process", _Proc)


def test_monitor_metrics_processes_and_files(tmp_path, monkeypatch):
    assert suspicious_command_reason("tool --help") is None
    assert suspicious_command_reason("chmod 777 notes.txt")

    saved = getattr(os, "getloadavg", None)
    if saved is not None:
        del os.getloadavg
    try:
        _install(monkeypatch, freq=False, disk_io=False, net_io=False, pids=[])
        bare = SystemMonitor().collect_system_metrics()
        assert bare["cpu"]["freq"] is None
        assert bare["cpu"]["load_avg"] is None
        assert bare["disk"]["io_counters"] is None
    finally:
        if saved is not None:
            os.getloadavg = saved

    _install(
        monkeypatch,
        pids=[1, 2, 3, 4, 5, 6],
        conns=[
            SimpleNamespace(
                fd=1, family=2, type=1, laddr=None, raddr=None, status="NONE", pid=None
            ),
            SimpleNamespace(
                fd=2,
                family=2,
                type=1,
                laddr=_Addr("127.0.0.1", 1),
                raddr=_Addr("192.0.2.1", 8080),
                status="ESTABLISHED",
                pid=2,
            ),
            SimpleNamespace(
                fd=3,
                family=2,
                type=1,
                laddr=_Addr("127.0.0.1", 2),
                raddr=_Addr("192.0.2.2", 443),
                status="ESTABLISHED",
                pid=1,
            ),
        ],
    )
    mon = SystemMonitor()
    metrics = mon.collect_system_metrics()
    assert metrics["processes"]["count"] == 6
    mon.last_scan = datetime.now() - timedelta(days=1)
    procs = mon.scan_processes()
    assert any(p.get("suspicious") for p in procs["processes"].values())
    assert procs["new_processes"]
    net = mon.scan_network_connections()
    assert net["suspicious_connections"]

    def explode():
        raise psutil.AccessDenied(0)

    monkeypatch.setattr(mac.psutil, "net_connections", explode)
    assert mon.scan_network_connections()["connection_count"] == 0
    monkeypatch.setattr(mac.psutil, "net_connections", lambda: [])

    missing = tmp_path / "absent"
    watched = tmp_path / "watch"
    watched.mkdir()
    (watched / "notes.py").write_text("print('ok')\n", encoding="utf-8")
    (watched / "plain.txt").write_text("ok\n", encoding="utf-8")
    hidden = watched / "gone.txt"
    hidden.write_text("x", encoding="utf-8")
    real_stat = os.stat

    def stat(path, *args, **kwargs):
        if str(path).endswith("gone.txt"):
            raise PermissionError("denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat)
    changes = mon.scan_file_changes([str(missing), str(watched)])
    assert changes["suspicious_files"]

    assert mon.detect_anomalies() == []
    mon.establish_baseline()
    found = mon.anomalies_between(
        {"cpu": {"percent": 0}, "memory": {"percent": 0}},
        {"cpu": {"percent": 90}, "memory": {"percent": 90}},
    )
    assert {a["type"] for a in found} == {"high_cpu_usage", "high_memory_usage"}
    assert (
        mon.anomalies_between(
            {"cpu": {"percent": 10}, "memory": {"percent": 10}},
            {"cpu": {"percent": 11}, "memory": {"percent": 11}},
        )
        == []
    )
    assert (
        mon.anomalies_between(
            {"cpu": {"percent": 0}, "memory": {"percent": 0}},
            {"cpu": {"percent": 0}, "memory": {"percent": 0}},
        )
        == []
    )
    mon.last_scan = datetime.now() + timedelta(days=1)
    assert mon.scan_processes()["new_processes"] == []


def test_macrophage_cycles_and_factory(tmp_path, monkeypatch):
    _install(monkeypatch, cpu=5.0, pids=[1], conns=[])
    cell = MacrophageCell(
        "macro_lab",
        {"scan_interval": 0, "watch_directories": [str(tmp_path)]},
    )
    sent = []
    cell._bus_send = lambda *args: sent.append(args) or True
    cell._process_cycle()
    assert cell.monitor.baseline
    monkeypatch.setattr(mac.psutil, "cpu_percent", lambda interval=None: 95.0)
    monkeypatch.setattr(
        mac.psutil,
        "pids",
        lambda: [6, 7],
    )
    monkeypatch.setattr(
        mac.psutil,
        "net_connections",
        lambda: [
            SimpleNamespace(
                fd=1,
                family=2,
                type=1,
                laddr=_Addr("127.0.0.1", 9),
                raddr=_Addr("192.0.2.9", 4444),
                status="ESTABLISHED",
                pid=1,
            )
        ],
    )
    cell._process_cycle()
    assert sent
    sent.clear()
    monkeypatch.setattr(mac.psutil, "cpu_percent", lambda interval=None: 5.0)
    monkeypatch.setattr(mac.psutil, "pids", lambda: [1])
    monkeypatch.setattr(mac.psutil, "net_connections", lambda: [])
    cell.monitor.baseline["system_metrics"]["cpu"]["percent"] = 5
    cell.monitor.baseline["system_metrics"]["memory"]["percent"] = 20
    cell.stats["actions_performed"] = 0
    cell._process_cycle()
    assert any(call[0] == "system_health" for call in sent)
    cell.stats["actions_performed"] = 1
    cell.scan_interval = 0
    cell.last_scan_time = datetime.now() - timedelta(days=1)
    cell._process_cycle()
    cell.last_scan_time = datetime.now()
    cell.scan_interval = 10_000
    cell._process_cycle()
    cell.scan_interval = 0
    cell.monitor.baseline = None
    cell.handle_message(CellMessage("request_scan", "lab", payload={}))

    cell.handle_message(
        CellMessage("request_scan", "lab", payload={"directories": [str(tmp_path)]})
    )
    cell.handle_message(CellMessage("request_scan", "lab", payload=None))
    cell.handle_message(CellMessage("request_scan", "lab", payload={"detect_anomalies": True}))
    cell.handle_message(CellMessage("system_start", "core"))
    cell.handle_message(CellMessage("unknown", "core"))

    assert len(create_cells({})) == 1
    made = create_cells(
        {
            "cells": {
                "macrophage": {"instances": [{}, {"name": "m2", "config": {"scan_interval": 1}}]}
            }
        }
    )
    assert [c.name for c in made] == ["macrophage_0", "m2"]
