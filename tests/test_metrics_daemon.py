"""Tests endpoint Prometheus du daemon (observabilité runtime)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

_HAS_PROM = importlib.util.find_spec("prometheus_client") is not None
pytestmark = pytest.mark.skipif(not _HAS_PROM, reason="prometheus_client absent (extra [web])")


def _render(server) -> str:
    """Rend les métriques du collecteur en texte exposition."""
    from prometheus_client import CollectorRegistry, generate_latest

    reg = CollectorRegistry()
    reg.register(server.build_collector())
    return generate_latest(reg).decode("utf-8")


def test_collector_uptime_always_present():
    from biocybe.metrics_daemon import DaemonMetricsServer

    server = DaemonMetricsServer()
    body = _render(server)
    assert "biocybe_daemon_uptime_seconds" in body


def test_collector_watcher_stats():
    from biocybe.metrics_daemon import DaemonMetricsServer

    stats = {
        "events_scanned": 100,
        "events_skipped": 5,
        "detections": 7,
        "quarantined": 3,
        "memory_suppressed": 2,
        "errors": 1,
    }
    server = DaemonMetricsServer(watcher_stats_fn=lambda: stats)
    body = _render(server)
    assert "biocybe_watcher_detections 7.0" in body
    assert "biocybe_watcher_memory_suppressed 2.0" in body
    assert "biocybe_watcher_quarantined 3.0" in body


def test_collector_nk_actions():
    from biocybe.metrics_daemon import DaemonMetricsServer

    counts = {"executed": 4, "dry_run": 10, "rate_limited": 1}
    server = DaemonMetricsServer(nk_counts_fn=lambda: counts)
    body = _render(server)
    assert 'biocybe_nk_actions_total{outcome="executed"} 4.0' in body
    assert 'biocybe_nk_actions_total{outcome="dry_run"} 10.0' in body


def test_collector_netmon_iocs():
    from biocybe.metrics_daemon import DaemonMetricsServer

    server = DaemonMetricsServer(netmon_iocs_fn=lambda: 18742)
    body = _render(server)
    assert "biocybe_netmon_iocs_loaded 18742.0" in body


def test_collector_memory_stats():
    from biocybe.metrics_daemon import DaemonMetricsServer

    stats = {
        "by_verdict": {"malicious": 12, "benign": 3},
        "by_disposition": {"confirmed_benign": 4, "unreviewed": 11},
    }
    server = DaemonMetricsServer(memory_stats_fn=lambda: stats)
    body = _render(server)
    assert 'biocybe_memory_indicators_total{verdict="malicious"} 12.0' in body
    assert 'biocybe_memory_disposition_total{disposition="confirmed_benign"} 4.0' in body


def test_collector_provider_exception_is_safe():
    """Un provider qui lève ne casse pas le scrape (les autres passent)."""
    from biocybe.metrics_daemon import DaemonMetricsServer

    def boom():
        raise RuntimeError("provider down")

    server = DaemonMetricsServer(
        watcher_stats_fn=boom,
        netmon_iocs_fn=lambda: 42,
    )
    body = _render(server)
    # uptime + netmon présents malgré le watcher en échec
    assert "biocybe_daemon_uptime_seconds" in body
    assert "biocybe_netmon_iocs_loaded 42.0" in body


def test_server_start_stop_real_http():
    """Démarre un vrai serveur HTTP, scrape /metrics, arrête."""
    import urllib.request

    from biocybe.metrics_daemon import DaemonMetricsServer

    server = DaemonMetricsServer(netmon_iocs_fn=lambda: 7)
    # Port haut peu susceptible d'être pris
    ok = server.start(port=19099, addr="127.0.0.1")
    assert ok is True
    try:
        with urllib.request.urlopen("http://127.0.0.1:19099/metrics", timeout=5) as resp:
            body = resp.read().decode("utf-8")
        assert "biocybe_netmon_iocs_loaded 7.0" in body
    finally:
        server.stop()


# ----------------------------------------------------------------------
# Wiring daemon
# ----------------------------------------------------------------------


def test_build_metrics_server_disabled():
    import argparse

    from biocybe.cli import _build_daemon_metrics_server

    args = argparse.Namespace(metrics_port=None)
    s = _build_daemon_metrics_server(
        {}, cli_args=args, watcher=None, netmon_service=None, immune_memory=None
    )
    assert s is None


def test_build_metrics_server_via_cli_port():
    import argparse

    from biocybe.cli import _build_daemon_metrics_server

    args = argparse.Namespace(metrics_port=19098)
    s = _build_daemon_metrics_server(
        {}, cli_args=args, watcher=None, netmon_service=None, immune_memory=None
    )
    assert s is not None
    try:
        import urllib.request

        with urllib.request.urlopen("http://127.0.0.1:19098/metrics", timeout=5) as resp:
            assert resp.status == 200
    finally:
        s.stop()
