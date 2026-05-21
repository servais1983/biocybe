"""Endpoint Prometheus du daemon BioCybe (observabilité runtime).

Le process API expose déjà `/metrics` (scan/quarantine/feed age/mémoire),
mais le **daemon** (watcher temps-réel, network monitor, cellule NK)
tourne dans un process séparé sans serveur HTTP. Ce module lui en donne
un, léger et standard : `prometheus_client.start_http_server`.

Conception : un **collecteur custom** lit l'état live au moment du scrape
(stats du watcher, compteurs NK, total IOCs du netmon, stats mémoire,
uptime). Aucune double comptabilité — les compteurs déjà tenus par les
composants (WatcherStats, NKCell.action_counts) sont la source de vérité.

Activation opt-in : `config.metrics.daemon_enabled` ou `--metrics-port`.
Dépend de l'extra `[web]` (prometheus_client). Sans, le daemon démarre
quand même (le serveur de métriques est simplement absent).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("biocybe.metrics_daemon")


class DaemonMetricsServer:
    """Serveur HTTP Prometheus pour le daemon.

    Les sources sont fournies via des callables (injection) pour rester
    découplé et testable :
      - `watcher_stats_fn() -> dict | None` (WatcherStats.to_dict())
      - `nk_counts_fn() -> dict[str,int] | None` (NKCell.action_counts)
      - `netmon_iocs_fn() -> int | None`
      - `memory_stats_fn() -> dict | None` (ImmuneMemory.stats())
      - `started_at` : timestamp de démarrage du daemon (uptime)
    """

    def __init__(
        self,
        *,
        watcher_stats_fn: Callable[[], dict | None] | None = None,
        nk_counts_fn: Callable[[], dict[str, int] | None] | None = None,
        netmon_iocs_fn: Callable[[], int | None] | None = None,
        memory_stats_fn: Callable[[], dict | None] | None = None,
        started_at: float | None = None,
    ):
        self.watcher_stats_fn = watcher_stats_fn
        self.nk_counts_fn = nk_counts_fn
        self.netmon_iocs_fn = netmon_iocs_fn
        self.memory_stats_fn = memory_stats_fn
        self.started_at = started_at or time.time()
        self._httpd = None
        self._registry = None

    def build_collector(self):
        """Construit le collecteur custom (lecture live au scrape)."""
        from prometheus_client.core import GaugeMetricFamily

        server = self

        class _DaemonCollector:
            def collect(self):
                # Uptime
                up = GaugeMetricFamily(
                    "biocybe_daemon_uptime_seconds", "Uptime du daemon BioCybe (s)"
                )
                up.add_metric([], time.time() - server.started_at)
                yield up

                # Watcher temps-réel
                if server.watcher_stats_fn is not None:
                    ws = _safe_call(server.watcher_stats_fn)
                    if isinstance(ws, dict):
                        for key in (
                            "events_scanned",
                            "events_skipped",
                            "detections",
                            "quarantined",
                            "memory_suppressed",
                            "errors",
                        ):
                            g = GaugeMetricFamily(
                                f"biocybe_watcher_{key}",
                                f"Watcher temps-réel : {key} (cumul depuis démarrage)",
                            )
                            g.add_metric([], float(ws.get(key, 0) or 0))
                            yield g

                # Cellule NK
                if server.nk_counts_fn is not None:
                    nk = _safe_call(server.nk_counts_fn)
                    if isinstance(nk, dict):
                        fam = GaugeMetricFamily(
                            "biocybe_nk_actions_total",
                            "Actions NK cumulées, par outcome "
                            "(executed/dry_run/refused/rate_limited/...)",
                            labels=["outcome"],
                        )
                        for outcome, n in nk.items():
                            fam.add_metric([str(outcome)], float(n))
                        yield fam

                # Network monitor : nombre d'IOCs chargés
                if server.netmon_iocs_fn is not None:
                    total = _safe_call(server.netmon_iocs_fn)
                    if isinstance(total, int):
                        g = GaugeMetricFamily(
                            "biocybe_netmon_iocs_loaded",
                            "Nombre d'IOCs chargés par le network monitor",
                        )
                        g.add_metric([], float(total))
                        yield g

                # Mémoire immunitaire
                if server.memory_stats_fn is not None:
                    ms = _safe_call(server.memory_stats_fn)
                    if isinstance(ms, dict):
                        by_verdict = ms.get("by_verdict", {}) or {}
                        fam = GaugeMetricFamily(
                            "biocybe_memory_indicators_total",
                            "Indicateurs en mémoire immunitaire, par verdict",
                            labels=["verdict"],
                        )
                        for verdict, n in by_verdict.items():
                            fam.add_metric([str(verdict)], float(n))
                        yield fam

                        by_disp = ms.get("by_disposition", {}) or {}
                        fam2 = GaugeMetricFamily(
                            "biocybe_memory_disposition_total",
                            "Indicateurs par disposition (confirmed_benign = FP supprimés)",
                            labels=["disposition"],
                        )
                        for disp, n in by_disp.items():
                            fam2.add_metric([str(disp)], float(n))
                        yield fam2

        return _DaemonCollector()

    def start(self, port: int = 9091, addr: str = "0.0.0.0") -> bool:  # noqa: S104
        """Démarre le serveur HTTP de métriques. False si indisponible.

        Le bind par défaut sur 0.0.0.0 est volontaire (scrape par
        Prometheus depuis un autre host/pod) ; restreindre via firewall /
        NetworkPolicy en prod, comme pour l'API.
        """
        try:
            from prometheus_client import CollectorRegistry, start_http_server
        except ImportError:
            logger.warning(
                "prometheus_client absent : pas de /metrics daemon. "
                "Installe : pip install biocybe[web]"
            )
            return False

        self._registry = CollectorRegistry()
        self._registry.register(self.build_collector())
        try:
            self._httpd, _thread = start_http_server(
                port, addr=addr, registry=self._registry
            )
        except OSError as exc:
            logger.error("Impossible de démarrer /metrics daemon sur %s:%d : %s", addr, port, exc)
            return False
        logger.info("Daemon /metrics exposé sur http://%s:%d/metrics", addr, port)
        return True

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            self._httpd = None


def _safe_call(fn: Callable[[], Any]):
    try:
        return fn()
    except Exception as exc:  # pragma: no cover - défense
        logger.debug("metrics provider a levé : %s", exc)
        return None


__all__ = ["DaemonMetricsServer"]
