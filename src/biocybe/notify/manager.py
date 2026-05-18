"""NotifierManager : orchestration des notifiers.

Distribue les `Event` à N notifiers en parallèle (threadpool) avec :
  - **Failure isolation** : un notifier qui plante n'empêche pas les
    autres d'être notifiés. Indispensable en SOC : on ne perd jamais
    une alerte critique parce que Slack a un hiccup.
  - **Retry exponential backoff** : 3 tentatives par défaut, espacées
    de 0.5s, 1s, 2s. Configurable.
  - **Rate limiting** par notifier pour éviter de flood en cas de storm
    d'événements (ex. ransomware déclenche 1000 détections en 1 minute).
  - **Async non-bloquant** : la production d'événements (scan, anomaly)
    n'attend jamais l'envoi réseau.
  - **Métriques internes** : compteurs success/failure par notifier,
    exposables en Prometheus si l'API est lancée.

Configuration via dict (typiquement chargé depuis YAML) :
    notify:
      slack:
        webhook_url: https://hooks.slack.com/services/T.../B.../X
        min_severity: warning
      syslog:
        host: siem.local
        port: 514
        protocol: udp
        min_severity: info
      webhook:
        url: https://soar.example.com/biocybe-hook
        min_severity: error
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from .notifier import (
    Event,
    Notifier,
    NotifyError,
    Severity,
    SlackNotifier,
    SyslogNotifier,
    WebhookNotifier,
)

logger = logging.getLogger("biocybe.notify.manager")


@dataclass
class NotifierStats:
    """Stats par notifier pour observabilité."""

    sent: int = 0
    failed: int = 0
    rate_limited: int = 0
    last_error: str | None = None
    last_success_at: float | None = None
    last_failure_at: float | None = None


class _RateLimiter:
    """Token bucket simple par notifier.

    `max_events` événements autorisés par fenêtre glissante de
    `window_seconds`. Au-delà : silencieusement droppés (rate_limited++).
    Évite le storm SOC quand un ransomware déclenche 1000 alertes/sec.
    """

    def __init__(self, max_events: int, window_seconds: float):
        self.max_events = max_events
        self.window = window_seconds
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        now = time.time()
        with self._lock:
            # Purge des événements en dehors de la fenêtre
            while self._events and now - self._events[0] > self.window:
                self._events.popleft()
            if len(self._events) >= self.max_events:
                return False
            self._events.append(now)
            return True


class NotifierManager:
    """Orchestre les notifiers : dispatch parallèle, retry, métriques."""

    def __init__(
        self,
        notifiers: list[Notifier] | None = None,
        *,
        max_workers: int = 4,
        retry_attempts: int = 3,
        retry_initial_delay: float = 0.5,
        rate_limit_per_minute: int = 60,
    ):
        self._notifiers: list[Notifier] = list(notifiers or [])
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="biocybe-notify"
        )
        self.retry_attempts = retry_attempts
        self.retry_initial_delay = retry_initial_delay
        self.rate_limit_per_minute = rate_limit_per_minute
        self._stats: dict[str, NotifierStats] = defaultdict(NotifierStats)
        self._limiters: dict[str, _RateLimiter] = {}
        for n in self._notifiers:
            self._limiters[n.name] = _RateLimiter(rate_limit_per_minute, 60.0)

    # -------------------- public API --------------------

    def add(self, notifier: Notifier) -> None:
        self._notifiers.append(notifier)
        self._limiters[notifier.name] = _RateLimiter(self.rate_limit_per_minute, 60.0)

    @property
    def notifiers(self) -> list[Notifier]:
        return list(self._notifiers)

    def stats(self) -> dict[str, dict[str, Any]]:
        return {name: vars(s) for name, s in self._stats.items()}

    def notify(self, event: Event) -> None:
        """Dispatche `event` aux notifiers compatibles. Non-bloquant."""
        for notifier in self._notifiers:
            if not notifier.accepts(event):
                continue
            if not self._limiters[notifier.name].try_acquire():
                self._stats[notifier.name].rate_limited += 1
                logger.warning(
                    "Notifier %s rate-limité (>%d evts/min) — event %s droppé",
                    notifier.name,
                    self.rate_limit_per_minute,
                    event.kind.value,
                )
                continue
            self._executor.submit(self._send_with_retry, notifier, event)

    def notify_sync(self, event: Event) -> dict[str, str]:
        """Variante synchrone pour tests et `biocybe notify test`.

        Retourne un dict {notifier_name: "ok" | error_message}.
        Ne fait PAS de retry (test = signal direct).
        """
        results: dict[str, str] = {}
        for notifier in self._notifiers:
            if not notifier.accepts(event):
                results[notifier.name] = "skipped (severity filter)"
                continue
            try:
                notifier.notify(event)
                self._stats[notifier.name].sent += 1
                self._stats[notifier.name].last_success_at = time.time()
                results[notifier.name] = "ok"
            except NotifyError as exc:
                self._stats[notifier.name].failed += 1
                self._stats[notifier.name].last_error = str(exc)
                self._stats[notifier.name].last_failure_at = time.time()
                results[notifier.name] = f"failed: {exc}"
            except Exception as exc:
                self._stats[notifier.name].failed += 1
                self._stats[notifier.name].last_error = f"unexpected: {exc}"
                self._stats[notifier.name].last_failure_at = time.time()
                results[notifier.name] = f"unexpected: {exc}"
        return results

    def shutdown(self, wait: bool = True, timeout: float = 5.0) -> None:
        """Coupe le pool, attend les notifications en cours si demandé."""
        if wait:
            self._executor.shutdown(wait=True)
        else:
            self._executor.shutdown(wait=False, cancel_futures=True)
        _ = timeout  # ThreadPoolExecutor n'a pas de paramètre timeout direct

    # -------------------- internals --------------------

    def _send_with_retry(self, notifier: Notifier, event: Event) -> None:
        delay = self.retry_initial_delay
        last_err: Exception | None = None
        for attempt in range(1, self.retry_attempts + 1):
            try:
                notifier.notify(event)
                self._stats[notifier.name].sent += 1
                self._stats[notifier.name].last_success_at = time.time()
                return
            except NotifyError as exc:
                last_err = exc
                logger.warning(
                    "Notifier %s tentative %d/%d échouée : %s",
                    notifier.name,
                    attempt,
                    self.retry_attempts,
                    exc,
                )
            except Exception as exc:
                last_err = exc
                logger.error(
                    "Notifier %s exception inattendue (att. %d/%d) : %s",
                    notifier.name,
                    attempt,
                    self.retry_attempts,
                    exc,
                )
            if attempt < self.retry_attempts:
                time.sleep(delay)
                delay *= 2  # exponential backoff

        # Toutes les tentatives ont échoué
        self._stats[notifier.name].failed += 1
        self._stats[notifier.name].last_error = str(last_err)
        self._stats[notifier.name].last_failure_at = time.time()
        logger.error(
            "Notifier %s : abandon après %d tentatives. Dernière erreur : %s",
            notifier.name,
            self.retry_attempts,
            last_err,
        )


# --------------------------------------------------------------------- #
# Builder à partir de config dict
# --------------------------------------------------------------------- #


def _parse_severity(value: Any, default: Severity = Severity.WARNING) -> Severity:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value.lower())
        except ValueError:
            logger.warning("Severity inconnue '%s', fallback %s", value, default.value)
    return default


def build_from_config(config: dict[str, Any]) -> NotifierManager:
    """Construit un NotifierManager depuis un dict de config.

    Format attendu (typiquement extrait de `notify:` dans biocybe.yaml) :

        slack:
          webhook_url: https://...  # ou env: SLACK_WEBHOOK_URL
          min_severity: warning
          channel: "#alerts"   # optionnel
        syslog:
          host: siem.local
          port: 514
          protocol: udp        # ou tcp
          min_severity: info
          app_name: biocybe-prod
        webhook:
          url: https://soar.example.com/biocybe
          min_severity: error
          headers:
            X-API-Key: ${MY_TOKEN}

    Les valeurs `${VAR}` sont substituées depuis l'environnement.
    """
    mgr = NotifierManager()

    def _resolve_env(v: Any) -> Any:
        if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
            return os.environ.get(v[2:-1], "")
        return v

    # Slack
    slack_cfg = config.get("slack") or {}
    if slack_cfg:
        url = _resolve_env(slack_cfg.get("webhook_url")) or os.environ.get("SLACK_WEBHOOK_URL", "")
        if url:
            try:
                mgr.add(
                    SlackNotifier(
                        url,
                        min_severity=_parse_severity(slack_cfg.get("min_severity")),
                        channel=slack_cfg.get("channel"),
                        username=slack_cfg.get("username", "BioCybe"),
                    )
                )
                logger.info(
                    "Notifier slack configuré (min_severity=%s)", slack_cfg.get("min_severity")
                )
            except ValueError as exc:
                logger.error("Notifier slack invalide : %s", exc)

    # Syslog
    syslog_cfg = config.get("syslog") or {}
    if syslog_cfg:
        host = _resolve_env(syslog_cfg.get("host")) or os.environ.get("SYSLOG_HOST", "")
        if host:
            try:
                mgr.add(
                    SyslogNotifier(
                        host=host,
                        port=int(syslog_cfg.get("port", 514)),
                        protocol=syslog_cfg.get("protocol", "udp"),
                        min_severity=_parse_severity(syslog_cfg.get("min_severity"), Severity.INFO),
                        app_name=syslog_cfg.get("app_name", "biocybe"),
                    )
                )
                logger.info("Notifier syslog configuré (%s:%s)", host, syslog_cfg.get("port", 514))
            except ValueError as exc:
                logger.error("Notifier syslog invalide : %s", exc)

    # Webhook(s) — peut être une liste pour plusieurs cibles
    webhook_cfg = config.get("webhook")
    if webhook_cfg:
        items = webhook_cfg if isinstance(webhook_cfg, list) else [webhook_cfg]
        for w in items:
            url = _resolve_env(w.get("url")) or os.environ.get("BIOCYBE_WEBHOOK_URL", "")
            if not url:
                continue
            headers = {k: _resolve_env(v) for k, v in (w.get("headers") or {}).items()}
            try:
                mgr.add(
                    WebhookNotifier(
                        url,
                        min_severity=_parse_severity(w.get("min_severity")),
                        timeout=float(w.get("timeout", 5.0)),
                        headers=headers,
                    )
                )
                logger.info("Notifier webhook configuré : %s", url)
            except ValueError as exc:
                logger.error("Notifier webhook invalide : %s", exc)

    return mgr
