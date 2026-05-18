"""Notifications sortantes BioCybe.

Distribue les événements (détection, quarantaine, anomalie) vers des
destinations externes : Slack, syslog (RFC 5424 — standard SIEM),
webhook HTTP générique (n8n, Zapier, Cortex XSOAR, scripts custom).

Architecture :
  - `Event` : payload canonique d'un événement
  - `Notifier` : interface abstraite (`notify(event)`)
  - Implémentations : `SlackNotifier`, `SyslogNotifier`, `WebhookNotifier`
  - `NotifierManager` : orchestre N notifiers en parallèle (threadpool),
    avec retry, failover (un notifier en panne ne bloque pas les autres),
    filtrage par sévérité.

Voir `manager.py` pour les détails.
"""

from .manager import NotifierManager, build_from_config
from .notifier import (
    Event,
    EventKind,
    Notifier,
    NotifyError,
    Severity,
    SlackNotifier,
    SyslogNotifier,
    WebhookNotifier,
)

__all__ = [
    "Event",
    "EventKind",
    "Notifier",
    "NotifierManager",
    "NotifyError",
    "Severity",
    "SlackNotifier",
    "SyslogNotifier",
    "WebhookNotifier",
    "build_from_config",
]
