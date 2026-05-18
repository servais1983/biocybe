"""Interfaces et implémentations Notifier.

Trois transports livrés en Phase 2.3.b :
  - SlackNotifier (Incoming Webhook ou bot webhook)
  - SyslogNotifier (RFC 5424, UDP ou TCP — standard SIEM/SOC)
  - WebhookNotifier (POST JSON générique → n8n, Zapier, SOAR, scripts)

Chaque notifier est pensé pour la prod :
  - Timeout HTTP/socket explicites (jamais bloquant)
  - Failure isolation : un notifier qui plante lève `NotifyError`,
    le manager le récupère et continue les autres.
  - Filtre par sévérité minimale (ex. Slack uniquement WARNING+).
  - Pas de secrets dans le code : webhook URL via env ou config.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import requests

logger = logging.getLogger("biocybe.notify")


# --------------------------------------------------------------------- #
# Modèle d'événement
# --------------------------------------------------------------------- #


class Severity(str, Enum):
    """Niveaux de sévérité, alignés sur syslog."""

    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    def syslog_severity(self) -> int:
        """Code numérique RFC 5424."""
        return {
            Severity.DEBUG: 7,
            Severity.INFO: 6,
            Severity.NOTICE: 5,
            Severity.WARNING: 4,
            Severity.ERROR: 3,
            Severity.CRITICAL: 2,
        }[self]

    def numeric(self) -> int:
        """Ordre pour le filtrage par seuil (plus haut = plus grave)."""
        return {
            Severity.DEBUG: 10,
            Severity.INFO: 20,
            Severity.NOTICE: 25,
            Severity.WARNING: 30,
            Severity.ERROR: 40,
            Severity.CRITICAL: 50,
        }[self]


class EventKind(str, Enum):
    """Catégories d'événements observables."""

    SCAN_DETECTION = "scan_detection"
    REALTIME_DETECTION = "realtime_detection"
    QUARANTINE_CREATED = "quarantine_created"
    QUARANTINE_RESTORED = "quarantine_restored"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    INTEL_UPDATE = "intel_update"
    SYSTEM = "system"


@dataclass
class Event:
    """Payload canonique d'un événement à notifier."""

    kind: EventKind
    severity: Severity
    title: str  # ligne courte (Slack title, syslog msg)
    message: str  # description longue (Slack body)
    source: str = "biocybe"  # quelle cellule/module
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["severity"] = self.severity.value
        return d


# --------------------------------------------------------------------- #
# Interface
# --------------------------------------------------------------------- #


class NotifyError(Exception):
    """Échec d'une notification (HTTP, socket, format)."""


class Notifier(ABC):
    """Interface : un transport vers une destination externe."""

    name: str = "abstract"

    def __init__(self, min_severity: Severity = Severity.WARNING) -> None:
        self.min_severity = min_severity

    def accepts(self, event: Event) -> bool:
        """Filtre par sévérité minimale."""
        return event.severity.numeric() >= self.min_severity.numeric()

    @abstractmethod
    def notify(self, event: Event) -> None:
        """Envoie l'événement. Lève `NotifyError` si échec."""


# --------------------------------------------------------------------- #
# Slack
# --------------------------------------------------------------------- #


_SEVERITY_COLOR = {
    Severity.DEBUG: "#9E9E9E",
    Severity.INFO: "#2196F3",
    Severity.NOTICE: "#03A9F4",
    Severity.WARNING: "#FF9800",
    Severity.ERROR: "#F44336",
    Severity.CRITICAL: "#B71C1C",
}

_SEVERITY_EMOJI = {
    Severity.DEBUG: ":bug:",
    Severity.INFO: ":information_source:",
    Severity.NOTICE: ":bell:",
    Severity.WARNING: ":warning:",
    Severity.ERROR: ":exclamation:",
    Severity.CRITICAL: ":rotating_light:",
}


class SlackNotifier(Notifier):
    """Notifier Slack via Incoming Webhook.

    URL au format : https://hooks.slack.com/services/T.../B.../...
    """

    name = "slack"

    def __init__(
        self,
        webhook_url: str,
        *,
        min_severity: Severity = Severity.WARNING,
        timeout: float = 5.0,
        username: str = "BioCybe",
        channel: str | None = None,
        session: requests.Session | None = None,
    ):
        super().__init__(min_severity=min_severity)
        if not webhook_url.startswith("https://"):
            raise ValueError("Slack webhook_url doit être en HTTPS")
        self.webhook_url = webhook_url
        self.timeout = timeout
        self.username = username
        self.channel = channel
        self._session = session or requests.Session()

    def _format(self, event: Event) -> dict[str, Any]:
        emoji = _SEVERITY_EMOJI[event.severity]
        color = _SEVERITY_COLOR[event.severity]
        fields = [
            {"title": "Source", "value": event.source, "short": True},
            {"title": "Kind", "value": event.kind.value, "short": True},
            {"title": "Severity", "value": event.severity.value.upper(), "short": True},
            {"title": "Time", "value": event.timestamp, "short": True},
        ]
        # Ajout dynamique des 4 premières clés du payload (file_path, family, etc.)
        for k, v in list(event.payload.items())[:4]:
            value = str(v)
            if len(value) > 200:
                value = value[:197] + "..."
            fields.append({"title": k, "value": value, "short": False})

        body: dict[str, Any] = {
            "username": self.username,
            "icon_emoji": emoji,
            "attachments": [
                {
                    "color": color,
                    "title": f"{emoji} {event.title}",
                    "text": event.message,
                    "fields": fields,
                    "footer": "BioCybe",
                    "ts": int(time.time()),
                }
            ],
        }
        if self.channel:
            body["channel"] = self.channel
        return body

    def notify(self, event: Event) -> None:
        try:
            resp = self._session.post(
                self.webhook_url,
                json=self._format(event),
                timeout=self.timeout,
            )
            if resp.status_code >= 400:
                raise NotifyError(f"Slack a répondu HTTP {resp.status_code} : {resp.text[:200]}")
        except requests.RequestException as exc:
            raise NotifyError(f"Slack : erreur réseau {exc}") from exc


# --------------------------------------------------------------------- #
# Syslog (RFC 5424)
# --------------------------------------------------------------------- #


class SyslogNotifier(Notifier):
    """Émet des messages syslog RFC 5424 vers UDP ou TCP.

    Standard de facto pour intégration SIEM (Splunk, Elastic,
    QRadar, Sentinel via universal forwarder, etc.).
    """

    name = "syslog"

    def __init__(
        self,
        host: str,
        port: int = 514,
        *,
        min_severity: Severity = Severity.INFO,
        protocol: str = "udp",  # "udp" | "tcp"
        facility: int = 16,  # local0 par défaut (réservé apps)
        app_name: str = "biocybe",
        timeout: float = 3.0,
    ):
        super().__init__(min_severity=min_severity)
        if protocol not in ("udp", "tcp"):
            raise ValueError("protocol doit être 'udp' ou 'tcp'")
        self.host = host
        self.port = port
        self.protocol = protocol
        self.facility = facility
        self.app_name = app_name
        self.timeout = timeout

    def _format(self, event: Event) -> bytes:
        """Format RFC 5424 :
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        """
        pri = self.facility * 8 + event.severity.syslog_severity()
        ts = event.timestamp
        hostname = socket.gethostname() or "-"
        procid = "-"
        msgid = event.kind.value
        # STRUCTURED-DATA : on encode le payload en JSON dans un champ
        msg = f"{event.title} — {event.message}"
        try:
            sd = json.dumps(event.payload, ensure_ascii=True, separators=(",", ":"))
            sd_field = f'[biocybe@32473 payload="{sd.replace(chr(34), chr(39))}"]'
        except (TypeError, ValueError):
            sd_field = "-"
        line = f"<{pri}>1 {ts} {hostname} {self.app_name} {procid} {msgid} {sd_field} {msg}\n"
        return line.encode("utf-8", errors="replace")

    def notify(self, event: Event) -> None:
        data = self._format(event)
        try:
            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(data, (self.host, self.port))
                finally:
                    sock.close()
            else:  # tcp
                with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                    s.sendall(data)
        except OSError as exc:
            raise NotifyError(
                f"Syslog : erreur {self.protocol} {self.host}:{self.port} {exc}"
            ) from exc


# --------------------------------------------------------------------- #
# Webhook générique (POST JSON)
# --------------------------------------------------------------------- #


class WebhookNotifier(Notifier):
    """POST JSON vers une URL arbitraire.

    Compatible n8n, Zapier, Cortex XSOAR, scripts custom, Discord
    (l'URL Discord est un format Slack-compatible mais préfère
    WebhookNotifier pour rester explicite).

    L'event entier est sérialisé en JSON dans le body.
    """

    name = "webhook"

    def __init__(
        self,
        url: str,
        *,
        min_severity: Severity = Severity.WARNING,
        timeout: float = 5.0,
        headers: dict[str, str] | None = None,
        session: requests.Session | None = None,
    ):
        super().__init__(min_severity=min_severity)
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL doit être http(s)://")
        if url.startswith("http://"):
            logger.warning(
                "WebhookNotifier sur HTTP non chiffré : %s — privilégier HTTPS en prod.",
                url,
            )
        self.url = url
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.headers.setdefault("Content-Type", "application/json")
        self.headers.setdefault(
            "User-Agent", "BioCybe/0.2 (+https://github.com/servais1983/biocybe)"
        )
        self._session = session or requests.Session()

    def notify(self, event: Event) -> None:
        try:
            resp = self._session.post(
                self.url,
                json=event.to_dict(),
                timeout=self.timeout,
                headers=self.headers,
            )
            if resp.status_code >= 400:
                raise NotifyError(
                    f"Webhook {self.url}: HTTP {resp.status_code} : {resp.text[:200]}"
                )
        except requests.RequestException as exc:
            raise NotifyError(f"Webhook {self.url} : erreur réseau {exc}") from exc
