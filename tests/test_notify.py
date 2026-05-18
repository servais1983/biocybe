"""Tests Phase 2.3.b : notifications sortantes.

Tests réels, pas tout mocké :
  - Slack/Webhook : mock `requests.Session.post` (pas de réseau)
  - Syslog : vrai socket UDP local + serveur dans un thread
  - Failover : un notifier qui plante n'empêche pas les autres
  - Rate limiting : drops réels quand on dépasse le quota
  - Hook isolation : quarantine_file déclenche bien le hook
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _make_response(status_code: int = 200, text: str = "ok"):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    return r


# --------------------------------------------------------------------- #
# Severity / Event / EventKind
# --------------------------------------------------------------------- #


def test_severity_ordering():
    from biocybe.notify import Severity

    assert Severity.DEBUG.numeric() < Severity.INFO.numeric()
    assert Severity.WARNING.numeric() < Severity.ERROR.numeric()
    assert Severity.ERROR.numeric() < Severity.CRITICAL.numeric()


def test_event_serialization():
    from biocybe.notify import Event, EventKind, Severity

    ev = Event(
        kind=EventKind.QUARANTINE_CREATED,
        severity=Severity.WARNING,
        title="t",
        message="m",
        payload={"k": "v"},
    )
    d = ev.to_dict()
    assert d["kind"] == "quarantine_created"
    assert d["severity"] == "warning"
    assert d["payload"]["k"] == "v"


# --------------------------------------------------------------------- #
# SlackNotifier
# --------------------------------------------------------------------- #


def test_slack_refuses_non_https():
    from biocybe.notify import SlackNotifier

    with pytest.raises(ValueError, match="HTTPS"):
        SlackNotifier("http://example.com/hook")


def test_slack_sends_well_formed_payload():
    from biocybe.notify import Event, EventKind, Severity, SlackNotifier

    session = MagicMock()
    session.post.return_value = _make_response(200, "ok")
    notifier = SlackNotifier(
        "https://hooks.slack.com/services/T/B/X",
        min_severity=Severity.INFO,
        channel="#alerts",
        session=session,
    )
    ev = Event(
        kind=EventKind.SCAN_DETECTION,
        severity=Severity.WARNING,
        title="EICAR detected",
        message="A test file matched",
        payload={"path": "/tmp/x", "family": "EICAR"},
    )
    notifier.notify(ev)

    assert session.post.called
    _args, kwargs = session.post.call_args
    body = kwargs["json"]
    assert body["channel"] == "#alerts"
    assert body["username"] == "BioCybe"
    assert body["attachments"][0]["title"].endswith("EICAR detected")
    fields = {f["title"]: f["value"] for f in body["attachments"][0]["fields"]}
    assert fields["Severity"] == "WARNING"
    assert fields["Kind"] == "scan_detection"
    # Le payload est aussi dans les fields
    assert "path" in fields and fields["path"] == "/tmp/x"


def test_slack_failure_raises_notify_error():
    from biocybe.notify import (
        Event,
        EventKind,
        NotifyError,
        Severity,
        SlackNotifier,
    )

    session = MagicMock()
    session.post.return_value = _make_response(500, "internal")
    notifier = SlackNotifier("https://hooks.slack.com/services/X", session=session)
    ev = Event(
        kind=EventKind.SYSTEM,
        severity=Severity.CRITICAL,
        title="t",
        message="m",
    )
    from biocybe.notify.notifier import NotifyError as _NE

    with pytest.raises((NotifyError, _NE), match="500"):
        notifier.notify(ev)


def test_severity_filter_blocks_below_threshold():
    from biocybe.notify import Event, EventKind, Severity, SlackNotifier

    notifier = SlackNotifier(
        "https://hooks.slack.com/services/X",
        min_severity=Severity.ERROR,
    )
    info_event = Event(kind=EventKind.SYSTEM, severity=Severity.INFO, title="t", message="m")
    error_event = Event(kind=EventKind.SYSTEM, severity=Severity.ERROR, title="t", message="m")
    assert notifier.accepts(info_event) is False
    assert notifier.accepts(error_event) is True


# --------------------------------------------------------------------- #
# SyslogNotifier — vrai socket UDP local
# --------------------------------------------------------------------- #


class _UDPSyslogReceiver:
    """Mini-serveur UDP local pour capter ce qu'envoie SyslogNotifier."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(2.0)
        self.port = self.sock.getsockname()[1]
        self.received: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, _ = self.sock.recvfrom(4096)
                self.received.append(data)
            except TimeoutError:
                continue
            except OSError:
                break

    def stop(self):
        self._stop.set()
        self.sock.close()


@pytest.fixture
def udp_syslog():
    server = _UDPSyslogReceiver()
    server.start()
    yield server
    server.stop()


def test_syslog_udp_sends_rfc5424_format(udp_syslog):
    from biocybe.notify import Event, EventKind, Severity, SyslogNotifier

    notifier = SyslogNotifier(
        "127.0.0.1",
        port=udp_syslog.port,
        protocol="udp",
        min_severity=Severity.INFO,
        app_name="biocybe-test",
    )
    ev = Event(
        kind=EventKind.QUARANTINE_CREATED,
        severity=Severity.WARNING,
        title="EICAR",
        message="Quarantined",
        payload={"family": "EICAR", "sha256": "abc"},
    )
    notifier.notify(ev)
    # Attendre que le serveur UDP ait reçu (le notifier ne retry pas UDP)
    deadline = time.time() + 1.0
    while not udp_syslog.received and time.time() < deadline:
        time.sleep(0.05)
    assert udp_syslog.received, "Aucun datagramme UDP reçu"
    line = udp_syslog.received[0].decode("utf-8", errors="replace")
    # Format : <PRI>VERSION TS HOSTNAME APP-NAME PROCID MSGID SD MSG
    assert line.startswith("<")
    assert ">1 " in line  # VERSION=1
    assert "biocybe-test" in line
    assert "quarantine_created" in line
    assert "EICAR" in line
    # PRI calculé : facility=16 (local0) * 8 + severity=4 (warning) = 132
    assert line.startswith("<132>")


def test_syslog_refuses_invalid_protocol():
    from biocybe.notify import SyslogNotifier

    with pytest.raises(ValueError, match=r"udp.*tcp"):
        SyslogNotifier("127.0.0.1", protocol="quic")


def test_syslog_unreachable_raises_notify_error():
    from biocybe.notify import Event, EventKind, NotifyError, Severity, SyslogNotifier

    # TCP vers un port qui n'écoute pas → connection refused
    notifier = SyslogNotifier("127.0.0.1", port=1, protocol="tcp", timeout=1.0)
    ev = Event(kind=EventKind.SYSTEM, severity=Severity.INFO, title="t", message="m")
    with pytest.raises(NotifyError):
        notifier.notify(ev)


# --------------------------------------------------------------------- #
# WebhookNotifier
# --------------------------------------------------------------------- #


def test_webhook_posts_event_json():
    from biocybe.notify import Event, EventKind, Severity, WebhookNotifier

    session = MagicMock()
    session.post.return_value = _make_response(200, "received")
    notifier = WebhookNotifier(
        "https://soar.example.com/hook",
        headers={"X-Token": "secret"},
        session=session,
    )
    ev = Event(
        kind=EventKind.BEHAVIORAL_ANOMALY,
        severity=Severity.ERROR,
        title="anom",
        message="cpu spike",
    )
    notifier.notify(ev)
    _args, kwargs = session.post.call_args
    assert kwargs["json"]["kind"] == "behavioral_anomaly"
    assert kwargs["headers"]["X-Token"] == "secret"
    assert kwargs["headers"]["Content-Type"] == "application/json"
    assert kwargs["timeout"] == 5.0


def test_webhook_refuses_invalid_scheme():
    from biocybe.notify import WebhookNotifier

    with pytest.raises(ValueError, match="http"):
        WebhookNotifier("ftp://example.com/")


# --------------------------------------------------------------------- #
# NotifierManager : dispatch + failover + rate limit
# --------------------------------------------------------------------- #


def test_manager_sync_failover_isolates_failures():
    """Un notifier qui plante ne doit pas empêcher les autres."""
    from biocybe.notify import (
        Event,
        EventKind,
        NotifierManager,
        NotifyError,
        Severity,
    )
    from biocybe.notify.notifier import Notifier

    class _OkNotifier(Notifier):
        name = "ok"

        def __init__(self):
            super().__init__(min_severity=Severity.DEBUG)
            self.received = []

        def notify(self, event):
            self.received.append(event)

    class _BrokenNotifier(Notifier):
        name = "broken"

        def __init__(self):
            super().__init__(min_severity=Severity.DEBUG)

        def notify(self, event):
            raise NotifyError("simulated outage")

    ok = _OkNotifier()
    broken = _BrokenNotifier()
    mgr = NotifierManager(notifiers=[broken, ok])
    ev = Event(kind=EventKind.SYSTEM, severity=Severity.INFO, title="t", message="m")
    results = mgr.notify_sync(ev)
    assert results["ok"] == "ok"
    assert results["broken"].startswith("failed")
    # Le notifier OK a bien reçu malgré le broken
    assert len(ok.received) == 1
    stats = mgr.stats()
    assert stats["ok"]["sent"] == 1
    assert stats["broken"]["failed"] == 1


def test_manager_severity_filter_per_notifier():
    from biocybe.notify import (
        Event,
        EventKind,
        NotifierManager,
        Severity,
    )
    from biocybe.notify.notifier import Notifier

    class _Recorder(Notifier):
        def __init__(self, name, min_severity):
            super().__init__(min_severity=min_severity)
            self.name = name
            self.received = []

        def notify(self, event):
            self.received.append(event)

    low = _Recorder("low", Severity.DEBUG)
    high = _Recorder("high", Severity.ERROR)
    mgr = NotifierManager(notifiers=[low, high])
    info_ev = Event(kind=EventKind.SYSTEM, severity=Severity.INFO, title="t", message="m")
    results = mgr.notify_sync(info_ev)
    assert results["low"] == "ok"
    assert "skipped" in results["high"]
    assert len(low.received) == 1
    assert len(high.received) == 0


def test_manager_rate_limit_drops_overflow():
    from biocybe.notify import (
        Event,
        EventKind,
        NotifierManager,
        Severity,
    )
    from biocybe.notify.notifier import Notifier

    class _Counter(Notifier):
        name = "counter"

        def __init__(self):
            super().__init__(min_severity=Severity.DEBUG)
            self.sent = 0

        def notify(self, event):
            self.sent += 1

    counter = _Counter()
    # Quota très bas pour le test : 3 events/minute
    mgr = NotifierManager(notifiers=[counter], rate_limit_per_minute=3)
    for _ in range(10):
        mgr.notify(Event(kind=EventKind.SYSTEM, severity=Severity.INFO, title="t", message="m"))
    mgr.shutdown(wait=True)
    # 3 envoyés (limite), 7 droppés
    assert counter.sent == 3
    assert mgr.stats()["counter"]["rate_limited"] == 7


# --------------------------------------------------------------------- #
# build_from_config
# --------------------------------------------------------------------- #


def test_build_from_config_slack_and_syslog():
    from biocybe.notify import NotifierManager, SlackNotifier, SyslogNotifier, build_from_config

    cfg = {
        "slack": {
            "webhook_url": "https://hooks.slack.com/services/T/B/X",
            "min_severity": "warning",
            "channel": "#sec",
        },
        "syslog": {
            "host": "127.0.0.1",
            "port": 514,
            "protocol": "udp",
            "min_severity": "info",
        },
    }
    mgr: NotifierManager = build_from_config(cfg)
    names = sorted(n.name for n in mgr.notifiers)
    assert names == ["slack", "syslog"]
    types = {type(n).__name__ for n in mgr.notifiers}
    assert {SlackNotifier.__name__, SyslogNotifier.__name__} == types


def test_build_from_config_env_substitution(monkeypatch):
    from biocybe.notify import build_from_config

    monkeypatch.setenv("MY_SLACK_HOOK", "https://hooks.slack.com/services/T/B/Z")
    cfg = {"slack": {"webhook_url": "${MY_SLACK_HOOK}", "min_severity": "warning"}}
    mgr = build_from_config(cfg)
    assert len(mgr.notifiers) == 1
    assert mgr.notifiers[0].webhook_url == "https://hooks.slack.com/services/T/B/Z"


def test_build_from_config_skips_invalid():
    from biocybe.notify import build_from_config

    cfg = {
        "slack": {"webhook_url": "http://insecure.example.com/hook"},  # non-HTTPS
    }
    mgr = build_from_config(cfg)
    # Doit avoir loggé l'erreur mais ne pas crash, et ne pas ajouter le notifier
    assert len(mgr.notifiers) == 0


# --------------------------------------------------------------------- #
# Hook isolation : quarantine_file déclenche le hook
# --------------------------------------------------------------------- #


def test_quarantine_hook_fires_on_quarantine(tmp_path, monkeypatch):
    from biocybe import isolation
    from biocybe.isolation import quarantine_file, set_notify_hook

    received = []

    def hook(**kwargs):
        received.append(kwargs)

    set_notify_hook(hook)
    try:
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "evil.bin"
        src.write_text("garbage", encoding="ascii")
        entry = quarantine_file(src, reason="test", detected_by="unit_test")

        assert len(received) == 1
        ev = received[0]
        assert ev["kind"] == "quarantine_created"
        assert ev["severity"] == "warning"
        assert ev["payload"]["quarantine_id"] == entry.quarantine_id
        assert ev["payload"]["detected_by"] == "unit_test"
    finally:
        # Reset le hook pour ne pas polluer les autres tests
        isolation._notify_hook = None


def test_quarantine_hook_exception_is_swallowed(tmp_path, monkeypatch):
    """Un hook qui plante ne doit JAMAIS empêcher la quarantaine."""
    from biocybe import isolation
    from biocybe.isolation import quarantine_file, set_notify_hook

    def broken_hook(**_kwargs):
        raise RuntimeError("hook is on fire")

    set_notify_hook(broken_hook)
    try:
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "evil.bin"
        src.write_text("garbage", encoding="ascii")
        entry = quarantine_file(src, reason="test")
        assert entry.quarantine_id  # la quarantaine a bien réussi
    finally:
        isolation._notify_hook = None
