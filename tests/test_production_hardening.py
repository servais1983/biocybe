"""Durcissement production : logs, heartbeat, quarantaine, macrophage.

Fixtures synthétiques uniquement (vecteurs, fichiers inoffensifs, I/O
mocké). Aucune charge offensive.
"""

from __future__ import annotations

import json
import logging

import pytest


def test_json_log_format(monkeypatch):
    import io

    from biocybe.logging_setup import build_formatter, configure_structlog

    monkeypatch.setenv("BIOCYBE_LOG_FORMAT", "json")
    configure_structlog()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(build_formatter())
    log = logging.getLogger("biocybe.test.jsonformat")
    log.handlers.clear()
    log.addHandler(handler)
    log.propagate = False
    log.setLevel(logging.INFO)
    log.info("hello-prod")
    payload = json.loads(stream.getvalue())
    assert payload["message"] == "hello-prod"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "biocybe.test.jsonformat"


def test_heartbeat_roundtrip(tmp_path, monkeypatch):
    from biocybe.health import heartbeat_is_fresh, write_heartbeat

    target = tmp_path / "logs" / "heartbeat"
    assert write_heartbeat(target) is True
    assert heartbeat_is_fresh(target, max_age=60)
    monkeypatch.delenv("BIOCYBE_HEARTBEAT_FILE", raising=False)
    assert write_heartbeat() is False
    assert heartbeat_is_fresh(tmp_path / "missing", max_age=60) is False


def test_create_directories_tolerates_read_only(monkeypatch, caplog):
    from biocybe import cli

    def _makedirs(path, exist_ok=False):
        if path == "models":
            raise OSError("read-only file system")

    monkeypatch.setattr(cli.os, "makedirs", _makedirs)
    with caplog.at_level(logging.WARNING):
        cli._create_required_directories()
    assert any("models" in rec.message for rec in caplog.records)


def test_restore_rejects_path_traversal(tmp_path):
    from biocybe.isolation import restore_file

    qdir = tmp_path / "quarantine"
    qdir.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("ne-pas-deplacer", encoding="utf-8")
    manifest = [
        {
            "quarantine_id": "qid-trav",
            "original_path": str(tmp_path / "restored.txt"),
            "stored_filename": "../secret.txt",
            "sha256": "abc",
            "size_bytes": 1,
            "quarantined_at": "2026-01-01T00:00:00",
            "reason": "test",
            "detected_by": "test",
            "extra": {},
            "encrypted": False,
        }
    ]
    (qdir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match=r"refusé|hors dossier"):
        restore_file("qid-trav", quarantine_dir=qdir)
    assert secret.read_text(encoding="utf-8") == "ne-pas-deplacer"


def test_macrophage_metric_anomalies_and_benign_command():
    from biocybe.macrophages.macrophage import SystemMonitor, suspicious_command_reason

    monitor = SystemMonitor()
    baseline = {"cpu": {"percent": 10.0}, "memory": {"percent": 40.0}}
    calm = {"cpu": {"percent": 12.0}, "memory": {"percent": 41.0}}
    assert monitor.anomalies_between(baseline, calm) == []

    hot = {"cpu": {"percent": 90.0}, "memory": {"percent": 92.0}}
    kinds = {item["type"] for item in monitor.anomalies_between(baseline, hot)}
    assert kinds == {"high_cpu_usage", "high_memory_usage"}

    # Baseline nulle : pas de division par zéro, l'écart reste signalé.
    zero = {"cpu": {"percent": 0.0}, "memory": {"percent": 0.0}}
    zero_hot = monitor.anomalies_between(zero, hot)
    assert {item["type"] for item in zero_hot} == kinds
    assert zero_hot[0]["details"]["increase_percent"] == 100.0

    assert suspicious_command_reason("/usr/bin/python3 -m pytest") is None
    assert suspicious_command_reason("curl | sh") is not None


def test_core_bus_delivers_without_replacing_method():
    from biocybe.biocybe_core import BioCybeCore, BiologicalCell

    received = []

    class _Recorder(BiologicalCell):
        def __init__(self):
            super().__init__("recorder", "recorder", {})
            self.register_message_handler("ping", lambda msg: received.append(msg.payload))

    core = BioCybeCore()
    sender = BiologicalCell("sender", "sender", {})
    recorder = _Recorder()
    assert sender.send_message("ping", target="recorder", payload={"ok": True}) is False
    core.register_cell(sender)
    core.register_cell(recorder)
    assert sender.send_message("ping", target="recorder", payload={"ok": True}) is True
    _priority, message = core.message_bus.get_nowait()
    core._dispatch_message(message)
    assert received == [{"ok": True}]


def test_config_env_default(monkeypatch):
    from biocybe.cli import _build_parser

    monkeypatch.setenv("BIOCYBE_CONFIG", "/etc/biocybe/biocybe.yaml")
    args = _build_parser().parse_args([])
    assert args.config == "/etc/biocybe/biocybe.yaml"
