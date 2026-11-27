"""Branches encore ouvertes des petits modules. Fixtures bénignes, aucun réseau."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def test_rules_verify_drops_extra_samples(tmp_path):
    from biocybe.intel.rules import verify_source

    src = tmp_path / "community" / "lab"
    src.mkdir(parents=True)
    (src / "broken.yar").write_text("rule x { condition: ??? }", encoding="utf-8")
    result = verify_source("lab", tmp_path / "community", sample_errors_limit=0)
    assert result.rules_broken == 1
    assert result.sample_errors == []


def test_urlhaus_entry_without_hostname(tmp_path):
    from biocybe.intel.urlhaus import URLHausEntry, update_urlhaus_iocs

    class _Client:
        def fetch_recent(self):
            return [
                URLHausEntry(
                    url_id="1",
                    url="not-a-url",
                    hostname="",
                    date_added="",
                    url_status="offline",
                    threat="fixture",
                    tags=[],
                    reporter="lab",
                )
            ]

    stats = update_urlhaus_iocs(tmp_path, client=_Client())
    hosts = json.loads((tmp_path / "urlhaus" / "hostnames.json").read_text(encoding="utf-8"))
    assert hosts == {}
    assert stats["unique_hostnames"] == 0


def test_format_scorecard_without_unexplained():
    from biocybe.lab import format_scorecard

    card = {
        "executions": 1,
        "detected": 1,
        "detection_rate": 1.0,
        "systemic": 0,
        "missed": 0,
        "latency_median_seconds": None,
        "latency_max_seconds": None,
        "unexplained_incidents": [],
        "results": [
            {
                "result": "local",
                "executed_at": 0,
                "latency_seconds": None,
                "technique": "T0000",
                "host": "lab",
                "test_name": "benign",
            }
        ],
    }
    text = format_scorecard(card)
    assert "à qualifier" not in text


def test_log_handlers_without_file(monkeypatch, tmp_path):
    from biocybe.logging_setup import (
        configure_logging,
        configure_structlog,
        default_log_handlers,
        log_level,
    )

    monkeypatch.setenv("BIOCYBE_LOG_LEVEL", "not-a-level")
    assert log_level() == 20
    monkeypatch.setenv("BIOCYBE_LOG_FORMAT", "text")
    configure_structlog()
    monkeypatch.setenv("BIOCYBE_LOG_FORMAT", "json")
    configure_structlog()
    monkeypatch.setenv("BIOCYBE_LOG_FILE", "")
    handlers = default_log_handlers()
    assert len(handlers) == 1
    monkeypatch.setenv("BIOCYBE_LOG_FILE", str(tmp_path / "biocybe.log"))
    configure_logging(force=True)
    configure_logging(force=False)


def test_injection_root_branch_and_idle_stop(monkeypatch):
    from biocybe.injection_monitor import InjectionMonitor

    mon = InjectionMonitor(interval=2)
    mon.scanner.scan_all = lambda exclude=None: []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert mon.start() is True
    mon.stop(timeout=2)
    InjectionMonitor().stop()


def test_metrics_non_dict_sources_and_idle_stop():
    from biocybe.metrics_daemon import DaemonMetricsServer

    server = DaemonMetricsServer(
        nk_counts_fn=lambda: "nope",
        netmon_iocs_fn=lambda: None,
        memory_stats_fn=lambda: ["nope"],
        inflammation_fn=lambda: "nope",
    )
    families = list(server.build_collector().collect())
    assert families
    server.stop()


def test_bus_cell_cycle_and_unknown_attr():
    import biocybe.inflammation as inflammation
    from biocybe.inflammation.bus_cell import InflammationCell

    cell = InflammationCell(engine=None)
    assert cell._process_cycle() is None
    with pytest.raises(AttributeError):
        _ = inflammation.not_a_real_export


def test_audit_whitespace_tail(tmp_path, monkeypatch):
    from biocybe.audit import INITIAL_HASH, AuditLog, get_default, set_default

    path = tmp_path / "audit.jsonl"
    path.write_text("\n   \n", encoding="utf-8")
    real_chmod = os.chmod

    def deny(target, mode):
        if str(target).endswith("audit.jsonl"):
            raise OSError("chmod")
        return real_chmod(target, mode)

    monkeypatch.setattr(os, "chmod", deny)
    log = AuditLog(path)
    assert log._read_tail_state() == (0, INITIAL_HASH)
    path.write_text("{not-json\n", encoding="utf-8")
    assert AuditLog(path)._read_tail_state() == (0, INITIAL_HASH)
    log.log_path = tmp_path
    assert log._read_tail_state() == (0, INITIAL_HASH)
    monkeypatch.setattr(os, "fsync", lambda *_a, **_k: (_ for _ in ()).throw(OSError("fs")))
    log.log_path = path
    log.append("lab")
    missing = AuditLog(tmp_path / "absent.jsonl")
    assert missing.read_all() == []
    path.write_text("\n{nope\n", encoding="utf-8")
    assert AuditLog(path).read_all() == []
    set_default(None)
    assert get_default() is None


def test_crypto_bad_magic(tmp_path, monkeypatch):
    from biocybe.crypto import (
        KEY_SIZE,
        MAGIC,
        VERSION,
        CryptoError,
        _build_header,
        _parse_header,
        encrypt_file,
        is_encrypted,
        key_to_base64,
        load_key,
    )

    blob = b"XXXX" + bytes([1, 1]) + b"\x00" * 40
    with pytest.raises(CryptoError, match="Magic"):
        _parse_header(blob)
    with pytest.raises(CryptoError, match="tronqué"):
        _parse_header(b"BCE1")
    bad_ver = MAGIC + bytes([9, 1]) + b"\x00" * 40
    with pytest.raises(CryptoError, match="Version"):
        _parse_header(bad_ver)
    bad_alg = MAGIC + bytes([VERSION, 9]) + b"\x00" * 40
    with pytest.raises(CryptoError, match="Algorithme"):
        _parse_header(bad_alg)
    with pytest.raises(ValueError):
        _build_header(b"short", b"\x00" * 16)
    with pytest.raises(ValueError):
        _build_header(b"\x00" * 12, b"short")
    with pytest.raises(ValueError):
        key_to_base64(b"short")
    with pytest.raises(ValueError):
        load_key(b"short")
    key = b"k" * KEY_SIZE
    assert load_key(key_to_base64(key)) == key
    src = tmp_path / "plain.txt"
    src.write_bytes(b"hello")
    real_chmod = os.chmod

    def deny(target, mode):
        if str(target).endswith(".enc"):
            raise OSError("chmod")
        return real_chmod(target, mode)

    monkeypatch.setattr(os, "chmod", deny)
    enc = tmp_path / "plain.enc"
    encrypt_file(src, enc, key=key)
    assert is_encrypted(enc) is True
    assert is_encrypted(tmp_path / "missing.enc") is False


def test_feedback_skips_unknown_incident_and_empty_signature():
    from biocybe.inflammation.feedback import VERDICT_FALSE_POSITIVE, ToleranceModel

    model = ToleranceModel.build(
        {},
        {"missing": {"verdict": VERDICT_FALSE_POSITIVE}},
    )
    assert model.fp_counts == {}
    model = ToleranceModel.build(
        {"i1": {"signals": [{"kind": "lab", "entities": ["pid:1", "host:local"]}]}},
        {"i1": {"verdict": VERDICT_FALSE_POSITIVE}},
    )
    assert model.fp_counts == {}


def test_ioc_lookup_odd_records(tmp_path):
    from biocybe.intel.ioc_lookup import IOCLookup

    db = tmp_path / "db"
    (db / "hashes").mkdir(parents=True)
    (db / "threatfox" / "by_type").mkdir(parents=True)
    (db / "urlhaus").mkdir()
    (db / "hashes" / "signatures.json").write_text(
        json.dumps({"abc": {"confidence": 90}}), encoding="utf-8"
    )
    (db / "threatfox" / "by_type" / "hash.json").write_text(
        json.dumps({"abc": {"confidence": 10}}), encoding="utf-8"
    )
    (db / "urlhaus" / "urls.json").write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    lookup = IOCLookup.from_db(db)
    assert lookup.lookup_hostname("") is None
    assert lookup.lookup_hash("abc") is not None


def test_restore_encrypted_without_hash_check(tmp_path, monkeypatch):
    from biocybe.isolation import MANIFEST_FILENAME, restore_file

    qdir = tmp_path / "quarantine"
    qdir.mkdir()
    (qdir / "stored.bin").write_bytes(b"cipher")
    manifest = [
        {
            "quarantine_id": "q1",
            "stored_filename": "stored.bin",
            "original_path": str(tmp_path / "gone.txt"),
            "sha256": "ab",
            "encrypted": True,
        }
    ]
    (qdir / MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")

    def fake_decrypt(src, dest, key=None, associated_data=None):
        Path(dest).write_bytes(b"clear")

    monkeypatch.setattr("biocybe.crypto.decrypt_file", fake_decrypt)

    def boom(*_a, **_k):
        raise RuntimeError("audit down")

    monkeypatch.setattr("biocybe.audit.audit", boom)
    dest = restore_file("q1", quarantine_dir=qdir, verify_hash=False, key=b"not-a-real-key")
    assert dest.read_bytes() == b"clear"


def test_swarm_skips_blank_indicator_and_bad_signature(tmp_path):
    from biocybe.memory.immune_memory import ImmuneMemory
    from biocybe.swarm.swarm_sync import BUNDLE_VERSION, SwarmSync

    sync = SwarmSync(
        ImmuneMemory(tmp_path / "mem.db"), node_id="lab", swarm_key="test-key-not-secret"
    )
    stats = sync.import_bundle(
        {"version": BUNDLE_VERSION, "node_id": "peer", "hmac": "00", "indicators": [{}]}
    )
    assert stats.signature_failed is True
    rejected = tmp_path / "bad.json"
    rejected.write_text(
        json.dumps({"version": BUNDLE_VERSION, "node_id": "peer", "indicators": []}),
        encoding="utf-8",
    )
    total = sync.import_dir(tmp_path)
    assert total.signature_failed is True
    sync.swarm_key = None
    blank = sync.import_bundle(
        {
            "version": BUNDLE_VERSION,
            "node_id": "peer",
            "indicators": [{"indicator": "", "indicator_type": ""}],
        }
    )
    assert blank.imported == 0


def test_health_heartbeat(tmp_path, monkeypatch):
    from biocybe.health import heartbeat_path, write_heartbeat

    monkeypatch.setenv("BIOCYBE_HEARTBEAT_FILE", str(tmp_path / "hb"))
    assert heartbeat_path() == tmp_path / "hb"
    assert write_heartbeat() is True

    def deny(*_a, **_k):
        raise OSError("ro")

    monkeypatch.setattr(Path, "mkdir", deny)
    assert write_heartbeat(tmp_path / "other" / "hb") is False


def test_memory_verdict_and_disposition(tmp_path):
    from biocybe.memory.immune_memory import (
        VERDICT_BENIGN,
        VERDICT_MALICIOUS,
        VERDICT_SUSPICIOUS,
        ImmuneMemory,
    )

    mem = ImmuneMemory(tmp_path / "mem.db")
    mem.remember("abc", indicator_type="hash", verdict=VERDICT_BENIGN, confidence=10)
    rec = mem.remember("abc", indicator_type="hash", verdict=VERDICT_MALICIOUS, confidence=20)
    assert rec.verdict == VERDICT_MALICIOUS
    with pytest.raises(ValueError):
        mem.set_disposition("abc", "hash", "nope")
    mem.remember("soft", indicator_type="hash", verdict=VERDICT_SUSPICIOUS, confidence=5)
    assert mem.adjust_confidence("soft", 40, "hash") == 40


def test_feed_age_unknown_source_and_bad_json(tmp_path):
    from biocybe.intel.feed_age import _count_iocs_for, _json_list_count

    assert _count_iocs_for(tmp_path, "other") == 0
    assert _json_list_count(tmp_path / "missing.json") == 0
    broken = tmp_path / "urls.json"
    broken.write_text("{", encoding="utf-8")
    assert _json_list_count(broken) == 0


def test_notifier_edge_transports(monkeypatch):
    import requests

    import biocybe.notify.notifier as notifier
    from biocybe.notify.notifier import (
        Event,
        EventKind,
        NotifyError,
        Severity,
        SlackNotifier,
        SyslogNotifier,
        WebhookNotifier,
    )

    event = Event(
        kind=EventKind.SYSTEM,
        severity=Severity.WARNING,
        title="lab",
        message="benign",
        payload={"note": "n" * 250, "blob": {1}},
    )

    class _Resp:
        status_code = 500
        text = "no"

    class _Session:
        def __init__(self, boom=False):
            self.boom = boom

        def post(self, *_a, **_k):
            if self.boom:
                raise requests.RequestException("down")
            return _Resp()

    slack = SlackNotifier("https://hooks.example.invalid/lab", session=_Session())
    with pytest.raises(NotifyError):
        slack.notify(event)
    slack._session = _Session(boom=True)
    with pytest.raises(NotifyError):
        slack.notify(Event(EventKind.SYSTEM, Severity.INFO, "t", "m", payload={"ok": 1}))

    class _Sock:
        def sendall(self, data):
            self.data = data

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    monkeypatch.setattr(notifier.socket, "create_connection", lambda *_a, **_k: _Sock())
    SyslogNotifier("192.0.2.1", protocol="tcp").notify(event)

    hook = WebhookNotifier("http://192.0.2.1/hook", session=_Session())
    with pytest.raises(NotifyError):
        hook.notify(Event(EventKind.SYSTEM, Severity.WARNING, "t", "m"))
    hook._session = _Session(boom=True)
    with pytest.raises(NotifyError):
        hook.notify(Event(EventKind.SYSTEM, Severity.WARNING, "t", "m"))
