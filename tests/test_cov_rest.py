"""Branches restantes des petits modules. Fixtures synthétiques, aucun réseau."""

from __future__ import annotations

import io
import json
import logging
import sys
import time
import zipfile
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from biocybe.coverage import (
    RESULT_ORDER,
    Case,
    _replay_case,
    format_report,
    navigator_layer,
)
from biocybe.crypto import TamperedError
from biocybe.intel.abusech import update_signatures_from_malwarebazaar
from biocybe.intel.feed_age import _count_iocs_for, _human_age, _json_keys_count, read_feed_ages
from biocybe.intel.ioc_lookup import IOCLookup, _safe_load_json
from biocybe.intel.rules import download_source, verify_source
from biocybe.intel.threatfox import ThreatFoxIOC, update_threatfox_iocs
from biocybe.intel.urlhaus import URLHausEntry
from biocybe.isolation import (
    QuarantineIntegrityError,
    _quarantine_stored_path,
    _safe_original_name,
    get_quarantine_entry,
    list_quarantine,
    quarantine_file,
    restore_file,
    set_notify_hook,
)
from biocybe.lab import PlannedRun, load_plan, score
from biocybe.logging_setup import build_formatter, default_log_handlers
from biocybe.memory.immune_memory import (
    DISPOSITION_CONFIRMED_BENIGN,
    DISPOSITION_CONFIRMED_MALICIOUS,
    ImmuneMemory,
)
from biocybe.metrics_daemon import DaemonMetricsServer
from biocybe.notify.manager import NotifierManager, build_from_config
from biocybe.notify.notifier import Event, EventKind, Notifier, NotifyError, Severity
from biocybe.process_monitor import load_rules
from biocybe.swarm.swarm_sync import BUNDLE_VERSION, SwarmSync


def test_coverage_partial_branches() -> None:
    rules = load_rules()
    _replay_case(
        Case(
            "T1486",
            "drift",
            "impact",
            "signal_only",
            steps=[{"type": "regen_drift", "path": "/tmp/lab/protected.txt"}],
        ),
        rules,
    )
    _replay_case(
        Case(
            "T0000",
            "inconnu",
            "x",
            "not_detected",
            steps=[{"type": "other"}],
        ),
        rules,
    )
    mem = _replay_case(
        Case(
            "T1055",
            "mem vide",
            "defense-evasion",
            "not_detected",
            steps=[{"type": "memory", "pid": 1, "name": "n", "exe": "/bin/true", "maps": ""}],
        ),
        rules,
    )
    assert mem["signals"] == 0
    conn = _replay_case(
        Case(
            "T1071",
            "confiance illisible",
            "command-and-control",
            "not_detected",
            steps=[{"type": "connection", "ip": "192.0.2.9", "confidence": "nope"}],
        ),
        rules,
    )
    assert conn["signals"] == 0

    counts = {k: 0 for k in RESULT_ORDER}
    counts["local"] = 1
    text = format_report(
        {
            "total": 1,
            "counts": counts,
            "incident_rate": 1.0,
            "results": [
                {
                    "result": "local",
                    "matches_expected": True,
                    "technique": "T1071",
                    "name": "vu",
                    "rules": [],
                    "expected": "local",
                    "note": "",
                }
            ],
        }
    )
    assert "Trous identifiés" not in text
    layer = navigator_layer(
        {
            "results": [
                {"tactic": "chain", "technique": "T1", "result": "local", "note": "skip"},
                {"tactic": "exec", "technique": "T1", "result": "systemic", "note": "haut"},
                {"tactic": "exec", "technique": "T1", "result": "not_detected", "note": "bas"},
            ]
        }
    )
    assert layer["techniques"][0]["score"] == 100


def test_metrics_start_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    srv = DaemonMetricsServer()
    saved = sys.modules.get("prometheus_client")
    sys.modules["prometheus_client"] = None  # type: ignore[assignment]
    try:
        assert srv.start(port=9) is False
    finally:
        if saved is None:
            sys.modules.pop("prometheus_client", None)
        else:
            sys.modules["prometheus_client"] = saved

    import prometheus_client

    def _boom(*_a, **_k):
        raise OSError("port occupé")

    monkeypatch.setattr(prometheus_client, "start_http_server", _boom)
    assert srv.start(port=9) is False

    class _Httpd:
        def shutdown(self) -> None:
            raise RuntimeError("déjà arrêté")

    srv._httpd = _Httpd()
    srv.stop()
    assert srv._httpd is None


def test_isolation_edges(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from pathlib import Path

    qdir = tmp_path / "q"
    qdir.mkdir()
    outside = tmp_path / "out"
    outside.mkdir()
    (outside / "note.txt").write_text("benign", encoding="utf-8")
    (qdir / "linkname").symlink_to(outside / "note.txt")
    with pytest.raises(ValueError):
        _quarantine_stored_path(qdir, "linkname")
    with pytest.raises(ValueError):
        _quarantine_stored_path(qdir, "")
    assert _safe_original_name(Path(".")) == "file"
    assert _safe_original_name(Path("dir/..")) == "file"

    (qdir / "manifest.json").write_text("{", encoding="utf-8")
    assert list_quarantine(qdir) == []
    (qdir / "manifest.json").write_text('{"a": 1}', encoding="utf-8")
    assert list_quarantine(qdir) == []

    src = tmp_path / "note.txt"
    src.write_text("BIOCYBE_COVERAGE_MARKER\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        quarantine_file(tmp_path, quarantine_dir=qdir)

    def _chmod(*_a, **_k):
        raise OSError("chmod")

    monkeypatch.setattr("biocybe.isolation.os.chmod", _chmod)

    def _audit(*_a, **_k):
        raise RuntimeError("audit")

    monkeypatch.setattr("biocybe.audit.audit", _audit)
    entry = quarantine_file(src, quarantine_dir=qdir, reason="lab")
    assert get_quarantine_entry("absent", qdir) is None

    stored = qdir / entry.stored_filename
    stored.write_bytes(b"changed")
    with pytest.raises(QuarantineIntegrityError):
        restore_file(entry.quarantine_id, quarantine_dir=qdir)

    src.write_text("again\n", encoding="utf-8")
    entry2 = quarantine_file(src, quarantine_dir=qdir, reason="lab")
    stored2 = qdir / entry2.stored_filename
    stored2.unlink()
    with pytest.raises(FileNotFoundError):
        restore_file(entry2.quarantine_id, quarantine_dir=qdir)

    src.write_text("third\n", encoding="utf-8")
    key = b"k" * 32
    entry3 = quarantine_file(src, quarantine_dir=qdir, reason="lab", encrypt=True, key=key)
    monkeypatch.setattr(
        "biocybe.crypto.decrypt_file",
        lambda _s, dest, **_k: Path(dest).write_bytes(b"not-the-plain"),
    )
    with pytest.raises(QuarantineIntegrityError):
        restore_file(entry3.quarantine_id, quarantine_dir=qdir, key=key)

    src.write_text("fourth\n", encoding="utf-8")
    monkeypatch.setattr("biocybe.isolation.os.chmod", lambda *_a, **_k: None)
    entry4 = quarantine_file(src, quarantine_dir=qdir, reason="lab")
    dest = tmp_path / "busy.txt"
    dest.write_text("occupied", encoding="utf-8")
    with pytest.raises(FileExistsError):
        restore_file(entry4.quarantine_id, destination=dest, quarantine_dir=qdir)

    def _hook(**_k):
        raise RuntimeError("notify")

    set_notify_hook(_hook)
    try:
        src.write_text("fifth\n", encoding="utf-8")
        entry5 = quarantine_file(src, quarantine_dir=qdir, reason="lab", encrypt=True, key=key)

        def _tamper(_s, _dest, **_k):
            raise TamperedError("lab")

        monkeypatch.setattr("biocybe.crypto.decrypt_file", _tamper)
        with pytest.raises(QuarantineIntegrityError):
            restore_file(entry5.quarantine_id, quarantine_dir=qdir, key=key)

        plain = b"sixth-plain\n"
        src.write_bytes(plain)
        monkeypatch.setattr(
            "biocybe.crypto.decrypt_file",
            lambda _s, dest, **_k: Path(dest).write_bytes(plain),
        )
        entry6 = quarantine_file(src, quarantine_dir=qdir, reason="lab", encrypt=True, key=key)
        restored = restore_file(entry6.quarantine_id, quarantine_dir=qdir, key=key)
        assert restored.is_file()
    finally:
        set_notify_hook(None)


def test_swarm_import_branches(tmp_path) -> None:
    mem = ImmuneMemory(tmp_path / "mem.db")
    sync = SwarmSync(mem, node_id="node-a", swarm_key=None)
    signed = {"version": BUNDLE_VERSION, "node_id": "peer", "hmac": "abc", "indicators": []}
    assert sync.import_bundle(signed).imported == 0
    bad = sync.import_bundle({"version": 99})
    assert bad.errors

    own = {
        "version": BUNDLE_VERSION,
        "node_id": "node-a",
        "indicators": [{"indicator": "x", "indicator_type": "domain"}],
    }
    assert sync.import_bundle(own).skipped_own == 1

    mem.remember("benign.example", indicator_type="domain", verdict="benign", confidence=10)
    mem.set_disposition("benign.example", "domain", DISPOSITION_CONFIRMED_BENIGN)
    skipped = sync.import_bundle(
        {
            "version": BUNDLE_VERSION,
            "node_id": "peer",
            "indicators": [{"indicator": "benign.example", "indicator_type": "domain"}],
        }
    )
    assert skipped.skipped_local_fp == 1

    first = sync.import_bundle(
        {
            "version": BUNDLE_VERSION,
            "node_id": "peer",
            "indicators": [
                {"indicator": "lab.example", "indicator_type": "domain", "confidence": 90},
                "pas-un-dict",
            ],
        }
    )
    assert first.imported == 1
    assert first.errors
    second = sync.import_bundle(
        {
            "version": BUNDLE_VERSION,
            "node_id": "peer",
            "indicators": [
                {
                    "indicator": "lab.example",
                    "indicator_type": "domain",
                    "confidence": 95,
                    "disposition": DISPOSITION_CONFIRMED_MALICIOUS,
                }
            ],
        }
    )
    assert second.updated == 1
    third = sync.import_bundle(
        {
            "version": BUNDLE_VERSION,
            "node_id": "peer",
            "indicators": [
                {
                    "indicator": "lab.example",
                    "indicator_type": "domain",
                    "disposition": DISPOSITION_CONFIRMED_MALICIOUS,
                }
            ],
        }
    )
    assert third.updated == 1

    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert sync.read_and_import(broken).errors
    missing = tmp_path / "absent.json"
    assert sync.read_and_import(missing).errors
    n = sync.write_bundle(tmp_path / "out" / "bundle.json")
    assert n >= 1


def test_feed_age_edges(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert read_feed_ages(tmp_path / "empty").freshest is None
    assert read_feed_ages(tmp_path / "empty").oldest is None
    assert _human_age(None) == "never"
    assert _human_age(5).endswith("s")
    assert _human_age(120).endswith("m")
    assert "h" in _human_age(3700)
    assert "d" in _human_age(90000)

    db = tmp_path / "db"
    mb = db / "hashes"
    mb.mkdir(parents=True)
    now = datetime(2026, 1, 2, 12, 0, 0)
    (mb / "last_update.txt").write_text("pas-une-date", encoding="utf-8")
    (mb / "signatures.json").write_text("[1]", encoding="utf-8")
    uh = db / "urlhaus"
    uh.mkdir()
    (uh / "last_update.txt").write_text((now - timedelta(hours=2)).isoformat(), encoding="utf-8")
    (uh / "urls.json").write_text('{"a": 1}', encoding="utf-8")
    tf = db / "threatfox"
    tf.mkdir()
    (tf / "iocs.json").mkdir()
    report = read_feed_ages(db, now=now)
    assert report.freshest is not None
    assert any(f.error for f in report.feeds)

    def _boom(_path):
        raise RuntimeError("count")

    bad_json = tmp_path / "not-json"
    bad_json.write_text("{", encoding="utf-8")
    assert _json_keys_count(bad_json) == 0
    as_dir = tmp_path / "json-dir"
    as_dir.mkdir()
    assert _json_keys_count(as_dir) == 0
    monkeypatch.setattr("biocybe.intel.feed_age._json_keys_count", _boom)
    assert _count_iocs_for(mb, "malwarebazaar") == 0


def test_rules_download_branches(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import biocybe.intel.rules as rules

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("repo-master/yara/", "")
        zf.writestr("repo-master/../evil.yar", "rule e { condition: true }")
        zf.writestr("repo-master/yara/ok.yar", "rule ok { condition: true }")
        zf.writestr("repo-master/yara/ok.yar", "rule ok2 { condition: true }")
        zf.writestr("repo-master/notes/skip.txt", "nope")
        zf.writestr("repo-master/yara/gen_powershell.yar", "rule g { condition: true }")
        zf.writestr("repo-master/yara/big.yar", "rule big { condition: true }\n" + (" " * 80))
        zf.writestr("plain.yar", "rule p { condition: true }")
    payload = buf.getvalue()

    class _Resp:
        content = payload

        def raise_for_status(self) -> None:
            return None

    class _Session:
        def get(self, *_a, **_k):
            return _Resp()

    monkeypatch.setattr(rules, "MAX_RULE_SIZE_BYTES", 40)
    wide = io.BytesIO()
    with zipfile.ZipFile(wide, "w") as zf:
        zf.writestr("repo-master/loose.yar", "rule loose { condition: true }")
    wide_payload = wide.getvalue()

    class _Wide:
        content = wide_payload

        def raise_for_status(self) -> None:
            return None

    class _WideSession:
        def get(self, *_a, **_k):
            return _Wide()

    assert (
        download_source("yara-rules", tmp_path / "wide", session=_WideSession()).files_extracted
        == 1
    )
    result = download_source("signature-base", tmp_path / "rules", session=_Session())
    assert result.files_extracted >= 1
    assert result.skipped_files >= 1

    with pytest.raises(KeyError):
        download_source("nope", tmp_path / "rules", session=_Session())
    monkeypatch.setattr(rules, "MAX_ZIP_SIZE_BYTES", 1)
    with pytest.raises(ValueError):
        download_source("yara-rules", tmp_path / "rules", session=_Session())

    src = tmp_path / "v" / "signature-base"
    src.mkdir(parents=True)
    (src / "good.yar").write_text("rule good { condition: true }\n", encoding="utf-8")
    (src / "bad.yar").write_text("rule bad { condition: ??? }\n", encoding="utf-8")
    checked = verify_source("signature-base", tmp_path / "v")
    assert checked.rules_ok == 1
    assert checked.rules_broken == 1
    with pytest.raises(FileNotFoundError):
        verify_source("signature-base", tmp_path / "missing")


def test_intel_small_branches(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import biocybe.intel.urlhaus as uh

    def _boom(_url):
        raise ValueError("parse")

    monkeypatch.setattr(uh, "urlparse", _boom)
    entry = URLHausEntry.from_csv_row({"url": "http://example.invalid/a", "tags": ""})
    assert entry.hostname == ""

    sample = SimpleNamespace(
        sha256="ab" * 32,
        sha1="cd" * 20,
        md5="ef" * 16,
        to_signature_entry=lambda: {"family": "fixture"},
    )
    db = tmp_path / "mb"
    sig = db / "hashes"
    sig.mkdir(parents=True)
    (sig / "signatures.json").write_text("{", encoding="utf-8")

    class _Client:
        def get_recent(self, **_k):
            return [sample]

    stats = update_signatures_from_malwarebazaar(db, client=_Client())
    assert stats["added"] >= 1
    stats2 = update_signatures_from_malwarebazaar(db, client=_Client())
    assert stats2["updated"] == 0

    class _TF:
        def get_recent(self, **_k):
            return [
                ThreatFoxIOC(
                    "1", "email", "a@example.invalid", "payload", "fixture", 10, "", "", []
                ),
                ThreatFoxIOC("2", "sha256_hash", "aa" * 32, "payload", "fixture", 10, "", "", []),
            ]

    counted = update_threatfox_iocs(tmp_path / "tf", client=_TF())
    assert counted["by_type_counts"].get("other") == 1

    root = tmp_path / "ioc"
    (root / "threatfox" / "by_type").mkdir(parents=True)
    (root / "urlhaus").mkdir()
    (root / "hashes").mkdir()
    (root / "threatfox" / "by_type" / "ip.json").write_text(
        json.dumps(
            {
                "192.0.2.8": "not-a-dict",
                "192.0.2.9:443": {"confidence": 40},
                "203.0.113.5": {"confidence": 10},
            }
        ),
        encoding="utf-8",
    )
    (root / "urlhaus" / "urls.json").write_text(
        json.dumps(["nope", {"url": ""}, {"url": "http://192.0.2.9/a", "hostname": "h"}]),
        encoding="utf-8",
    )
    (root / "urlhaus" / "hostnames.json").write_text(
        json.dumps({"tracked.example": ["http://tracked.example/a"]}),
        encoding="utf-8",
    )
    (root / "hashes" / "signatures.json").write_text(
        json.dumps({("aa" * 32): "not-a-dict"}),
        encoding="utf-8",
    )
    (root / "threatfox" / "by_type" / "hash.json").write_text("{}", encoding="utf-8")
    look = IOCLookup.from_db(root)
    assert look.lookup_url("") is None
    assert look.lookup_url("http://192.0.2.9/a") is not None
    assert look.lookup_url("http://tracked.example/other") is not None
    assert look.lookup_url("http://unknown.example/x") is None
    assert look.lookup_ip("") is None
    assert look.lookup_ip("192.0.2.9:443") is not None
    assert look.lookup_ip("192.0.2.8") is not None
    assert look.lookup_ip("203.0.113.9") is None
    assert look.lookup_ip("203.0.113.5:80") is not None
    assert look.lookup_ip("203.0.113.5:80").to_dict()["ioc_type"] == "ip"
    assert look.lookup_auto("") is None
    assert look.lookup_auto("aa" * 32) is not None
    assert look.lookup_auto("http://192.0.2.9/a") is not None
    assert look.lookup_auto("192.0.2.9") is not None
    assert look.lookup_auto("tracked.example") is not None

    import biocybe.intel.ioc_lookup as ioc

    monkeypatch.setattr(ioc, "urlparse", lambda _v: (_ for _ in ()).throw(ValueError("x")))
    assert look.lookup_url("http://tracked.example/z") is None
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{", encoding="utf-8")
    assert _safe_load_json(corrupt) == {}
    assert _safe_load_json(tmp_path) == {}


def test_lab_plan_and_local_score(tmp_path) -> None:
    plan = tmp_path / "plan.csv"
    plan.write_text("technique,executed_at\n,2026-01-01T00:00:00\n", encoding="utf-8")
    assert load_plan(plan) == []
    bad = tmp_path / "bad.csv"
    bad.write_text("technique,executed_at\nT1003,pas-une-date\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_plan(bad)
    missing = tmp_path / "miss.csv"
    missing.write_text("technique\nT1003\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_plan(missing)

    when = datetime(2026, 1, 1, 12, 0, 0).timestamp()
    card = score(
        [PlannedRun("T1003", when, "lab", "host")],
        {
            "inc-1": {
                "incident_id": "inc-1",
                "severity": "local",
                "mitre": ["T1003.001"],
                "signals": [{"timestamp": when + 5, "mitre": ["T1003.001"]}],
                "kinds": ["process"],
                "disposition": None,
            }
        },
    )
    assert card["results"][0]["result"] == "local"
    assert score([], {})["detection_rate"] == 0.0


def test_logging_text_and_unwritable_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BIOCYBE_LOG_FORMAT", "text")
    assert isinstance(build_formatter(), logging.Formatter)
    monkeypatch.setenv("BIOCYBE_LOG_FILE", str(tmp_path))
    handlers = default_log_handlers()
    assert len(handlers) == 1
    for handler in handlers:
        handler.close()


class _FakeNotifier(Notifier):
    name = "fake"

    def __init__(
        self, mode: str, *, name: str = "fake", minimum: Severity = Severity.DEBUG
    ) -> None:
        super().__init__(min_severity=minimum)
        self.name = name
        self.mode = mode
        self.calls = 0

    def notify(self, event: Event) -> None:
        self.calls += 1
        if self.mode == "notify_error":
            raise NotifyError("echec labo")
        if self.mode == "boom":
            raise RuntimeError("boom")
        if self.mode == "retry":
            self.mode = "ok"
            raise NotifyError("premier essai")


def test_notifier_manager_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    event = Event(EventKind.SYSTEM, Severity.WARNING, "titre", "message")
    quiet = Event(EventKind.SYSTEM, Severity.DEBUG, "bas", "message")
    high = _FakeNotifier("ok", name="high", minimum=Severity.CRITICAL)
    failing = _FakeNotifier("notify_error", name="failing")
    bursting = _FakeNotifier("boom", name="bursting")
    retrying = _FakeNotifier("retry", name="retrying")
    ok = _FakeNotifier("ok", name="ok")
    mgr = NotifierManager(
        [high, ok, failing, bursting],
        retry_attempts=2,
        retry_initial_delay=0.0,
        rate_limit_per_minute=60,
    )
    sync = mgr.notify_sync(quiet)
    assert sync[high.name].startswith("skipped")
    assert sync[ok.name] == "ok"
    assert sync[failing.name].startswith("failed")
    assert sync[bursting.name].startswith("unexpected")
    mgr._send_with_retry(retrying, event)
    assert retrying.calls == 2
    always = _FakeNotifier("notify_error", name="always")
    mgr._send_with_retry(always, event)
    mgr._send_with_retry(_FakeNotifier("boom", name="burst2"), event)

    rejected = NotifierManager(
        [_FakeNotifier("ok", name="high", minimum=Severity.CRITICAL)],
        rate_limit_per_minute=60,
    )
    rejected.notify(quiet)
    rejected.shutdown(wait=True)

    limited = NotifierManager([_FakeNotifier("ok")], rate_limit_per_minute=1)
    limited.notify(event)
    limited.notify(event)
    assert limited.stats()["fake"]["rate_limited"] == 1
    limiter = limited._limiters["fake"]
    limiter._events.appendleft(time.time() - 10_000)
    assert limiter.try_acquire() is False
    limited.shutdown(wait=True)

    mgr._executor.shutdown(wait=False, cancel_futures=True)

    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SYSLOG_HOST", raising=False)
    monkeypatch.delenv("BIOCYBE_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("LAB_HOOK", "https://example.invalid/hook")
    built = build_from_config(
        {
            "slack": {
                "webhook_url": "${LAB_HOOK}",
                "min_severity": Severity.WARNING,
                "channel": "#lab",
            },
            "syslog": {"host": "192.0.2.1", "protocol": "udp", "min_severity": "info"},
            "webhook": [
                {"url": ""},
                {"url": "${LAB_HOOK}", "headers": {"X-Lab": "${LAB_HOOK}"}},
            ],
        }
    )
    assert len(built.notifiers) == 3
    built.shutdown(wait=False)

    empty = build_from_config({})
    empty.shutdown(wait=False)
    no_url = build_from_config(
        {"slack": {"webhook_url": ""}, "syslog": {"host": ""}, "webhook": {"url": ""}}
    )
    no_url.shutdown(wait=False)
    invalid = build_from_config(
        {
            "slack": {"webhook_url": "http://example.invalid/hook", "min_severity": "nope"},
            "syslog": {"host": "192.0.2.1", "protocol": "sctp"},
            "webhook": {"url": "ftp://example.invalid/hook"},
        }
    )
    assert invalid.notifiers == []
    invalid.shutdown(wait=False)
