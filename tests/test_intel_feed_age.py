"""Tests Phase 3.g : âge des feeds threat intel + métriques.

Couvre :
  - read_feed_ages : feeds présents / absents / timestamp invalide
  - calcul age_seconds avec `now` déterministe
  - flag stale selon seuil
  - comptage IOC par source
  - CLI `intel age` exit codes 0/1/2
  - gauges Prometheus peuplées au scrape /metrics
  - /readyz expose le warning intel_feeds_fresh sans bloquer
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _write_feed(db_path: Path, subdir: str, ts: datetime, index_file: str, index_content):
    d = db_path / subdir
    d.mkdir(parents=True, exist_ok=True)
    (d / "last_update.txt").write_text(ts.isoformat(), encoding="utf-8")
    (d / index_file).write_text(json.dumps(index_content), encoding="utf-8")


def test_read_feed_ages_all_present(tmp_path):
    from biocybe.intel.feed_age import read_feed_ages

    now = datetime(2026, 5, 21, 12, 0, 0)
    _write_feed(tmp_path, "hashes", now - timedelta(hours=1), "signatures.json", {"a": 1, "b": 2})
    _write_feed(tmp_path, "urlhaus", now - timedelta(hours=2), "urls.json", [{"url": "x"}])
    _write_feed(
        tmp_path, "threatfox", now - timedelta(hours=3), "iocs.json", [{"id": 1}, {"id": 2}]
    )

    report = read_feed_ages(tmp_path, now=now)
    assert len(report.feeds) == 3
    assert not report.any_stale
    assert not report.all_missing

    by_src = {f.source: f for f in report.feeds}
    assert by_src["malwarebazaar"].age_seconds == 3600
    assert by_src["malwarebazaar"].ioc_count == 2
    assert by_src["urlhaus"].age_seconds == 7200
    assert by_src["urlhaus"].ioc_count == 1
    assert by_src["threatfox"].ioc_count == 2


def test_stale_flag(tmp_path):
    from biocybe.intel.feed_age import read_feed_ages

    now = datetime(2026, 5, 21, 12, 0, 0)
    # MalwareBazaar récent, URLhaus vieux de 3 jours
    _write_feed(tmp_path, "hashes", now - timedelta(hours=1), "signatures.json", {"a": 1})
    _write_feed(tmp_path, "urlhaus", now - timedelta(days=3), "urls.json", [])

    report = read_feed_ages(tmp_path, stale_threshold_s=48 * 3600, now=now)
    by_src = {f.source: f for f in report.feeds}
    assert by_src["malwarebazaar"].stale is False
    assert by_src["urlhaus"].stale is True
    # threatfox jamais récupéré → stale (manquant)
    assert by_src["threatfox"].stale is True
    assert by_src["threatfox"].exists is False
    assert report.any_stale is True


def test_all_missing(tmp_path):
    from biocybe.intel.feed_age import read_feed_ages

    report = read_feed_ages(tmp_path)
    assert report.all_missing is True
    assert report.any_stale is True
    assert all(f.age_seconds is None for f in report.feeds)


def test_invalid_timestamp_is_error(tmp_path):
    from biocybe.intel.feed_age import read_feed_ages

    d = tmp_path / "hashes"
    d.mkdir(parents=True)
    (d / "last_update.txt").write_text("pas une date", encoding="utf-8")

    report = read_feed_ages(tmp_path)
    by_src = {f.source: f for f in report.feeds}
    assert by_src["malwarebazaar"].error is not None
    assert by_src["malwarebazaar"].stale is True  # erreur → traité comme stale


def test_freshest_and_oldest(tmp_path):
    from biocybe.intel.feed_age import read_feed_ages

    now = datetime(2026, 5, 21, 12, 0, 0)
    _write_feed(tmp_path, "hashes", now - timedelta(hours=1), "signatures.json", {})
    _write_feed(tmp_path, "urlhaus", now - timedelta(hours=5), "urls.json", [])

    report = read_feed_ages(tmp_path, now=now)
    assert report.freshest.source == "malwarebazaar"
    assert report.oldest.source == "urlhaus"


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def test_cli_intel_age_fresh(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    db = tmp_path / "db" / "signatures"
    now = datetime.now()
    _write_feed(db, "hashes", now, "signatures.json", {"a": 1})
    _write_feed(db, "urlhaus", now, "urls.json", [{"url": "x"}])
    _write_feed(db, "threatfox", now, "iocs.json", [{"id": 1}])

    monkeypatch.chdir(tmp_path)
    exit_code = main(["intel", "age"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "fresh" in out


def test_cli_intel_age_stale_exit_1(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    db = tmp_path / "db" / "signatures"
    now = datetime.now()
    _write_feed(db, "hashes", now, "signatures.json", {"a": 1})
    _write_feed(db, "urlhaus", now - timedelta(days=5), "urls.json", [])
    _write_feed(db, "threatfox", now, "iocs.json", [{"id": 1}])

    monkeypatch.chdir(tmp_path)
    exit_code = main(["intel", "age", "--stale-after", str(48 * 3600)])
    assert exit_code == 1
    assert "STALE" in capsys.readouterr().out


def test_cli_intel_age_missing_exit_2(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    monkeypatch.chdir(tmp_path)
    exit_code = main(["intel", "age"])
    assert exit_code == 2
    assert "Aucun feed" in capsys.readouterr().out


def test_cli_intel_age_json(tmp_path, monkeypatch, capsys):
    from biocybe.cli import main

    db = tmp_path / "db" / "signatures"
    now = datetime.now()
    _write_feed(db, "hashes", now, "signatures.json", {"a": 1, "b": 2})

    monkeypatch.chdir(tmp_path)
    main(["intel", "age", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert "feeds" in payload
    assert payload["all_missing"] is False
    by_src = {f["source"]: f for f in payload["feeds"]}
    assert by_src["malwarebazaar"]["ioc_count"] == 2


# ----------------------------------------------------------------------
# Prometheus / API
# ----------------------------------------------------------------------


def test_metrics_exposes_feed_age_gauges(tmp_path):
    pytest_importorskip_flask()
    from biocybe.api.app import APIConfig, create_app

    db = tmp_path / "db" / "signatures"
    now = datetime.now()
    _write_feed(db, "hashes", now - timedelta(hours=1), "signatures.json", {"a": 1, "b": 2})
    _write_feed(db, "urlhaus", now - timedelta(days=5), "urls.json", [])

    cfg = APIConfig(
        require_auth=False,
        signatures_db_path=str(db),
        feed_stale_threshold_s=48 * 3600,
    )
    app = create_app(cfg)
    client = app.test_client()

    resp = client.get("/metrics")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "biocybe_intel_feed_age_seconds" in body
    assert 'source="malwarebazaar"' in body
    assert "biocybe_intel_feed_iocs_total" in body
    # urlhaus stale (5 jours > 48h) → gauge stale = 1
    assert 'biocybe_intel_feed_stale{source="urlhaus"} 1.0' in body
    # threatfox jamais récupéré → -1
    assert 'biocybe_intel_feed_stale{source="threatfox"} -1.0' in body


def test_readyz_exposes_intel_warning_without_blocking(tmp_path):
    pytest_importorskip_flask()
    from biocybe.api.app import APIConfig, create_app

    db = tmp_path / "db" / "signatures"
    # Aucun feed → all_missing, mais /readyz ne doit PAS échouer pour ça
    cfg = APIConfig(
        require_auth=False,
        signatures_db_path=str(db),
        token="x" * 32,
    )
    app = create_app(cfg)
    client = app.test_client()

    resp = client.get("/readyz")
    body = resp.get_json()
    assert "warnings" in body
    assert "intel_feeds_fresh" in body["warnings"]
    # Le warning est informatif (ok=True), n'influe pas sur le status
    assert body["warnings"]["intel_feeds_fresh"]["ok"] is True


def pytest_importorskip_flask():
    import importlib

    import pytest

    for mod in ("flask", "prometheus_client"):
        if importlib.util.find_spec(mod) is None:
            pytest.skip(f"{mod} non installé (extra [web])")
