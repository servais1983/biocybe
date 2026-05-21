"""Tests métriques Prometheus de la mémoire immunitaire (scrape-time)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

_HAS_WEB = all(
    importlib.util.find_spec(m) is not None for m in ("flask", "prometheus_client")
)
pytestmark = pytest.mark.skipif(not _HAS_WEB, reason="extra [web] non installé")


def _seed_memory(db_path: Path):
    from biocybe.memory import VERDICT_BENIGN, VERDICT_MALICIOUS, ImmuneMemory

    mem = ImmuneMemory(db_path)
    mem.remember("a" * 64, indicator_type="sha256", verdict=VERDICT_MALICIOUS)
    mem.remember("b" * 64, indicator_type="sha256", verdict=VERDICT_MALICIOUS)
    mem.remember("c" * 64, indicator_type="sha256", verdict=VERDICT_BENIGN)
    # Un FP confirmé
    mem.set_disposition("b" * 64, "sha256", "confirmed_benign")
    mem.close()


def test_metrics_exposes_memory_gauges(tmp_path):
    from biocybe.api.app import APIConfig, create_app

    db = tmp_path / "mem.db"
    _seed_memory(db)

    cfg = APIConfig(require_auth=False, memory_db_path=str(db))
    app = create_app(cfg)
    client = app.test_client()

    resp = client.get("/metrics")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "biocybe_memory_indicators_total" in body
    assert 'biocybe_memory_indicators_total{verdict="malicious"} 2.0' in body
    assert "biocybe_memory_disposition_total" in body
    # 1 faux positif confirmé
    assert 'biocybe_memory_disposition_total{disposition="confirmed_benign"} 1.0' in body


def test_metrics_no_memory_db_does_not_crash(tmp_path):
    from biocybe.api.app import APIConfig, create_app

    cfg = APIConfig(require_auth=False, memory_db_path=str(tmp_path / "absent.db"))
    app = create_app(cfg)
    client = app.test_client()
    resp = client.get("/metrics")
    # /metrics reste fonctionnel même sans DB mémoire
    assert resp.status_code == 200
