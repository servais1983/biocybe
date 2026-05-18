"""Tests Phase 2.3.a : API REST.

Tests d'intégration réels via le test client Flask : pas de mock,
les endpoints exécutent le vrai code de scan/quarantaine. EICAR
est créé sur disque, scanné via POST /api/v1/scan, quarantiné
via flag dans la requête, listé via GET, restauré via POST.

L'auth Bearer token est testée explicitement :
  - sans header → 401
  - token incorrect → 401 (et compare_digest → pas de timing leak)
  - token correct → 200
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

pytest.importorskip("flask", reason="API REST requiert biocybe[web]")

TEST_TOKEN = "test-token-not-secret-just-deterministic"

EICAR_PARTS = [
    "X5O!P%@AP[4\\PZX54(P^)7CC)",
    "7}$EICAR-STANDARD-ANTIVIRUS-",
    "TEST-FILE!$H+H*",
]
EICAR_STRING = "".join(EICAR_PARTS)


# --------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------- #


@pytest.fixture
def working_dir(tmp_path, monkeypatch):
    """Dossier isolé avec règles YARA + CWD basculé."""
    rules_src = ROOT / "rules" / "yara"
    rules_dst = tmp_path / "rules" / "yara"
    rules_dst.mkdir(parents=True)
    for rule in rules_src.glob("*.yar"):
        (rules_dst / rule.name).write_bytes(rule.read_bytes())
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def app(working_dir):
    """Application Flask configurée pour les tests, dossier qurarantine = working_dir/quarantine."""
    from biocybe.api import APIConfig, create_app

    cfg = APIConfig(
        token=TEST_TOKEN,
        require_auth=True,
        quarantine_dir=str(working_dir / "quarantine"),
    )
    app = create_app(cfg)
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers():
    return {"Authorization": f"Bearer {TEST_TOKEN}"}


def _make_eicar(directory: Path, name: str = "eicar.com") -> Path:
    f = directory / name
    f.write_text(EICAR_STRING, encoding="ascii")
    return f


# --------------------------------------------------------------------- #
# create_app validation
# --------------------------------------------------------------------- #


def test_create_app_requires_token_in_prod(monkeypatch):
    """En mode auth requise, refuser de démarrer sans token."""
    from biocybe.api import APIConfig, create_app

    monkeypatch.delenv("BIOCYBE_API_TOKEN", raising=False)
    cfg = APIConfig(require_auth=True, token=None)
    with pytest.raises(RuntimeError, match="API token absent"):
        create_app(cfg)


def test_create_app_no_auth_explicit_dev_mode():
    """`require_auth=False` doit fonctionner (dev mode)."""
    from biocybe.api import APIConfig, create_app

    app = create_app(APIConfig(require_auth=False))
    assert app is not None


# --------------------------------------------------------------------- #
# /healthz : pas d'auth
# --------------------------------------------------------------------- #


def test_healthz_no_auth_required(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert body["service"] == "biocybe"


def test_healthz_responds_json_even_without_token(client):
    resp = client.get("/healthz")
    assert resp.is_json
    assert resp.headers["Content-Type"].startswith("application/json")


# --------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------- #


def test_endpoints_require_bearer_token(client):
    resp = client.get("/api/v1/info")
    assert resp.status_code == 401
    body = resp.get_json()
    assert body["error"] == "unauthorized"


def test_endpoints_reject_wrong_token(client):
    resp = client.get("/api/v1/info", headers={"Authorization": "Bearer not-the-right-one"})
    assert resp.status_code == 401


def test_endpoints_reject_malformed_authorization_header(client):
    resp = client.get("/api/v1/info", headers={"Authorization": "wrong-format"})
    assert resp.status_code == 401


def test_info_endpoint_with_valid_token(client, auth_headers):
    resp = client.get("/api/v1/info", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "version" in body
    assert body["api_version"] == "v1"


# --------------------------------------------------------------------- #
# /api/v1/scan
# --------------------------------------------------------------------- #


def test_scan_missing_path_returns_400(client, auth_headers):
    resp = client.post("/api/v1/scan", json={}, headers=auth_headers)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "bad_request"


def test_scan_nonexistent_path_returns_404(client, auth_headers):
    resp = client.post(
        "/api/v1/scan", json={"path": "/nonexistent/path/12345"}, headers=auth_headers
    )
    assert resp.status_code == 404


def test_scan_detects_eicar_real(working_dir, client, auth_headers):
    eicar = _make_eicar(working_dir)
    resp = client.post(
        "/api/v1/scan",
        json={"path": str(eicar), "recursive": False, "quarantine": False},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total_files"] == 1
    assert body["malicious_files"] == 1
    v = body["verdicts"][0]
    assert v["is_malicious"] is True
    assert v["result"]["malware_family"] == "EICAR"
    assert v["quarantine"] is None  # quarantine=False


def test_scan_dry_run_does_not_quarantine(working_dir, client, auth_headers):
    eicar = _make_eicar(working_dir)
    resp = client.post(
        "/api/v1/scan",
        json={"path": str(eicar), "quarantine": True, "dry_run": True},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    v = body["verdicts"][0]
    assert v["is_malicious"] is True
    assert v["quarantine"] == {"dry_run": True}
    # Fichier toujours en place
    assert eicar.exists()


def test_scan_with_quarantine_creates_manifest_entry(working_dir, client, auth_headers):
    eicar = _make_eicar(working_dir)
    resp = client.post(
        "/api/v1/scan",
        json={"path": str(eicar), "quarantine": True, "dry_run": False},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    v = body["verdicts"][0]
    assert v["quarantine"] is not None
    assert "id" in v["quarantine"]
    # Fichier a disparu
    assert not eicar.exists()


# --------------------------------------------------------------------- #
# /api/v1/quarantine
# --------------------------------------------------------------------- #


def test_quarantine_list_empty(client, auth_headers):
    resp = client.get("/api/v1/quarantine", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == 0
    assert body["entries"] == []


def test_quarantine_get_unknown_returns_404(client, auth_headers):
    resp = client.get("/api/v1/quarantine/inexistant_id_12345", headers=auth_headers)
    assert resp.status_code == 404


def test_quarantine_full_lifecycle(working_dir, client, auth_headers):
    """E2E : scan → quarantine → list → get → restore → list."""
    eicar = _make_eicar(working_dir)
    original_path = str(eicar.resolve())

    # 1. Scan + quarantaine
    scan_resp = client.post(
        "/api/v1/scan",
        json={"path": str(eicar), "quarantine": True},
        headers=auth_headers,
    )
    qid = scan_resp.get_json()["verdicts"][0]["quarantine"]["id"]

    # 2. list — voit notre entrée
    list_resp = client.get("/api/v1/quarantine", headers=auth_headers)
    assert list_resp.status_code == 200
    body = list_resp.get_json()
    assert body["count"] == 1
    assert body["entries"][0]["quarantine_id"] == qid

    # 3. get — info détaillée
    get_resp = client.get(f"/api/v1/quarantine/{qid}", headers=auth_headers)
    assert get_resp.status_code == 200
    entry = get_resp.get_json()
    assert entry["quarantine_id"] == qid
    assert "sha256" in entry

    # 4. restore — destructif
    restore_resp = client.post(f"/api/v1/quarantine/{qid}/restore", json={}, headers=auth_headers)
    assert restore_resp.status_code == 200
    body = restore_resp.get_json()
    assert body["ok"] is True
    assert body["restored_to"].endswith("eicar.com")
    assert Path(original_path).exists()

    # 5. list à nouveau — vide
    list2_resp = client.get("/api/v1/quarantine", headers=auth_headers)
    assert list2_resp.get_json()["count"] == 0


def test_restore_unknown_id_returns_404(client, auth_headers):
    resp = client.post(
        "/api/v1/quarantine/inexistant_xyz/restore",
        json={},
        headers=auth_headers,
    )
    assert resp.status_code == 404


def test_restore_destination_exists_returns_409(working_dir, client, auth_headers):
    eicar = _make_eicar(working_dir)
    original_path = eicar.resolve()
    scan_resp = client.post(
        "/api/v1/scan",
        json={"path": str(eicar), "quarantine": True},
        headers=auth_headers,
    )
    qid = scan_resp.get_json()["verdicts"][0]["quarantine"]["id"]

    # Quelqu'un occupe la place
    original_path.write_text("squatter", encoding="utf-8")

    resp = client.post(f"/api/v1/quarantine/{qid}/restore", json={}, headers=auth_headers)
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "destination_exists"


# --------------------------------------------------------------------- #
# /metrics (Prometheus)
# --------------------------------------------------------------------- #


def test_metrics_endpoint_no_auth_required(client):
    """Prometheus scrape : pas de Bearer token (protection upstream)."""
    resp = client.get("/metrics")
    # 200 si prometheus_client présent, 503 sinon
    assert resp.status_code in (200, 503)


def test_metrics_exposes_counters_after_scan(working_dir, client, auth_headers):
    pytest.importorskip("prometheus_client")
    eicar = _make_eicar(working_dir)

    # Avant : pas encore de scan
    resp = client.get("/metrics")
    body = resp.get_data(as_text=True)
    assert "biocybe_scan_total" in body

    # Trigger un scan
    client.post(
        "/api/v1/scan",
        json={"path": str(eicar)},
        headers=auth_headers,
    )

    # Après : compteur incrémenté
    resp = client.get("/metrics")
    body = resp.get_data(as_text=True)
    # Le format Prometheus exposition contient les valeurs
    assert 'biocybe_scan_total{outcome="success"}' in body
    assert "biocybe_scan_duration_seconds" in body
