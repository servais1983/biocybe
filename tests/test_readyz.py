"""Tests Phase 3.c : Kubernetes readiness probe `/readyz`.

Vérifie que :
  - /readyz est accessible sans auth (compatible K8s readinessProbe)
  - Retourne 200 + détail JSON quand tous les checks passent
  - Retourne 503 + détail quand un check échoue
  - Chaque check individuel (quarantine, yara, metrics, auth) est
    correctement reflété
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

pytest.importorskip("flask", reason="API REST requiert biocybe[web]")


TEST_TOKEN = "test-token-not-secret-just-deterministic"


@pytest.fixture
def working_dir(tmp_path, monkeypatch):
    """CWD isolé + règles YARA présentes."""
    rules_src = ROOT / "rules" / "yara"
    rules_dst = tmp_path / "rules" / "yara"
    rules_dst.mkdir(parents=True)
    for r in rules_src.glob("*.yar"):
        (rules_dst / r.name).write_bytes(r.read_bytes())
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def app_with_auth(working_dir):
    from biocybe.api import APIConfig, create_app

    cfg = APIConfig(
        token=TEST_TOKEN,
        require_auth=True,
        quarantine_dir=str(working_dir / "quarantine"),
    )
    app = create_app(cfg)
    app.config.update(TESTING=True)
    return app


def test_readyz_no_auth_required(app_with_auth):
    """`/readyz` doit être accessible SANS Bearer token (K8s probe)."""
    client = app_with_auth.test_client()
    resp = client.get("/readyz")
    # Pas 401 même sans header
    assert resp.status_code in (200, 503)
    body = resp.get_json()
    assert "status" in body
    assert "checks" in body


def test_readyz_returns_200_when_all_checks_pass(app_with_auth, working_dir):
    """Setup propre = tous les checks passent."""
    # Crée le quarantine dir pour que le check writable passe
    (working_dir / "quarantine").mkdir()

    client = app_with_auth.test_client()
    resp = client.get("/readyz")
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["status"] == "ready"
    assert all(c["ok"] for c in body["checks"].values()), body["checks"]


def test_readyz_includes_uptime(app_with_auth):
    client = app_with_auth.test_client()
    resp = client.get("/readyz")
    body = resp.get_json()
    assert "uptime_seconds" in body
    assert isinstance(body["uptime_seconds"], (int, float))
    assert body["uptime_seconds"] >= 0


def test_readyz_quarantine_writable_check(app_with_auth, working_dir):
    """Le check quarantine doit indiquer 'ok' ou 'not yet created'."""
    client = app_with_auth.test_client()
    resp = client.get("/readyz")
    body = resp.get_json()
    qc = body["checks"]["quarantine_dir"]
    assert qc["ok"] is True
    # Soit le dossier existe et est writable, soit pas encore créé
    assert "ok" in qc["detail"] or "not yet" in qc["detail"]


def test_readyz_yara_check_finds_rules(app_with_auth, working_dir):
    """Avec les règles natives copiées, le check YARA doit passer."""
    client = app_with_auth.test_client()
    resp = client.get("/readyz")
    body = resp.get_json()
    yc = body["checks"]["rules_yara_compilable"]
    assert yc["ok"] is True
    assert "source rule(s)" in yc["detail"] or "cache" in yc["detail"]


def test_readyz_yara_check_fails_without_rules(tmp_path, monkeypatch):
    """Sans aucune règle ni cache, le check YARA doit échouer → 503."""
    from biocybe.api import APIConfig, create_app

    monkeypatch.chdir(tmp_path)  # CWD vide, pas de rules/yara
    # On vire aussi le path /home/biocybe — sur la CI Linux ce path
    # n'existe pas, sur dev local non plus.
    cfg = APIConfig(
        token=TEST_TOKEN,
        require_auth=True,
        quarantine_dir=str(tmp_path / "quarantine"),
    )
    app = create_app(cfg)
    client = app.test_client()
    resp = client.get("/readyz")
    body = resp.get_json()
    assert body["status"] == "not_ready", body
    assert resp.status_code == 503
    assert body["checks"]["rules_yara_compilable"]["ok"] is False


def test_readyz_auth_check_fails_without_token(working_dir, monkeypatch):
    """L'app refuse de démarrer sans token quand require_auth=True ;
    mais si elle est créée puis le token est retiré ensuite (ex. env
    rotated), le check auth doit le détecter."""
    from biocybe.api import APIConfig, create_app

    cfg = APIConfig(token=TEST_TOKEN, require_auth=True)
    app = create_app(cfg)
    # Simule la rotation : on vide le token côté config ET env
    app.config["BIOCYBE_API_CONFIG"].token = None
    monkeypatch.delenv("BIOCYBE_API_TOKEN", raising=False)
    (working_dir / "quarantine").mkdir()

    client = app.test_client()
    resp = client.get("/readyz")
    body = resp.get_json()
    auth_check = body["checks"]["auth"]
    assert auth_check["ok"] is False
    assert "no token" in auth_check["detail"]


def test_readyz_token_too_short_warns(working_dir):
    """Token < 16 chars n'est PAS prod-grade — refusé par /readyz."""
    from biocybe.api import APIConfig, create_app

    cfg = APIConfig(token="short123", require_auth=True)
    app = create_app(cfg)
    (working_dir / "quarantine").mkdir()
    client = app.test_client()
    resp = client.get("/readyz")
    body = resp.get_json()
    assert body["checks"]["auth"]["ok"] is False
    assert "too short" in body["checks"]["auth"]["detail"]


def test_readyz_auth_disabled_check_passes(working_dir):
    """En dev mode (require_auth=False), le check auth doit passer."""
    from biocybe.api import APIConfig, create_app

    cfg = APIConfig(require_auth=False)
    app = create_app(cfg)
    (working_dir / "quarantine").mkdir()
    client = app.test_client()
    resp = client.get("/readyz")
    body = resp.get_json()
    auth_check = body["checks"]["auth"]
    assert auth_check["ok"] is True
    assert "dev" in auth_check["detail"].lower()


def test_readyz_503_returns_full_diagnostic(tmp_path, monkeypatch):
    """Quand /readyz fait 503, le body doit lister CHAQUE check
    pour que l'opérateur K8s puisse debugger."""
    from biocybe.api import APIConfig, create_app

    monkeypatch.chdir(tmp_path)
    cfg = APIConfig(token=TEST_TOKEN, require_auth=True)
    app = create_app(cfg)
    client = app.test_client()
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.get_json()
    # Les 4 checks sont présents même en cas d'échec
    assert set(body["checks"].keys()) == {
        "quarantine_dir",
        "rules_yara_compilable",
        "metrics",
        "auth",
    }
    # Au moins un check ko
    assert not all(c["ok"] for c in body["checks"].values())
