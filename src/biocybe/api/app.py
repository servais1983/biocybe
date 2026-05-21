"""Application Flask de BioCybe.

Pensée production-SOC :

  - Auth Bearer token obligatoire sur tous les endpoints sauf
    `/healthz`. Token via env `BIOCYBE_API_TOKEN`. Pas de token
    en config file (anti-leak Git).
  - Endpoints destructifs (`POST /quarantine/{id}/restore`,
    `POST /scan` avec `quarantine=true`) gérés explicitement,
    documentés, retournent des codes HTTP standards.
  - Sortie JSON systématique (header `Content-Type: application/json`,
    même pour les erreurs).
  - Endpoint `/metrics` au format Prometheus exposition (scan/quarantine
    counters, alert gauge, scan latency histogram).
  - Logs structurés JSON via structlog (déjà core dep).
  - Pas de DEBUG=True en prod (gardé pour dev uniquement via run_dev).
  - CORS désactivé par défaut, activable via config (multi-domain).
  - Pas de session/cookie : API stateless, tokens uniquement.
"""

from __future__ import annotations

import functools
import hmac
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from flask import Flask, current_app, jsonify, request

from ..isolation import (
    QuarantineIntegrityError,
    get_quarantine_entry,
    list_quarantine,
    restore_file,
)
from ..scanner import scan_path

logger = logging.getLogger("biocybe.api")

API_TOKEN_ENV = "BIOCYBE_API_TOKEN"  # noqa: S105 — nom de l'env var, pas une valeur
API_VERSION = "v1"

# --------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------- #


@dataclass
class APIConfig:
    """Configuration de l'application API."""

    host: str = "127.0.0.1"
    port: int = 8080
    # Si None, lu depuis l'env BIOCYBE_API_TOKEN. Lever en cas d'absence.
    token: str | None = None
    # Si False, l'auth est désactivée (mode dev uniquement, JAMAIS en prod).
    require_auth: bool = True
    # CORS : liste d'origines autorisées. None = pas de header CORS.
    cors_origins: list[str] | None = None
    # Quarantine dir pour les endpoints quarantine
    quarantine_dir: str = "quarantine"
    # Racine des feeds threat intel (Phase 3.g — métriques feed age)
    signatures_db_path: str = "db/signatures"
    # Seuil staleness des feeds (secondes) pour /readyz + gauge stale
    feed_stale_threshold_s: int = 48 * 3600
    # Workers WSGI (waitress/gunicorn)
    workers: int = 4
    # Activer l'endpoint /metrics (Prometheus)
    metrics_enabled: bool = True
    # Stats internes
    started_at: float = field(default_factory=time.time)


# --------------------------------------------------------------------- #
# Métriques Prometheus
# --------------------------------------------------------------------- #


class _Metrics:
    """Wrapper paresseux autour de prometheus_client.

    Utilise un `CollectorRegistry` dédié par instance d'app (pas le
    registry global) pour éviter les collisions quand plusieurs apps
    coexistent dans le même process (tests, multi-tenancy, etc.).

    Permet à l'app de démarrer même si prometheus_client n'est pas
    installé (l'extra `[web]` l'inclut, mais on reste robuste).
    """

    def __init__(self) -> None:
        try:
            from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

            self.registry = CollectorRegistry()
            self.scan_total = Counter(
                "biocybe_scan_total",
                "Nombre total de scans déclenchés via API",
                ["outcome"],  # success | error
                registry=self.registry,
            )
            self.scan_malicious = Counter(
                "biocybe_scan_malicious_total",
                "Nombre de fichiers flaggés malveillants par les scans API",
                registry=self.registry,
            )
            self.quarantine_action = Counter(
                "biocybe_quarantine_action_total",
                "Actions sur la quarantaine",
                ["action"],  # restore | list | get
                registry=self.registry,
            )
            self.scan_duration = Histogram(
                "biocybe_scan_duration_seconds",
                "Latence des scans API",
                buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 120.0),
                registry=self.registry,
            )
            self.api_requests = Counter(
                "biocybe_api_requests_total",
                "Total des requêtes API",
                ["method", "endpoint", "status"],
                registry=self.registry,
            )
            self.quarantine_size = Gauge(
                "biocybe_quarantine_size",
                "Nombre d'entrées actuellement en quarantaine",
                registry=self.registry,
            )
            # Phase 3.g : surveillance fraicheur des feeds threat intel
            self.intel_feed_age = Gauge(
                "biocybe_intel_feed_age_seconds",
                "Age (secondes) du dernier refresh d'un feed threat intel. "
                "Alerter si > 86400 (24h).",
                ["source"],
                registry=self.registry,
            )
            self.intel_feed_iocs = Gauge(
                "biocybe_intel_feed_iocs_total",
                "Nombre d'IOCs presents dans un feed local (estimation).",
                ["source"],
                registry=self.registry,
            )
            self.intel_feed_stale = Gauge(
                "biocybe_intel_feed_stale",
                "1 si le feed est stale (au-dela du seuil), 0 sinon. -1 si jamais recupere.",
                ["source"],
                registry=self.registry,
            )
            self.enabled = True
        except ImportError:
            logger.warning(
                "prometheus_client absent : /metrics renverra 503. "
                "Installer avec : pip install biocybe[web]"
            )
            self.enabled = False
            self.registry = None


# --------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------- #


def _check_auth() -> tuple[bool, str | None]:
    """Vérifie le header `Authorization: Bearer <token>`.

    Retourne (ok, error_message). Utilise hmac.compare_digest pour
    éviter les timing attacks même si on n'est pas en mode passphrase.
    """
    cfg: APIConfig = current_app.config["BIOCYBE_API_CONFIG"]
    if not cfg.require_auth:
        return True, None

    expected = cfg.token or os.environ.get(API_TOKEN_ENV)
    if not expected:
        return False, "API token not configured server-side"

    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return False, "Missing or malformed Authorization header"

    presented = header[len("Bearer ") :]
    if not hmac.compare_digest(presented, expected):
        return False, "Invalid token"
    return True, None


def require_auth(view):
    """Décorateur d'authentification pour les endpoints."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        ok, err = _check_auth()
        if not ok:
            _metrics_track_request(request.method, request.endpoint or "?", 401)
            return jsonify({"error": "unauthorized", "detail": err}), 401
        return view(*args, **kwargs)

    return wrapper


# --------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------- #


def _metrics_track_request(method: str, endpoint: str, status: int) -> None:
    m: _Metrics = current_app.config["BIOCYBE_METRICS"]
    if m.enabled:
        m.api_requests.labels(method=method, endpoint=endpoint, status=str(status)).inc()


def _refresh_feed_age_gauges(m: _Metrics, cfg: APIConfig) -> None:
    """Met à jour les gauges feed age depuis le disque (Phase 3.g).

    Appelé au scrape `/metrics`. Robuste : toute erreur de lecture est
    avalée (les gauges gardent leur dernière valeur), on ne casse jamais
    l'endpoint de métriques pour un feed manquant.
    """
    if not m.enabled:
        return
    try:
        from ..intel.feed_age import read_feed_ages

        report = read_feed_ages(
            cfg.signatures_db_path,
            stale_threshold_s=cfg.feed_stale_threshold_s,
        )
        for feed in report.feeds:
            label = feed.source
            if feed.age_seconds is not None:
                m.intel_feed_age.labels(source=label).set(feed.age_seconds)
                m.intel_feed_stale.labels(source=label).set(1 if feed.stale else 0)
            else:
                # Jamais récupéré : age non défini, stale = -1 (sentinelle)
                m.intel_feed_stale.labels(source=label).set(-1)
            m.intel_feed_iocs.labels(source=label).set(feed.ioc_count)
    except Exception as exc:  # pragma: no cover - défense
        logger.debug("refresh feed age gauges: %s", exc)


def _verdict_to_json(v) -> dict[str, Any]:
    return {
        "path": str(v.path),
        "is_malicious": v.is_malicious,
        "result": v.result.to_dict(),
        "quarantine": (
            {
                "id": v.quarantine.quarantine_id,
                "stored_filename": v.quarantine.stored_filename,
            }
            if v.quarantine
            else ({"dry_run": True} if v.quarantine_dry_run else None)
        ),
    }


# --------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------- #


def create_app(config: APIConfig | None = None) -> Flask:
    """Construit l'application Flask.

    Cette fonction est appelable par tout WSGI : waitress, gunicorn
    (`gunicorn 'biocybe.api:create_app()'`), uwsgi, etc.
    """
    app = Flask("biocybe.api")
    cfg = config or APIConfig()

    # Validation : refuser de démarrer en prod sans token
    if cfg.require_auth:
        token = cfg.token or os.environ.get(API_TOKEN_ENV)
        if not token:
            raise RuntimeError(
                f"API token absent. Définir l'env var {API_TOKEN_ENV} "
                "ou passer token=... dans APIConfig, ou explicitement "
                "require_auth=False (DEV UNIQUEMENT, jamais en prod)."
            )

    app.config["BIOCYBE_API_CONFIG"] = cfg
    app.config["BIOCYBE_METRICS"] = _Metrics()
    # Lock thread-safe pour BCell partagée (les workers waitress
    # appellent scan_file_sync en parallèle ; la lib YARA est
    # thread-safe en lecture mais on lock pour l'init paresseuse).
    import threading as _threading

    app.config["BIOCYBE_BCELL_LOCK"] = _threading.Lock()
    app.config["BIOCYBE_BCELL"] = None  # init paresseux au 1er scan

    # CORS si configuré
    if cfg.cors_origins:
        try:
            from flask_cors import CORS

            CORS(app, origins=cfg.cors_origins, supports_credentials=False)
        except ImportError:
            logger.warning("flask-cors absent ; CORS désactivé.")

    _register_routes(app)
    return app


# --------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------- #


def _register_routes(app: Flask) -> None:
    @app.route("/healthz", methods=["GET"])
    def healthz():
        """Liveness probe (Kubernetes-style). Pas d'auth requise."""
        return jsonify({"status": "ok", "service": "biocybe", "api_version": API_VERSION}), 200

    @app.route("/readyz", methods=["GET"])
    def readyz():
        """Readiness probe Kubernetes-style — peut-on accepter du trafic ?

        **Pas d'auth requise** : K8s scrape avec un sidecar sans token.
        Sécurité : `/readyz` ne révèle aucune info sensible, juste l'état
        de checks fonctionnels (booléens + détails techniques).

        Retourne **HTTP 200** si tous les checks critiques passent,
        **HTTP 503** sinon. Le corps détaille chaque check pour debugging
        et observabilité.

        Checks effectués :
          - quarantine_dir : existe et writable
          - rules_yara_compilable : YARA peut compiler quelque chose
            (cache .yarc présent OU au moins 1 règle source)
          - metrics : prometheus_client OK si metrics_enabled
          - auth : token configuré si require_auth
        """
        cfg: APIConfig = current_app.config["BIOCYBE_API_CONFIG"]

        def _check_quarantine() -> tuple[bool, str]:
            qdir = Path(cfg.quarantine_dir)
            if not qdir.is_dir():
                # Pas un échec : la quarantaine est créée à la 1re mise
                # en quarantaine. On vérifie juste que le parent existe.
                parent = qdir.parent if qdir.parent.exists() else Path.cwd()
                if not os.access(str(parent), os.W_OK):
                    return False, f"parent {parent} not writable"
                return True, f"{qdir} not yet created (will be on first use)"
            if not os.access(str(qdir), os.W_OK):
                return False, f"{qdir} not writable"
            return True, "ok"

        def _check_yara() -> tuple[bool, str]:
            # On accepte 3 états :
            # 1) cache compiled.yarc existe → load rapide au scan
            # 2) rules/yara/ ou db/signatures/yara/ contient au moins 1 .yar
            # 3) sinon : pas prêt
            cache_paths = [
                Path("db/signatures/yara/compiled.yarc"),
                Path("/home/biocybe/db/signatures/yara/compiled.yarc"),
            ]
            for cp in cache_paths:
                if cp.exists():
                    return True, f"cache .yarc found at {cp}"
            sources = []
            for d in (
                Path("rules/yara"),
                Path("/home/biocybe/rules/yara"),
                Path("db/signatures/yara"),
                Path("/home/biocybe/db/signatures/yara"),
            ):
                if d.is_dir():
                    sources.extend(d.rglob("*.yar"))
                    sources.extend(d.rglob("*.yara"))
            if sources:
                return True, f"{len(sources)} source rule(s) found (will compile on first scan)"
            return False, "no YARA rules and no cache — scan will fail"

        def _check_metrics() -> tuple[bool, str]:
            if not cfg.metrics_enabled:
                return True, "disabled by config"
            m: _Metrics = current_app.config["BIOCYBE_METRICS"]
            if not m.enabled:
                return False, "prometheus_client missing (pip install biocybe[web])"
            return True, "ok"

        def _check_auth_config() -> tuple[bool, str]:
            if not cfg.require_auth:
                return True, "disabled (dev mode)"
            token = cfg.token or os.environ.get(API_TOKEN_ENV)
            if not token:
                return False, f"no token configured (env {API_TOKEN_ENV} or APIConfig.token)"
            if len(token) < 16:
                return False, f"token too short ({len(token)} chars, recommend >= 32)"
            return True, "ok"

        def _check_intel_feeds() -> tuple[bool, str]:
            # Non-bloquant pour la readiness : un feed stale ne doit pas
            # sortir le pod du load balancer (le scan signature/YARA marche
            # toujours). On le rapporte en `warn` séparé pour observabilité.
            try:
                from ..intel.feed_age import read_feed_ages

                report = read_feed_ages(
                    cfg.signatures_db_path,
                    stale_threshold_s=cfg.feed_stale_threshold_s,
                )
            except Exception as exc:  # pragma: no cover
                return True, f"feed age check skipped: {exc}"
            if report.all_missing:
                return True, "no intel feeds fetched yet (run: biocybe intel update)"
            stale = [f.source for f in report.feeds if f.stale]
            if stale:
                return True, f"stale feeds: {', '.join(stale)} (refresh recommended)"
            return True, "all feeds fresh"

        checks = {
            "quarantine_dir": _check_quarantine(),
            "rules_yara_compilable": _check_yara(),
            "metrics": _check_metrics(),
            "auth": _check_auth_config(),
        }
        # Check informatif (jamais bloquant) — exposé dans le body mais
        # n'influe pas sur le status_code.
        warnings = {
            "intel_feeds_fresh": _check_intel_feeds(),
        }

        all_ok = all(ok for ok, _ in checks.values())
        status_code = 200 if all_ok else 503
        body = {
            "status": "ready" if all_ok else "not_ready",
            "uptime_seconds": round(time.time() - cfg.started_at, 2),
            "checks": {name: {"ok": ok, "detail": detail} for name, (ok, detail) in checks.items()},
            "warnings": {
                name: {"ok": ok, "detail": detail} for name, (ok, detail) in warnings.items()
            },
        }
        return jsonify(body), status_code

    @app.route("/api/v1/info", methods=["GET"])
    @require_auth
    def info():
        from .. import __version__

        return jsonify(
            {
                "version": __version__,
                "api_version": API_VERSION,
            }
        ), 200

    # ---- Scan -----------------------------------------------------------

    @app.route("/api/v1/scan", methods=["POST"])
    @require_auth
    def scan():
        """Scanne un chemin et retourne les verdicts.

        Body JSON :
            {
              "path": "/path/to/file_or_dir",
              "recursive": true,
              "quarantine": false,
              "dry_run": false
            }
        """
        m: _Metrics = current_app.config["BIOCYBE_METRICS"]
        payload = request.get_json(silent=True) or {}
        target = payload.get("path")
        if not target or not isinstance(target, str):
            _metrics_track_request("POST", "scan", 400)
            return jsonify({"error": "bad_request", "detail": "missing 'path'"}), 400

        recursive = bool(payload.get("recursive", True))
        quarantine = bool(payload.get("quarantine", False))
        dry_run = bool(payload.get("dry_run", False))

        # BCell partagée — évite de recharger les 748 règles YARA à
        # chaque requête (cause de timeout 10s en charge mesurée
        # Phase VALIDATION). Création lazy au 1er scan, lock pour
        # init thread-safe.
        bcell_lock = current_app.config["BIOCYBE_BCELL_LOCK"]
        with bcell_lock:
            bcell = current_app.config.get("BIOCYBE_BCELL")
            if bcell is None:
                from ..lymphocytes_b import BCell
                from ..scanner import sync_yara_rules

                sync_yara_rules()
                bcell = BCell("api_scanner")
                current_app.config["BIOCYBE_BCELL"] = bcell

        start = time.time()
        try:
            verdicts = scan_path(
                target,
                recursive=recursive,
                quarantine=quarantine,
                dry_run=dry_run,
                cell=bcell,  # réutilise la cellule partagée
                sync_rules=False,  # déjà synchronisé au 1er scan
            )
        except FileNotFoundError as exc:
            if m.enabled:
                m.scan_total.labels(outcome="error").inc()
            _metrics_track_request("POST", "scan", 404)
            return jsonify({"error": "not_found", "detail": str(exc)}), 404
        except Exception as exc:
            logger.exception("Scan API failed")
            if m.enabled:
                m.scan_total.labels(outcome="error").inc()
            _metrics_track_request("POST", "scan", 500)
            return jsonify({"error": "internal", "detail": str(exc)}), 500

        duration = time.time() - start
        malicious_count = sum(1 for v in verdicts if v.is_malicious)

        if m.enabled:
            m.scan_total.labels(outcome="success").inc()
            m.scan_duration.observe(duration)
            if malicious_count:
                m.scan_malicious.inc(malicious_count)

        _metrics_track_request("POST", "scan", 200)
        return jsonify(
            {
                "target": target,
                "duration_seconds": duration,
                "total_files": len(verdicts),
                "malicious_files": malicious_count,
                "verdicts": [_verdict_to_json(v) for v in verdicts],
            }
        ), 200

    # ---- Quarantine -----------------------------------------------------

    @app.route("/api/v1/quarantine", methods=["GET"])
    @require_auth
    def quarantine_list():
        cfg: APIConfig = current_app.config["BIOCYBE_API_CONFIG"]
        m: _Metrics = current_app.config["BIOCYBE_METRICS"]
        entries = list_quarantine(cfg.quarantine_dir)
        if m.enabled:
            m.quarantine_action.labels(action="list").inc()
            m.quarantine_size.set(len(entries))
        _metrics_track_request("GET", "quarantine_list", 200)
        return jsonify({"count": len(entries), "entries": entries}), 200

    @app.route("/api/v1/quarantine/<quarantine_id>", methods=["GET"])
    @require_auth
    def quarantine_get(quarantine_id: str):
        cfg: APIConfig = current_app.config["BIOCYBE_API_CONFIG"]
        m: _Metrics = current_app.config["BIOCYBE_METRICS"]
        entry = get_quarantine_entry(quarantine_id, cfg.quarantine_dir)
        if entry is None:
            _metrics_track_request("GET", "quarantine_get", 404)
            return jsonify({"error": "not_found", "id": quarantine_id}), 404
        if m.enabled:
            m.quarantine_action.labels(action="get").inc()
        _metrics_track_request("GET", "quarantine_get", 200)
        return jsonify(entry), 200

    @app.route("/api/v1/quarantine/<quarantine_id>/restore", methods=["POST"])
    @require_auth
    def quarantine_restore(quarantine_id: str):
        """Endpoint DESTRUCTIF : restaure le fichier original."""
        cfg: APIConfig = current_app.config["BIOCYBE_API_CONFIG"]
        m: _Metrics = current_app.config["BIOCYBE_METRICS"]
        payload = request.get_json(silent=True) or {}
        destination = payload.get("destination")
        verify_hash = bool(payload.get("verify_hash", True))
        keep_manifest = bool(payload.get("keep_manifest", False))

        try:
            dest = restore_file(
                quarantine_id,
                destination=destination,
                quarantine_dir=cfg.quarantine_dir,
                verify_hash=verify_hash,
                remove_from_manifest=not keep_manifest,
            )
        except KeyError as exc:
            _metrics_track_request("POST", "quarantine_restore", 404)
            return jsonify({"error": "not_found", "detail": str(exc)}), 404
        except FileNotFoundError as exc:
            _metrics_track_request("POST", "quarantine_restore", 410)
            return jsonify({"error": "gone", "detail": str(exc)}), 410
        except QuarantineIntegrityError as exc:
            _metrics_track_request("POST", "quarantine_restore", 409)
            return jsonify({"error": "integrity", "detail": str(exc)}), 409
        except FileExistsError as exc:
            _metrics_track_request("POST", "quarantine_restore", 409)
            return jsonify({"error": "destination_exists", "detail": str(exc)}), 409

        if m.enabled:
            m.quarantine_action.labels(action="restore").inc()
        _metrics_track_request("POST", "quarantine_restore", 200)
        return jsonify({"id": quarantine_id, "restored_to": str(dest), "ok": True}), 200

    # ---- Métriques Prometheus -------------------------------------------

    @app.route("/metrics", methods=["GET"])
    def metrics():
        m: _Metrics = current_app.config["BIOCYBE_METRICS"]
        cfg: APIConfig = current_app.config["BIOCYBE_API_CONFIG"]
        if not cfg.metrics_enabled or not m.enabled:
            return jsonify({"error": "metrics_disabled"}), 503
        # /metrics ne doit PAS exiger le Bearer token (Prometheus scrape).
        # Cas d'usage : protéger via network policy / mTLS upstream.
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        # Phase 3.g : rafraîchit les gauges feed age au moment du scrape
        # (peu coûteux : lit quelques last_update.txt + compte des clés JSON).
        _refresh_feed_age_gauges(m, cfg)

        # Utilise le registry dédié à cette instance d'app (pas global)
        return generate_latest(m.registry), 200, {"Content-Type": CONTENT_TYPE_LATEST}

    # ---- Error handlers JSON-only ---------------------------------------

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({"error": "method_not_allowed"}), 405

    @app.errorhandler(500)
    def server_error(e):
        logger.exception("Unhandled API error: %s", e)
        return jsonify({"error": "internal"}), 500


# --------------------------------------------------------------------- #
# Lancement (dev + prod)
# --------------------------------------------------------------------- #


def run_dev(config: APIConfig) -> None:
    """Démarrage rapide en serveur Flask de DEV. JAMAIS en prod."""
    app = create_app(config)
    logger.warning(
        "Flask development server — NE PAS utiliser en prod. "
        "Préférer `run_production()` (waitress/gunicorn)."
    )
    app.run(host=config.host, port=config.port, debug=False, use_reloader=False)


def run_production(config: APIConfig) -> None:
    """Démarre l'API derrière un WSGI de prod.

    waitress sur Windows (pas de fork), gunicorn sur Linux/macOS.
    Les deux supportent N workers, timeout, etc.
    """
    import sys as _sys

    app = create_app(config)

    if _sys.platform == "win32":
        try:
            from waitress import serve
        except ImportError as exc:
            raise RuntimeError(
                "waitress requis sur Windows. Installer : pip install biocybe[web]"
            ) from exc
        logger.info(
            "Démarrage waitress sur %s:%s (%d threads)",
            config.host,
            config.port,
            config.workers,
        )
        serve(app, host=config.host, port=config.port, threads=config.workers)
    else:
        try:
            from gunicorn.app.wsgiapp import WSGIApplication
        except ImportError as exc:
            raise RuntimeError("gunicorn requis. Installer : pip install biocybe[web]") from exc

        class _StandaloneApp(WSGIApplication):
            def __init__(self, wsgi_app, options):
                self._wsgi_app = wsgi_app
                self._options = options
                super().__init__()

            def load_config(self):
                for k, v in self._options.items():
                    self.cfg.set(k, v)

            def load(self):
                return self._wsgi_app

        opts = {
            "bind": f"{config.host}:{config.port}",
            "workers": config.workers,
            "worker_class": "sync",
            "timeout": 60,
            "accesslog": "-",
        }
        _StandaloneApp(app, opts).run()
