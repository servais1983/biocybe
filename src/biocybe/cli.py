"""Point d'entrée CLI de BioCybe.

Expose `main()` qui est lié à la commande `biocybe` après
`pip install`, et utilisable via `python -m biocybe`.

Sous-commandes :
  - (aucune)  → daemon : démarre le noyau et les cellules en continu.
  - scan PATH → scan one-shot d'un fichier ou d'un dossier.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime

import yaml

from . import lymphocytes_b, macrophages
from .biocybe_core import BioCybeCore

# Force UTF-8 sur stdout/stderr (Windows utilise cp1252 par défaut).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("biocybe.log")],
)
logger = logging.getLogger("biocybe.cli")

# État global pour le daemon
_core: BioCybeCore | None = None
_running = True

DEFAULT_CONFIG_PATH = "config/biocybe.yaml"

_BANNER = """
██████╗ ██╗ ██████╗  ██████╗██╗   ██╗██████╗ ███████╗
██╔══██╗██║██╔═══██╗██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝
██████╔╝██║██║   ██║██║      ╚████╔╝ ██████╔╝█████╗
██╔══██╗██║██║   ██║██║       ╚██╔╝  ██╔══██╗██╔══╝
██████╔╝██║╚██████╔╝╚██████╗   ██║   ██████╔╝███████╗
╚═════╝ ╚═╝ ╚═════╝  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝

Le système immunitaire numérique libre, modulaire et explicable.
"""


def _load_config(config_path: str) -> dict | None:
    try:
        with open(config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f)
        logger.info("Configuration chargée depuis %s", config_path)
        return config
    except Exception as exc:
        logger.error("Erreur lors du chargement de la configuration : %s", exc)
        return None


def _setup_logging_from_config(config: dict) -> None:
    log_level_str = config.get("core", {}).get("log_level", "INFO")
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    for handler in logging.root.handlers:
        handler.setLevel(log_level)
    logging.root.setLevel(log_level)
    logger.setLevel(log_level)
    logger.info("Niveau de journalisation défini à %s", log_level_str)


def _handle_signal(signum, _frame) -> None:
    global _running, _core
    name = {signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, str(signum))
    logger.info("Signal %s reçu, arrêt du système en cours...", name)
    _running = False
    if _core:
        _core.stop()


def _create_required_directories() -> None:
    for d in (
        "db",
        "db/signatures",
        "db/signatures/hashes",
        "db/signatures/yara",
        "db/memory",
        "db/metrics",
        "logs",
        "quarantine",
        "models",
        "models/behavior",
        "models/network",
        "rules",
        "rules/firewall",
        "rules/yara",
        "templates",
        "templates/recovery",
    ):
        os.makedirs(d, exist_ok=True)
    logger.info("Structure de répertoires créée")


def _init_core(config: dict) -> BioCybeCore | None:
    try:
        core = BioCybeCore()
        if config.get("cells", {}).get("autoload", True):
            enabled = config.get("cells", {}).get("enabled_types", [])
            if "macrophage" in enabled:
                logger.info("Chargement des cellules Macrophages")
                for cell in macrophages.create_cells(config):
                    core.register_cell(cell)
            if "b_cell" in enabled:
                logger.info("Chargement des cellules Lymphocytes B")
                for cell in lymphocytes_b.create_cells(config):
                    core.register_cell(cell)
            if "t_cell" in enabled:
                # Import paresseux : sklearn n'est pas une dép core.
                try:
                    from . import lymphocytes_t

                    logger.info("Chargement des cellules Lymphocytes T")
                    for cell in lymphocytes_t.create_cells(config):
                        core.register_cell(cell)
                except Exception as exc:  # MLDepsMissing ou autre
                    logger.warning(
                        "Lymphocytes T non chargés : %s. "
                        "Pour activer la détection comportementale : "
                        "pip install biocybe[ml]",
                        exc,
                    )
        return core
    except Exception as exc:
        logger.error("Erreur lors de l'initialisation du noyau : %s", exc)
        return None


# --- Sous-commande : scan ------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan one-shot d'un fichier ou d'un dossier."""
    from .scanner import format_report, scan_path

    try:
        verdicts = scan_path(
            args.path,
            recursive=not args.no_recursive,
            quarantine=args.quarantine,
            dry_run=args.dry_run,
        )
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = [
            {
                "path": str(v.path),
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
            for v in verdicts
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(format_report(verdicts))
        if args.dry_run and args.quarantine:
            print(
                "\n[DRY-RUN actif] aucun fichier n'a été déplacé. "
                "Retirez --dry-run pour activer la quarantaine."
            )

    return 1 if any(v.is_malicious for v in verdicts) else 0


# --- Sous-commande : quarantine ------------------------------------------


def cmd_quarantine_list(args: argparse.Namespace) -> int:
    from .isolation import list_quarantine

    entries = list_quarantine(args.quarantine_dir)
    if args.json:
        print(json.dumps(entries, indent=2, ensure_ascii=False))
        return 0

    if not entries:
        print("Quarantaine vide.")
        return 0

    print(f"{len(entries)} entrée(s) en quarantaine :\n")
    for e in entries:
        print(f"  ID       : {e['quarantine_id']}")
        print(f"  Original : {e['original_path']}")
        print(f"  Raison   : {e['reason']}")
        print(f"  Date     : {e['quarantined_at']}")
        print(f"  SHA-256  : {e['sha256']}")
        print(f"  Stocké   : {e['stored_filename']}")
        print()
    return 0


def cmd_intel_update(args: argparse.Namespace) -> int:
    """Met à jour les bases de signatures depuis les feeds de threat intel."""
    from .intel import AbuseChAuthMissing, update_signatures_from_malwarebazaar

    try:
        stats = update_signatures_from_malwarebazaar(
            db_path=args.db_path,
            selector=args.selector,
        )
    except AbuseChAuthMissing as exc:
        print(f"Auth manquante : {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Échec mise à jour : {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(stats, indent=2, ensure_ascii=False))
    else:
        print(
            f"MalwareBazaar : {stats['fetched']} échantillons récupérés, "
            f"{stats['added']} ajoutés, {stats['updated']} mis à jour. "
            f"Total signatures : {stats['total']}."
        )
    return 0


def cmd_intel_rules_list(args: argparse.Namespace) -> int:
    from .intel import list_sources

    sources = list_sources()
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "name": s.name,
                        "description": s.description,
                        "license": s.license,
                        "url": s.zipball_url,
                    }
                    for s in sources
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print(f"{len(sources)} source(s) YARA communautaire(s) disponible(s) :\n")
    for s in sources:
        print(f"  [{s.name}]")
        print(f"    {s.description}")
        print(f"    Licence : {s.license}")
        print(f"    URL     : {s.zipball_url}")
        print()
    print("Utiliser : biocybe intel rules update --source <name>")
    return 0


def cmd_intel_rules_update(args: argparse.Namespace) -> int:
    from .intel import KNOWN_SOURCES, download_source

    sources_to_update = [args.source] if args.source else list(KNOWN_SOURCES.keys())

    if not args.yes:
        names = ", ".join(sources_to_update)
        print(
            f"Cela va télécharger {len(sources_to_update)} source(s) : {names}\n"
            "Les règles seront placées dans rules/yara/community/<source>/.\n"
            "Re-lance avec --yes pour confirmer."
        )
        return 1

    results = []
    for name in sources_to_update:
        try:
            res = download_source(name, dest_dir=args.dest)
            results.append(res)
            print(
                f"[{name}] {res.files_extracted} règles ({res.bytes_written / 1024:.0f} Ko), "
                f"{res.skipped_files} ignorées -> {res.output_dir}"
            )
        except Exception as exc:
            print(f"[{name}] échec : {exc}", file=sys.stderr)

    if args.verify:
        from .intel import verify_source

        print("\nVérification de la compilation YARA :")
        for res in results:
            v = verify_source(res.source, dest_dir=args.dest)
            ratio = (v.rules_ok / v.total * 100) if v.total else 0
            print(
                f"  [{v.source}] {v.rules_ok}/{v.total} règles compilent "
                f"({ratio:.0f} %), {v.rules_broken} cassées (ignorées par BCell)"
            )
    return 0


def cmd_tcell_train(args: argparse.Namespace) -> int:
    """Entraîne une TCell sur le système actuel pendant N secondes.

    Pour la prod : à lancer pendant une période représentative
    d'activité **normale** (heures ouvrées habituelles, pas pendant
    une migration ou un incident).
    """
    try:
        from .lymphocytes_t import TCell
    except Exception as exc:  # MLDepsMissing
        print(f"Erreur : {exc}", file=sys.stderr)
        return 4

    cfg = {
        "model_dir": args.model_dir,
        "scan_interval_seconds": args.interval,
        "training_samples": 10_000_000,  # on dépasse jamais — on s'arrête sur durée
        "contamination": args.contamination,
    }
    cell = TCell(name=args.name, config=cfg)

    n_samples = max(1, int(args.duration / args.interval))
    print(
        f"Entraînement TCell '{cell.name}' : {n_samples} échantillons "
        f"sur ~{args.duration:.0f}s, contamination={args.contamination}"
    )
    print("Garde le système dans son comportement nominal pendant ce temps.")

    last_print = 0.0
    for i in range(n_samples):
        cell.collect_one()
        # Progression toutes les ~2 s sans spammer
        now = time.time()
        if now - last_print > 2.0 or i == n_samples - 1:
            print(f"  collecté {i + 1}/{n_samples} ({(i + 1) * 100 // n_samples} %)")
            last_print = now
        # Attente entre 2 collectes
        time.sleep(args.interval)

    try:
        cell.train_from_buffer()
    except ValueError as exc:
        print(f"Échec entraînement : {exc}", file=sys.stderr)
        return 5

    info = cell.tcell_model
    print(
        f"\nModèle entraîné sur {info.n_samples} échantillons, "
        f"persisté dans {args.model_dir}/model.joblib"
    )
    print(f"État : {cell.state}")
    if args.json:
        print(
            json.dumps(
                {
                    "trained_at": info.trained_at,
                    "n_samples": info.n_samples,
                    "contamination": info.contamination,
                    "model_dir": str(args.model_dir),
                },
                indent=2,
            )
        )
    return 0


def cmd_tcell_status(args: argparse.Namespace) -> int:
    try:
        from .lymphocytes_t import TCellModel
    except Exception as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 4

    try:
        info = TCellModel.load(args.model_dir)
    except FileNotFoundError:
        if args.json:
            print(json.dumps({"state": "no_model", "model_dir": str(args.model_dir)}))
        else:
            print(f"Aucun modèle dans {args.model_dir}. Entraîne avec `biocybe tcell train`.")
        return 0

    if args.json:
        print(
            json.dumps(
                {
                    "state": "ready",
                    "trained_at": info.trained_at,
                    "n_samples": info.n_samples,
                    "contamination": info.contamination,
                    "version": info.version,
                    "features": info.feature_names,
                },
                indent=2,
            )
        )
    else:
        print("TCell modèle :")
        print(f"  Entraîné le        : {info.trained_at}")
        print(f"  Sur N échantillons : {info.n_samples}")
        print(f"  Contamination      : {info.contamination}")
        print(f"  Version            : {info.version}")
        print(f"  Features           : {len(info.feature_names)}")
    return 0


def _setup_audit_log_from_config(config: dict) -> None:
    """Active l'audit log immuable si `audit.enabled: true` en config."""
    audit_cfg = (config or {}).get("audit") or {}
    if not audit_cfg.get("enabled"):
        return
    try:
        from . import audit as _audit

        path = audit_cfg.get("path", "logs/audit.jsonl")
        _audit.set_default(_audit.AuditLog(path))
        _audit.audit(
            "system_startup",
            actor="biocybe.cli",
            details={"version": _audit.__name__, "config_path": path},
        )
        logger.info("Audit log immuable activé : %s", path)
    except Exception as exc:
        logger.error("Audit log non activé : %s", exc)


def cmd_crypto_generate_key(args: argparse.Namespace) -> int:
    """Génère une clé AES-256 aléatoire encodée base64.

    Usage typique :
        export BIOCYBE_QUARANTINE_KEY="$(biocybe crypto generate-key)"
    """
    from .crypto import generate_key, key_to_base64

    key = generate_key()
    b64 = key_to_base64(key)
    if args.json:
        print(json.dumps({"key_base64": b64, "key_size_bytes": len(key)}))
    elif args.export:
        print(f"export BIOCYBE_QUARANTINE_KEY={b64}")
    else:
        print(b64)
        print(
            "\n# Cette clé chiffrera tes quarantaines en AES-256-GCM.",
            file=sys.stderr,
        )
        print(
            "# Conserve-la dans un secret manager (Vault, AWS Secrets Manager…) :",
            file=sys.stderr,
        )
        print(
            "# si tu la perds, les fichiers en quarantaine deviennent IRRÉCUPÉRABLES.",
            file=sys.stderr,
        )
        print(
            f"# Exporte via : export {('BIOCYBE_QUARANTINE_KEY')}=...",
            file=sys.stderr,
        )
    return 0


def cmd_audit_show(args: argparse.Namespace) -> int:
    """Affiche les N dernières entrées d'audit."""
    from . import audit as _audit

    log = _audit.AuditLog(args.path)
    entries = log.read_all()
    if args.action:
        entries = [e for e in entries if e.action == args.action]
    if args.limit and args.limit > 0:
        entries = entries[-args.limit :]

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "seq": e.seq,
                        "ts": e.ts,
                        "actor": e.actor,
                        "action": e.action,
                        "outcome": e.outcome,
                        "details": e.details,
                        "prev_hash": e.prev_hash,
                        "self_hash": e.self_hash,
                    }
                    for e in entries
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    if not entries:
        print("Audit log vide.")
        return 0

    print(f"{len(entries)} entrée(s) :")
    for e in entries:
        det = json.dumps(e.details, ensure_ascii=False)
        if len(det) > 80:
            det = det[:77] + "..."
        print(f"  #{e.seq:>5} {e.ts}  {e.actor:25} {e.action:25} {e.outcome}  {det}")
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Vérifie l'intégrité de la chaîne de hash du log d'audit."""
    from . import audit as _audit

    log = _audit.AuditLog(args.path)
    ok, errors = log.verify()
    n = len(log.read_all())
    if ok:
        print(f"Audit log OK : {n} entrée(s), chaîne SHA-256 cohérente.")
        return 0
    print(f"AUDIT LOG ALTÉRÉ : {len(errors)} anomalie(s) détectée(s) sur {n} entrée(s).")
    for err in errors[:20]:
        print(f"  - {err}")
    if len(errors) > 20:
        print(f"  ... {len(errors) - 20} autres anomalies non affichées")
    return 2


def _build_notifier_manager_from_config(config: dict):
    """Construit un NotifierManager depuis `config.notify` et le branche
    en hook isolation. Retourne (manager, count) ou (None, 0)."""
    notify_cfg = (config or {}).get("notify") or {}
    if not notify_cfg:
        return None, 0
    try:
        from .isolation import set_notify_hook
        from .notify import build_from_config
    except Exception as exc:
        logger.warning("Notifier non disponible : %s", exc)
        return None, 0

    mgr = build_from_config(notify_cfg)
    if not mgr.notifiers:
        return mgr, 0

    # Adapte le hook isolation (kwargs string) -> Event typé
    from .notify import Event, EventKind, Severity

    def _hook(kind: str, severity: str, title: str, message: str, payload: dict) -> None:
        try:
            ek = EventKind(kind)
        except ValueError:
            ek = EventKind.SYSTEM
        try:
            sev = Severity(severity)
        except ValueError:
            sev = Severity.INFO
        mgr.notify(Event(kind=ek, severity=sev, title=title, message=message, payload=payload))

    set_notify_hook(_hook)
    return mgr, len(mgr.notifiers)


def cmd_notify_test(args: argparse.Namespace) -> int:
    """Envoie un Event de test à tous les notifiers configurés.

    Charge la config YAML (idem daemon), construit le NotifierManager,
    envoie un event synchrone, affiche le rapport (qui a OK / failed).
    """
    config = _load_config(args.config) or {}
    notify_cfg = config.get("notify") or {}

    if not notify_cfg:
        print(
            "Aucune section `notify:` dans la config. Exemple :\n"
            "  notify:\n"
            "    slack:\n"
            "      webhook_url: https://hooks.slack.com/services/...\n"
            "      min_severity: warning",
            file=sys.stderr,
        )
        return 2

    try:
        from .notify import Event, EventKind, NotifierManager, Severity, build_from_config
    except Exception as exc:
        print(f"Module notify indisponible : {exc}", file=sys.stderr)
        return 4

    mgr: NotifierManager = build_from_config(notify_cfg)
    if not mgr.notifiers:
        print(
            "Aucun notifier configuré (vérifie webhook_url / host / env vars).",
            file=sys.stderr,
        )
        return 3

    print(f"Test des notifiers configurés ({len(mgr.notifiers)}) :")
    for n in mgr.notifiers:
        print(f"  - {n.name} (min_severity={n.min_severity.value})")

    severity_str = (args.severity or "warning").lower()
    try:
        sev = Severity(severity_str)
    except ValueError:
        print(f"Severity inconnue : {severity_str}", file=sys.stderr)
        return 2

    event = Event(
        kind=EventKind.SYSTEM,
        severity=sev,
        title="BioCybe notify test",
        message=args.message or "Message de test envoyé via `biocybe notify test`.",
        source="cli.notify.test",
        payload={"test": True, "host": __import__("socket").gethostname()},
    )
    print(f"\nEnvoi event de test (severity={sev.value})...")
    results = mgr.notify_sync(event)
    print("\nRésultats :")
    any_failure = False
    for name, status in results.items():
        marker = (
            "OK "
            if status == "ok"
            else "ERR"
            if status.startswith(("failed", "unexpected"))
            else "-- "
        )
        print(f"  [{marker}] {name}: {status}")
        if marker == "ERR":
            any_failure = True
    mgr.shutdown()
    return 1 if any_failure else 0


def cmd_notify_list(args: argparse.Namespace) -> int:
    """Liste les notifiers actuellement configurés."""
    config = _load_config(args.config) or {}
    notify_cfg = config.get("notify") or {}

    if not notify_cfg:
        print("Aucune section `notify:` dans la config.")
        return 0

    try:
        from .notify import build_from_config
    except Exception as exc:
        print(f"Module notify indisponible : {exc}", file=sys.stderr)
        return 4

    mgr = build_from_config(notify_cfg)
    if not mgr.notifiers:
        print("Section `notify:` présente mais aucun notifier valide configuré.")
        print("Vérifie : webhook_url / host définis et atteignables.")
        return 0

    if args.json:
        print(
            json.dumps(
                [{"name": n.name, "min_severity": n.min_severity.value} for n in mgr.notifiers],
                indent=2,
            )
        )
    else:
        print(f"{len(mgr.notifiers)} notifier(s) configuré(s) :")
        for n in mgr.notifiers:
            print(f"  - {n.name:10} min_severity={n.min_severity.value}")
    return 0


def cmd_api_serve(args: argparse.Namespace) -> int:
    """Démarre l'API REST de BioCybe.

    Auth Bearer token obligatoire (env BIOCYBE_API_TOKEN), sauf si
    `--no-auth` est passé (mode dev uniquement, refusé en prod par
    l'application).
    """
    try:
        from .api import APIConfig, run_dev, run_production
    except Exception as exc:
        print(f"Erreur : module API indisponible ({exc}).", file=sys.stderr)
        print("Installer les dépendances web : pip install biocybe[web]", file=sys.stderr)
        return 4

    cfg = APIConfig(
        host=args.host,
        port=args.port,
        token=args.token,
        require_auth=not args.no_auth,
        cors_origins=args.cors_origin or None,
        quarantine_dir=args.quarantine_dir,
        workers=args.workers,
        metrics_enabled=not args.no_metrics,
    )

    try:
        if args.dev:
            run_dev(cfg)
        else:
            run_production(cfg)
    except RuntimeError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 5
    except KeyboardInterrupt:
        print("\nArrêt API.", file=sys.stderr)
    return 0


def cmd_tcell_evaluate(args: argparse.Namespace) -> int:
    """Évalue l'état système courant avec la TCell entraînée."""
    try:
        from .lymphocytes_t import TCell
    except Exception as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 4

    cell = TCell(name=args.name, config={"model_dir": args.model_dir})
    if cell.state != "armed":
        print(
            f"TCell non armée (état={cell.state}). Lance `biocybe tcell train` d'abord.",
            file=sys.stderr,
        )
        return 2

    explanation = cell.evaluate()
    if args.json:
        print(json.dumps(explanation.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(explanation.human_summary())
    return 0 if not explanation.is_anomaly else 1


def cmd_intel_rules_verify(args: argparse.Namespace) -> int:
    from .intel import verify_source

    try:
        v = verify_source(args.source, dest_dir=args.dest)
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        print(
            "Télécharge d'abord la source : "
            f"biocybe intel rules update --source {args.source} --yes",
            file=sys.stderr,
        )
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "source": v.source,
                    "ok": v.rules_ok,
                    "broken": v.rules_broken,
                    "total": v.total,
                    "sample_errors": [{"file": f, "error": e} for f, e in v.sample_errors],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    ratio = (v.rules_ok / v.total * 100) if v.total else 0
    print(
        f"Source '{v.source}' : {v.rules_ok}/{v.total} règles compilent "
        f"({ratio:.0f} %), {v.rules_broken} cassées."
    )
    if v.sample_errors:
        print("\nÉchantillon d'erreurs (les règles cassées sont ignorées par BCell) :")
        for f, e in v.sample_errors:
            print(f"  - {f}: {e}")
    return 0


def cmd_quarantine_restore(args: argparse.Namespace) -> int:
    from .isolation import QuarantineIntegrityError, restore_file

    try:
        dest = restore_file(
            args.quarantine_id,
            destination=args.to,
            quarantine_dir=args.quarantine_dir,
            verify_hash=not args.no_verify,
            remove_from_manifest=not args.keep_manifest,
        )
    except KeyError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 3
    except QuarantineIntegrityError as exc:
        print(f"Intégrité compromise : {exc}", file=sys.stderr)
        print("Utilisez --no-verify pour forcer (forensique uniquement).", file=sys.stderr)
        return 4
    except FileExistsError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 5

    print(f"Fichier restauré : {dest}")
    return 0


# --- Sous-commande par défaut : daemon -----------------------------------


def cmd_daemon(args: argparse.Namespace) -> int:
    """Démarre le noyau et les cellules en continu jusqu'à Ctrl+C."""
    global _core, _running

    config = _load_config(args.config)
    if not config:
        return 1

    _setup_logging_from_config(config)
    _create_required_directories()

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    _core = _init_core(config)
    if not _core:
        return 1

    # Phase 2.4.a : audit log immuable (opt-in via config.audit.enabled)
    _setup_audit_log_from_config(config)

    # Phase 2.3.b : wire-up des notifiers depuis config.notify
    notify_mgr, notifier_count = _build_notifier_manager_from_config(config)
    if notifier_count:
        logger.info(
            "%d notifier(s) sortants actifs : %s",
            notifier_count,
            ", ".join(n.name for n in notify_mgr.notifiers),
        )

    logger.info("Démarrage du système BioCybe...")
    _core.start()

    # ---- Real-time watcher (Phase 2.2.a) ----
    # Le watcher tourne en plus du noyau et alimente les détections
    # temps-réel via la même BCell que celle utilisée par `scan`.
    watcher = None
    watch_dirs: list[str] = list(getattr(args, "watch", []) or [])
    if not watch_dirs:
        # Fallback : lire depuis config si pas d'arg CLI
        watch_dirs = config.get("core", {}).get("watch_directories", []) or []

    if watch_dirs:
        from .lymphocytes_b import BCell
        from .scanner import sync_yara_rules
        from .watcher import FileSystemWatcher

        sync_yara_rules()  # assure que les règles sont à jour avant le watcher
        rt_cell = BCell("realtime_watcher")
        watcher = FileSystemWatcher(
            watch_dirs,
            cell=rt_cell,
            quarantine_on_match=args.watch_quarantine,
            dry_run=args.watch_dry_run,
        )
        watcher.start()

    print(_BANNER)
    print(f"Système démarré à {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Cellules actives : {len(_core.cells)}")
    print(f"Types de cellules : {', '.join(_core.cell_types.keys())}")
    if watch_dirs:
        if args.watch_dry_run:
            rt_mode = "DRY-RUN"
        elif args.watch_quarantine:
            rt_mode = "QUARANTINE"
        else:
            rt_mode = "ALERT-ONLY"
        print(f"Watcher temps-réel : {len(watch_dirs)} dossier(s), mode {rt_mode}")
    print("Appuyez sur Ctrl+C pour arrêter le système")

    try:
        interval = config.get("core", {}).get("state_save_interval", 300)
        last_save = time.time()
        while _running:
            now = time.time()
            if now - last_save >= interval:
                _core.save_status()
                last_save = now
            time.sleep(1)
    except Exception as exc:
        logger.error("Erreur dans la boucle principale : %s", exc)
    finally:
        if watcher is not None:
            watcher.stop()
        if _core and _core.active:
            logger.info("Arrêt du système BioCybe...")
            _core.stop()
        if notify_mgr is not None:
            try:
                notify_mgr.shutdown(wait=False)
            except Exception:
                pass
        logger.info("Système BioCybe arrêté")

    return 0


# --- Parser --------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="biocybe",
        description="BioCybe — Système de cyberdéfense bio-inspiré",
    )
    parser.add_argument(
        "-c",
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Chemin vers le fichier de configuration",
    )
    parser.add_argument("--debug", action="store_true", help="Active le mode debug")
    # Flags du daemon par défaut (utilisables sans sous-commande).
    # Noms distincts des flags `scan` pour éviter les ambiguïtés argparse.
    parser.add_argument(
        "--watch",
        action="append",
        metavar="DIR",
        help="Dossier à surveiller en temps réel (répétable). "
        "Sinon utilise core.watch_directories de la config.",
    )
    parser.add_argument(
        "--watch-quarantine",
        action="store_true",
        dest="watch_quarantine",
        help="Mettre en quarantaine les détections temps-réel du watcher.",
    )
    parser.add_argument(
        "--watch-dry-run",
        action="store_true",
        dest="watch_dry_run",
        help="Mode évaluation pour le watcher : détecte sans quarantine. "
        "Combine avec --watch-quarantine pour simuler.",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser(
        "scan",
        help="Scanne un fichier ou un dossier (one-shot)",
    )
    scan_p.add_argument("path", help="Fichier ou dossier à analyser")
    scan_p.add_argument(
        "--no-recursive", action="store_true", help="Ne pas descendre dans les sous-dossiers"
    )
    scan_p.add_argument(
        "--quarantine", action="store_true", help="Mettre en quarantaine les fichiers détectés"
    )
    scan_p.add_argument(
        "--dry-run",
        action="store_true",
        help="N'effectue aucune action destructive (pas de quarantaine effective). "
        "Le rapport indique ce qui aurait été fait. Obligatoire en évaluation SOC.",
    )
    scan_p.add_argument("--json", action="store_true", help="Sortie JSON au lieu du rapport texte")

    # ---------------- quarantine ----------------
    q_p = subparsers.add_parser(
        "quarantine",
        help="Inspecte et gère la quarantaine (list / restore)",
    )
    q_sub = q_p.add_subparsers(dest="q_command", required=True)

    q_list = q_sub.add_parser("list", help="Liste les fichiers en quarantaine")
    q_list.add_argument("--quarantine-dir", default="quarantine", help="Dossier de quarantaine")
    q_list.add_argument("--json", action="store_true", help="Sortie JSON")

    q_restore = q_sub.add_parser(
        "restore",
        help="Restaure un fichier (réversibilité — exigence SOC)",
    )
    q_restore.add_argument("quarantine_id", help="ID retourné par `quarantine list` ou le scan")
    q_restore.add_argument(
        "--to",
        default=None,
        help="Destination personnalisée (défaut : chemin original)",
    )
    q_restore.add_argument("--quarantine-dir", default="quarantine")
    q_restore.add_argument(
        "--no-verify",
        action="store_true",
        help="Ne pas vérifier l'intégrité SHA-256 (forensique uniquement, déconseillé)",
    )
    q_restore.add_argument(
        "--keep-manifest",
        action="store_true",
        help="Garder l'entrée dans le manifeste après restauration (audit trail)",
    )

    # ---------------- intel ----------------
    intel_p = subparsers.add_parser(
        "intel",
        help="Threat intel : signatures hash (abuse.ch) et règles YARA communautaires",
    )
    intel_sub = intel_p.add_subparsers(dest="intel_command", required=True)

    # intel update : alimenté par abuse.ch (anciennement seul)
    intel_up = intel_sub.add_parser(
        "update",
        help="Télécharge les nouveaux IOC depuis abuse.ch MalwareBazaar",
    )
    intel_up.add_argument(
        "--source",
        choices=["malwarebazaar"],
        default="malwarebazaar",
        help="Source à interroger (autres prévues : urlhaus, threatfox)",
    )
    intel_up.add_argument(
        "--selector",
        default="100",
        help="MalwareBazaar selector : 'time' (60 min), '100' ou '1000' derniers",
    )
    intel_up.add_argument(
        "--db-path",
        default="db/signatures",
        help="Dossier de signatures BioCybe (défaut : db/signatures)",
    )
    intel_up.add_argument("--json", action="store_true")

    # intel rules : règles YARA communautaires opt-in (Phase 2.2.c)
    intel_rules_p = intel_sub.add_parser(
        "rules",
        help="Gère les règles YARA communautaires opt-in (signature-base, yara-rules)",
    )
    intel_rules_sub = intel_rules_p.add_subparsers(dest="rules_command", required=True)

    rules_list = intel_rules_sub.add_parser("list", help="Liste les sources connues")
    rules_list.add_argument("--json", action="store_true")

    rules_update = intel_rules_sub.add_parser(
        "update",
        help="Télécharge une ou toutes les sources (opt-in : exige --yes)",
    )
    rules_update.add_argument(
        "--source",
        help="Nom d'une source spécifique (sinon : toutes)",
    )
    rules_update.add_argument(
        "--dest",
        default="rules/yara/community",
        help="Dossier de destination (défaut : rules/yara/community)",
    )
    rules_update.add_argument(
        "--yes",
        action="store_true",
        help="Confirme le téléchargement (obligatoire — opt-in explicite)",
    )
    rules_update.add_argument(
        "--verify",
        action="store_true",
        help="Vérifie la compilation après téléchargement",
    )

    rules_verify = intel_rules_sub.add_parser(
        "verify",
        help="Vérifie quelles règles d'une source compilent",
    )
    rules_verify.add_argument("source", help="Nom de la source à vérifier")
    rules_verify.add_argument("--dest", default="rules/yara/community")
    rules_verify.add_argument("--json", action="store_true")

    # ---------------- tcell (Lymphocyte T — détection comportementale ML) -----
    tcell_p = subparsers.add_parser(
        "tcell",
        help="Lymphocyte T : détection d'anomalies comportementales (IsolationForest)",
    )
    tcell_sub = tcell_p.add_subparsers(dest="tcell_command", required=True)

    tcell_train = tcell_sub.add_parser(
        "train",
        help="Entraîne la TCell sur l'activité système courante (durée configurable)",
    )
    tcell_train.add_argument(
        "--duration",
        type=float,
        default=180.0,
        help="Durée d'entraînement en secondes (défaut 180 = 3 min). "
        "Pour la prod : 1800-3600s pendant une période 'normale' typique.",
    )
    tcell_train.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Intervalle entre 2 échantillons en secondes (défaut 5)",
    )
    tcell_train.add_argument(
        "--contamination",
        type=float,
        default=0.01,
        help="Fraction d'anomalies attendue dans le baseline (défaut 0.01 = 1%%)",
    )
    tcell_train.add_argument(
        "--model-dir",
        default="models/t_cell",
        help="Dossier de persistance du modèle",
    )
    tcell_train.add_argument("--name", default="t_cell_main")
    tcell_train.add_argument("--json", action="store_true")

    tcell_status = tcell_sub.add_parser(
        "status",
        help="Affiche l'état du modèle TCell persisté",
    )
    tcell_status.add_argument("--model-dir", default="models/t_cell")
    tcell_status.add_argument("--json", action="store_true")

    tcell_eval = tcell_sub.add_parser(
        "evaluate",
        help="Évalue l'état système courant. Exit 1 si anomalie détectée.",
    )
    tcell_eval.add_argument("--model-dir", default="models/t_cell")
    tcell_eval.add_argument("--name", default="t_cell_main")
    tcell_eval.add_argument("--json", action="store_true")

    # ---------------- api (Phase 2.3 — intégration SIEM/SOAR) ----------------
    api_p = subparsers.add_parser(
        "api",
        help="API REST HTTP pour intégration SIEM/SOAR (Phase 2.3)",
    )
    api_sub = api_p.add_subparsers(dest="api_command", required=True)

    api_serve = api_sub.add_parser(
        "serve",
        help="Démarre l'API HTTP. Auth Bearer token via env BIOCYBE_API_TOKEN.",
    )
    api_serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="Adresse d'écoute (défaut 127.0.0.1 ; 0.0.0.0 pour exposer)",
    )
    api_serve.add_argument("--port", type=int, default=8080)
    api_serve.add_argument(
        "--token",
        default=None,
        help="Token Bearer (sinon lu depuis env BIOCYBE_API_TOKEN)",
    )
    api_serve.add_argument(
        "--no-auth",
        action="store_true",
        help="DÉSACTIVE l'auth. DEV UNIQUEMENT, refusé par défaut en prod.",
    )
    api_serve.add_argument(
        "--cors-origin",
        action="append",
        metavar="ORIGIN",
        help="Origine CORS autorisée (répétable). Par défaut : CORS désactivé.",
    )
    api_serve.add_argument(
        "--quarantine-dir",
        default="quarantine",
        help="Dossier de quarantaine que l'API gère",
    )
    api_serve.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Nombre de workers/threads WSGI (défaut 4)",
    )
    api_serve.add_argument(
        "--no-metrics",
        action="store_true",
        help="Désactive /metrics (Prometheus)",
    )
    api_serve.add_argument(
        "--dev",
        action="store_true",
        help="Utilise le serveur Flask de dev (PAS de prod, single-thread)",
    )

    # ---------------- notify (Phase 2.3.b — webhooks sortants) ---------------
    notify_p = subparsers.add_parser(
        "notify",
        help="Notifications sortantes : Slack / syslog / webhook générique",
    )
    notify_sub = notify_p.add_subparsers(dest="notify_command", required=True)

    notify_list = notify_sub.add_parser(
        "list", help="Liste les notifiers configurés dans la config YAML"
    )
    notify_list.add_argument("--json", action="store_true")

    notify_test = notify_sub.add_parser(
        "test", help="Envoie un event de test à tous les notifiers configurés"
    )
    notify_test.add_argument(
        "--severity",
        default="warning",
        choices=["debug", "info", "notice", "warning", "error", "critical"],
        help="Sévérité de l'event de test (défaut warning)",
    )
    notify_test.add_argument("--message", default=None, help="Message personnalisé")

    # ---------------- audit (Phase 2.4.a — log immuable compliance) ----------
    audit_p = subparsers.add_parser(
        "audit",
        help="Audit log immuable (compliance SOC2 / ISO 27001)",
    )
    audit_sub = audit_p.add_subparsers(dest="audit_command", required=True)

    audit_show = audit_sub.add_parser("show", help="Affiche les dernières entrées")
    audit_show.add_argument("--path", default="logs/audit.jsonl", help="Chemin du log")
    audit_show.add_argument("--limit", type=int, default=50, help="Nombre max d'entrées")
    audit_show.add_argument("--action", default=None, help="Filtre par type d'action")
    audit_show.add_argument("--json", action="store_true")

    audit_verify = audit_sub.add_parser(
        "verify", help="Vérifie l'intégrité de la chaîne de hash (anti-tampering)"
    )
    audit_verify.add_argument("--path", default="logs/audit.jsonl")

    # ---------------- crypto (Phase 2.4.b) ----------------------------------
    crypto_p = subparsers.add_parser(
        "crypto",
        help="Outillage clés / chiffrement AES-256-GCM pour la quarantaine",
    )
    crypto_sub = crypto_p.add_subparsers(dest="crypto_command", required=True)

    gen_key = crypto_sub.add_parser(
        "generate-key",
        help="Génère une clé AES-256 base64 (à mettre en BIOCYBE_QUARANTINE_KEY)",
    )
    gen_key.add_argument(
        "--export",
        action="store_true",
        help="Sortie au format `export BIOCYBE_QUARANTINE_KEY=...`",
    )
    gen_key.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        logger.debug("Mode debug activé")

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "quarantine":
        if args.q_command == "list":
            return cmd_quarantine_list(args)
        if args.q_command == "restore":
            return cmd_quarantine_restore(args)
    if args.command == "intel":
        if args.intel_command == "update":
            return cmd_intel_update(args)
        if args.intel_command == "rules":
            if args.rules_command == "list":
                return cmd_intel_rules_list(args)
            if args.rules_command == "update":
                return cmd_intel_rules_update(args)
            if args.rules_command == "verify":
                return cmd_intel_rules_verify(args)
    if args.command == "tcell":
        if args.tcell_command == "train":
            return cmd_tcell_train(args)
        if args.tcell_command == "status":
            return cmd_tcell_status(args)
        if args.tcell_command == "evaluate":
            return cmd_tcell_evaluate(args)
    if args.command == "api" and args.api_command == "serve":
        return cmd_api_serve(args)
    if args.command == "notify":
        if args.notify_command == "list":
            return cmd_notify_list(args)
        if args.notify_command == "test":
            return cmd_notify_test(args)
    if args.command == "audit":
        if args.audit_command == "show":
            return cmd_audit_show(args)
        if args.audit_command == "verify":
            return cmd_audit_verify(args)
    if args.command == "crypto" and args.crypto_command == "generate-key":
        return cmd_crypto_generate_key(args)
    return cmd_daemon(args)


if __name__ == "__main__":
    sys.exit(main())
