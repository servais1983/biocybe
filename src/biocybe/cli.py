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
import threading
import time
from datetime import datetime
from pathlib import Path

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
    handlers=[
        logging.StreamHandler(),
        # encoding="utf-8" explicite : sinon Windows utilise cp1252 par
        # défaut et casse les accents — donc logs illisibles dans un
        # SIEM Linux qui s'attend à de l'UTF-8.
        logging.FileHandler("biocybe.log", encoding="utf-8"),
    ],
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
            network_scan=getattr(args, "network_scan", False),
        )
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = [
            {
                "path": str(v.path),
                "result": v.result.to_dict(),
                "network": v.network.to_dict() if v.network else None,
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
    """Met à jour les bases de signatures/IOCs depuis abuse.ch.

    Sources supportées :
      - malwarebazaar : hashes md5/sha1/sha256 d'échantillons
      - urlhaus       : URLs malveillantes (CSV public, pas d'auth requise)
      - threatfox     : IOCs structurés (URL/IP/domaine/hash + famille)
      - all           : toutes les sources ci-dessus
    """
    from .intel import (
        AbuseChAPIError,
        AbuseChAuthMissing,
        update_signatures_from_malwarebazaar,
        update_threatfox_iocs,
        update_urlhaus_iocs,
    )

    sources = ["malwarebazaar", "urlhaus", "threatfox"] if args.source == "all" else [args.source]

    all_stats: dict[str, dict] = {}
    any_error = False

    for src in sources:
        try:
            if src == "malwarebazaar":
                stats = update_signatures_from_malwarebazaar(
                    db_path=args.db_path,
                    selector=args.selector,
                )
                summary = (
                    f"MalwareBazaar : {stats['fetched']} échantillons, "
                    f"{stats['added']} ajoutés, {stats['updated']} mis à jour. "
                    f"Total : {stats['total']}."
                )
            elif src == "urlhaus":
                stats = update_urlhaus_iocs(db_path=args.db_path)
                summary = (
                    f"URLhaus : {stats['fetched']} URLs ({stats['unique_hostnames']} "
                    f"hosts uniques, {stats['online']} online)."
                )
            elif src == "threatfox":
                stats = update_threatfox_iocs(
                    db_path=args.db_path,
                    days=args.threatfox_days,
                )
                bt = stats.get("by_type_counts", {})
                summary = (
                    f"ThreatFox : {stats['fetched']} IOCs "
                    f"({bt.get('hash', 0)} hashes, {bt.get('url', 0)} URLs, "
                    f"{bt.get('domain', 0)} domaines, {bt.get('ip', 0)} IPs)."
                )
            else:
                print(f"Source inconnue : {src}", file=sys.stderr)
                return 2

            all_stats[src] = stats
            if not args.json:
                print(summary)
        except AbuseChAuthMissing as exc:
            print(f"[{src}] auth manquante : {exc}", file=sys.stderr)
            all_stats[src] = {"error": "auth_missing", "detail": str(exc)}
            any_error = True
        except AbuseChAPIError as exc:
            print(f"[{src}] erreur API : {exc}", file=sys.stderr)
            all_stats[src] = {"error": "api_error", "detail": str(exc)}
            any_error = True
        except Exception as exc:
            print(f"[{src}] échec mise à jour : {exc}", file=sys.stderr)
            all_stats[src] = {"error": "unknown", "detail": str(exc)}
            any_error = True

    if args.json:
        print(json.dumps(all_stats, indent=2, ensure_ascii=False))
    return 1 if any_error else 0


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


def _build_network_monitor_service_from_config(config: dict, notify_mgr, *, cli_args=None):
    """Construit un NetworkMonitorService (Phase 3.h) depuis config.netmon.

    Le callback on_match :
      1. écrit une entrée d'audit immuable (si audit actif)
      2. émet un Event vers le NotifierManager (si configuré)

    Activation : config.netmon.enabled OU flag CLI --netmon.
    Retourne le service démarré-able, ou None si désactivé.
    """
    netmon_cfg = (config or {}).get("netmon") or {}
    cli_enabled = bool(getattr(cli_args, "netmon", False))
    if not netmon_cfg.get("enabled", False) and not cli_enabled:
        return None

    try:
        from .network_monitor import NetworkMonitorService
    except Exception as exc:
        logger.warning("NetworkMonitor indisponible : %s", exc)
        return None

    db_path = netmon_cfg.get("db_path", "db/signatures")
    interval = float(getattr(cli_args, "netmon_interval", None) or netmon_cfg.get("interval", 5.0))
    reverse_dns = bool(netmon_cfg.get("reverse_dns", False))

    # Importe l'audit + types notify une seule fois
    from .audit import audit as _audit

    # Cellule NK optionnelle : réponse active si config.nk.enabled +
    # config.nk.auto_respond. Ultra-conservatrice par défaut (dry-run).
    nk_cell = _build_nk_cell_from_config(config)
    nk_auto = bool((config or {}).get("nk", {}).get("auto_respond", False))

    def _on_match(record) -> None:
        hit = record.hit
        details = {
            "pid": record.pid,
            "process_name": record.process_name,
            "process_exe": record.process_exe,
            "remote": record.raddr,
            "ioc_type": hit.ioc_type if hit else None,
            "ioc_value": hit.value if hit else None,
            "source": hit.source if hit else None,
            "malware": hit.malware if hit else None,
            "confidence": hit.confidence if hit else None,
        }
        # 1) Audit immuable (no-op si audit non activé)
        _audit("network_ioc_detected", actor="netmon", outcome="alert", details=details)

        # 2) Notification sortante
        if notify_mgr is not None:
            try:
                from .notify import Event, EventKind, Severity

                conf = hit.confidence if hit else 0
                sev = Severity.CRITICAL if conf >= 90 else Severity.WARNING
                notify_mgr.notify(
                    Event(
                        kind=EventKind.REALTIME_DETECTION,
                        severity=sev,
                        title=f"IOC réseau détecté : {record.process_name} → {record.raddr}",
                        message=(
                            f"Le processus {record.process_name} (pid {record.pid}) "
                            f"contacte {record.raddr}, référencé "
                            f"{hit.source if hit else '?'} "
                            f"(malware={hit.malware if hit else '?'}, conf={conf})."
                        ),
                        payload=details,
                    )
                )
            except Exception as exc:
                logger.error("netmon: notify a échoué : %s", exc)

        # 3) Réponse active NK (optionnelle, conservatrice)
        if nk_cell is not None and nk_auto and record.pid is not None:
            try:
                from .nk_cells import NKDecision

                decision: NKDecision = nk_cell.evaluate(
                    pid=record.pid,
                    process_name=record.process_name,
                    confidence=hit.confidence if hit else 0,
                    reason=f"netmon: {record.process_name} -> {record.raddr} ({hit.source if hit else '?'})",
                )
                nk_cell.respond(decision)
            except Exception as exc:
                logger.error("netmon: réponse NK a échoué : %s", exc)

    service = NetworkMonitorService(
        db_path,
        interval=interval,
        reverse_dns=reverse_dns,
        on_match=_on_match,
    )
    return service


def _build_nk_cell_from_config(config: dict):
    """Construit une NKCell depuis config.nk, ou None si section absente.

    N'active rien tout seul : les garde-fous (enabled, dry_run, allow_kill)
    sont lus depuis la config et restent conservateurs par défaut.
    """
    nk_cfg = (config or {}).get("nk") or {}
    if not nk_cfg:
        return None
    try:
        from .nk_cells import NKAction, NKCell, NKConfig
    except Exception as exc:
        logger.warning("NK cell indisponible : %s", exc)
        return None

    try:
        default_action = NKAction(nk_cfg.get("default_action", "suspend"))
    except ValueError:
        default_action = NKAction.SUSPEND

    cfg = NKConfig(
        enabled=bool(nk_cfg.get("enabled", False)),
        dry_run=bool(nk_cfg.get("dry_run", True)),
        min_confidence=int(nk_cfg.get("min_confidence", 90)),
        default_action=default_action,
        allow_kill=bool(nk_cfg.get("allow_kill", False)),
        max_actions_per_minute=int(nk_cfg.get("max_actions_per_minute", 10)),
    )
    return NKCell(cfg)


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


def cmd_intel_rules_build_cache(args: argparse.Namespace) -> int:
    """Précompile le cache YARA (`compiled.yarc`).

    Usage typique :
      - en provisioning Docker (RUN biocybe intel rules build-cache)
      - en cron quotidien après `intel rules update`
      - manuellement après ajout de règles custom

    Sans cache pré-compilé, le 1er démarrage du daemon prend 1-5 min
    sur Windows + Defender avec 700+ règles. Avec cache, ~200 ms.
    """
    import time as _time

    from .lymphocytes_b.b_cell import SignatureDatabase
    from .scanner import sync_yara_rules

    if not args.skip_sync:
        copied = sync_yara_rules()
        if copied:
            print(f"  + {copied} règle(s) synchronisée(s) depuis rules/yara/")

    db_path = Path(args.db_path)
    if not (db_path / "yara").is_dir():
        print(
            f"Erreur : pas de dossier YARA dans {db_path}/yara. "
            "Lance d'abord `biocybe intel rules update --source signature-base --yes` "
            "ou copie tes règles dans rules/yara/.",
            file=sys.stderr,
        )
        return 2

    # Force la recompilation : supprime le cache existant
    if args.force:
        cache_bin = db_path / "yara" / "compiled.yarc"
        cache_fp = db_path / "yara" / "compiled.fingerprint.json"
        for f in (cache_bin, cache_fp):
            if f.exists():
                f.unlink()

    print(f"Compilation des règles YARA dans {db_path}/yara ...")
    t0 = _time.time()
    # SignatureDatabase.__init__ déclenche _compile_yara_rules qui
    # crée le cache compiled.yarc — pas besoin de stocker l'instance.
    SignatureDatabase(str(db_path))
    duration = _time.time() - t0

    cache_bin = db_path / "yara" / "compiled.yarc"
    cache_fp = db_path / "yara" / "compiled.fingerprint.json"
    if not cache_bin.exists():
        print(
            f"\nERREUR : cache .yarc PAS créé après {duration:.1f}s. "
            "Vérifie qu'au moins 1 règle valide existe.",
            file=sys.stderr,
        )
        return 3

    size_kb = cache_bin.stat().st_size / 1024
    if args.json:
        meta = json.loads(cache_fp.read_text(encoding="utf-8"))
        print(
            json.dumps(
                {
                    "duration_s": round(duration, 2),
                    "cache_bin": str(cache_bin),
                    "cache_size_kb": round(size_kb, 1),
                    **meta,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(f"\nCache compilé en {duration:.1f}s : {cache_bin} ({size_kb:.0f} KB)")
        print(
            f"Au prochain démarrage du daemon, chargement en ~50 ms (au lieu de {duration:.0f}s)."
        )
    return 0


def cmd_intel_lookup(args: argparse.Namespace) -> int:
    """Cherche une valeur dans les feeds IOC indexés localement (Phase 3.e)."""
    from .intel.ioc_lookup import IOCLookup

    lookup = IOCLookup.from_db(args.db_path)
    if lookup.total == 0:
        print(
            "Aucun IOC chargé. Lance d'abord :\n"
            "  biocybe intel update --source all",
            file=sys.stderr,
        )
        return 2

    type_ = args.type
    if type_ == "auto":
        hit = lookup.lookup_auto(args.value)
    elif type_ == "hash":
        hit = lookup.lookup_hash(args.value)
    elif type_ == "hostname":
        hit = lookup.lookup_hostname(args.value)
    elif type_ == "url":
        hit = lookup.lookup_url(args.value)
    elif type_ == "ip":
        hit = lookup.lookup_ip(args.value)
    else:
        print(f"Type inconnu : {type_}", file=sys.stderr)
        return 2

    if hit is None:
        if args.json:
            print(json.dumps({"value": args.value, "match": None}))
        else:
            print(f"Aucun match pour : {args.value}")
        return 1

    if args.json:
        print(json.dumps({"value": args.value, "match": hit.to_dict()}, indent=2, ensure_ascii=False))
    else:
        print(f"MATCH IOC trouvé : {args.value}")
        print(f"  Type      : {hit.ioc_type}")
        print(f"  Source    : {hit.source}")
        print(f"  Malware   : {hit.malware}")
        print(f"  Threat    : {hit.threat_type or 'N/A'}")
        print(f"  Confiance : {hit.confidence}/100")
        if hit.metadata:
            interesting = {
                k: v
                for k, v in hit.metadata.items()
                if k in ("first_seen", "date_added", "tags", "hostname", "matched_parent_domain", "url_status")
            }
            if interesting:
                print("  Metadata  :")
                for k, v in interesting.items():
                    print(f"    {k}: {v}")
    return 0


def cmd_intel_age(args: argparse.Namespace) -> int:
    """Affiche l'age des feeds threat intel (Phase 3.g).

    Exit codes :
      - 0 : tous les feeds sont presents ET frais
      - 1 : au moins un feed est stale OU manquant
      - 2 : aucun feed n'a jamais ete recupere (deploiement neuf)
    """
    from .intel.feed_age import read_feed_ages

    report = read_feed_ages(args.db_path, stale_threshold_s=args.stale_after)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"BioCybe — age des feeds threat intel (db={args.db_path})")
        print(f"  Seuil stale : {args.stale_after}s ({args.stale_after // 3600}h)")
        print("-" * 78)
        print(f"  {'source':<14} {'last_update':<22} {'age':<10} {'iocs':>8}  status")
        print("-" * 78)
        for f in report.feeds:
            last = f.last_update.isoformat(timespec="seconds") if f.last_update else "—"
            age = f.to_dict()["age_human"]
            status = "STALE" if f.stale else "fresh"
            if f.error:
                status = f"ERROR ({f.error})"
            print(
                f"  {f.source:<14} {last:<22} {age:<10} {f.ioc_count:>8}  {status}"
            )
        print("-" * 78)
        if report.all_missing:
            print("Aucun feed recupere. Lance : biocybe intel update --source all")
        elif report.any_stale:
            print("Au moins un feed est stale. Relance : biocybe intel update --source all")
        else:
            print("Tous les feeds sont frais.")

    if report.all_missing:
        return 2
    return 1 if report.any_stale else 0


def cmd_intel_stats(args: argparse.Namespace) -> int:
    """Affiche les compteurs IOC chargés localement (Phase 3.e)."""
    from .intel.ioc_lookup import IOCLookup

    lookup = IOCLookup.from_db(args.db_path)
    stats = lookup.stats()
    total = lookup.total

    if args.json:
        print(json.dumps({"total": total, "by_type": stats, "db_path": str(args.db_path)},
                         indent=2, ensure_ascii=False))
    else:
        print(f"Index IOC chargé depuis : {args.db_path}")
        print(f"  Total       : {total}")
        print(f"  Hashes      : {stats['hashes']} (MalwareBazaar + ThreatFox)")
        print(f"  Hostnames   : {stats['hostnames']} (URLhaus + ThreatFox)")
        print(f"  URLs        : {stats['urls']} (URLhaus)")
        print(f"  IPs         : {stats['ips']} (ThreatFox)")
        if total == 0:
            print("\nAucun IOC chargé. Lance : biocybe intel update --source all")
    return 0 if total > 0 else 1


def _guess_indicator_type(value: str) -> str:
    """Devine le type d'un indicateur (cohérent avec IOCLookup.lookup_auto)."""
    import ipaddress

    v = value.strip()
    if len(v) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v):
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(v)]
    if v.lower().startswith(("http://", "https://", "ftp://")):
        return "url"
    candidate = v.split(":", 1)[0] if v.count(":") == 1 else v
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass
    if "/" in v or "\\" in v:
        return "path"
    if "." in v:
        return "hostname"
    return "family"


def cmd_memory_stats(args: argparse.Namespace) -> int:
    from .memory import ImmuneMemory

    mem = ImmuneMemory(args.db_path)
    stats = mem.stats()
    families = mem.top_families(10)
    mem.close()
    if args.json:
        print(json.dumps({**stats, "top_families": families}, indent=2, ensure_ascii=False))
    else:
        print(f"Memoire immunitaire : {stats['db_path']}")
        print(f"  Total indicateurs : {stats['total']}")
        print(f"  Par verdict       : {stats['by_verdict']}")
        print(f"  Par disposition   : {stats['by_disposition']}")
        if families:
            print("  Top familles      :")
            for fam, n in families:
                print(f"    {fam:24} {n}")
    return 0


def cmd_memory_recall(args: argparse.Namespace) -> int:
    from .memory import ImmuneMemory

    itype = args.type or _guess_indicator_type(args.indicator)
    mem = ImmuneMemory(args.db_path)
    rec = mem.recall(args.indicator, itype if args.type else None)
    mem.close()
    if rec is None:
        if args.json:
            print(json.dumps({"indicator": args.indicator, "found": False}))
        else:
            print(f"Inconnu en memoire : {args.indicator} (type devine: {itype})")
        return 1
    if args.json:
        print(json.dumps(rec.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"MEMOIRE : {rec.indicator} [{rec.indicator_type}]")
        print(f"  Verdict      : {rec.verdict}")
        print(f"  Famille      : {rec.family or '—'}")
        print(f"  Confiance    : {rec.confidence}/100")
        print(f"  Vu           : {rec.times_seen} fois")
        print(f"  Premiere fois: {rec.first_seen}")
        print(f"  Derniere fois: {rec.last_seen}")
        print(f"  Disposition  : {rec.disposition}")
        if rec.notes:
            print(f"  Notes        : {rec.notes}")
    return 0


def cmd_memory_recent(args: argparse.Namespace) -> int:
    from .memory import ImmuneMemory

    mem = ImmuneMemory(args.db_path)
    records = mem.most_seen(args.limit) if args.most_seen else mem.recent(args.limit)
    mem.close()
    if args.json:
        print(json.dumps([r.to_dict() for r in records], indent=2, ensure_ascii=False))
    else:
        label = "plus frequents" if args.most_seen else "plus recents"
        print(f"Memoire immunitaire — {len(records)} indicateurs ({label}) :")
        for r in records:
            print(
                f"  [{r.verdict[:4]}] {r.indicator[:50]:50} "
                f"vu={r.times_seen:>4} conf={r.confidence:>3} {r.disposition}"
            )
    return 0


def cmd_memory_mark(args: argparse.Namespace) -> int:
    from .memory import (
        DISPOSITION_CONFIRMED_BENIGN,
        DISPOSITION_CONFIRMED_MALICIOUS,
        DISPOSITION_UNREVIEWED,
        ImmuneMemory,
    )

    disp_map = {
        "benign": DISPOSITION_CONFIRMED_BENIGN,
        "malicious": DISPOSITION_CONFIRMED_MALICIOUS,
        "unreviewed": DISPOSITION_UNREVIEWED,
    }
    mem = ImmuneMemory(args.db_path)
    # Crée l'entrée si absente (un analyste peut pré-marquer un FP connu)
    if mem.recall(args.indicator, args.type) is None:
        from .memory import VERDICT_BENIGN, VERDICT_MALICIOUS

        verdict = VERDICT_BENIGN if args.disposition == "benign" else VERDICT_MALICIOUS
        mem.remember(
            args.indicator, indicator_type=args.type, verdict=verdict, source="analyst"
        )
    ok = mem.set_disposition(
        args.indicator, args.type, disp_map[args.disposition], notes=args.notes
    )
    mem.close()
    if ok:
        print(f"Marque '{args.indicator}' [{args.type}] comme {args.disposition}.")
        if args.disposition == "benign":
            print("  -> les futures detections de cet indicateur seront supprimees (FP).")
        return 0
    print(f"Echec du marquage pour {args.indicator}", file=sys.stderr)
    return 1


def cmd_memory_forget(args: argparse.Namespace) -> int:
    from .memory import ImmuneMemory

    mem = ImmuneMemory(args.db_path)
    ok = mem.forget(args.indicator, args.type)
    mem.close()
    if ok:
        print(f"Oublie : {args.indicator} [{args.type}]")
        return 0
    print(f"Indicateur absent : {args.indicator} [{args.type}]", file=sys.stderr)
    return 1


def cmd_nk_respond(args: argparse.Namespace) -> int:
    """Réponse NK manuelle sur un PID (suspend/terminate/kill)."""
    from .nk_cells import NKAction, NKCell, NKConfig

    # Récupère le nom du process pour le garde-fou de protection
    process_name = ""
    try:
        import psutil

        process_name = psutil.Process(args.pid).name()
    except Exception as exc:
        print(f"Avertissement : impossible de lire le process {args.pid} : {exc}", file=sys.stderr)

    cfg = NKConfig(
        enabled=True,
        dry_run=not args.execute,
        min_confidence=args.min_confidence,
        allow_kill=args.allow_kill,
        default_action=NKAction(args.action),
    )
    nk = NKCell(cfg)
    decision = nk.evaluate(
        pid=args.pid,
        process_name=process_name,
        confidence=args.confidence,
        reason=args.reason,
        requested_action=NKAction(args.action),
    )
    decision = nk.respond(decision)

    if args.json:
        print(json.dumps(decision.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"Cible      : pid={decision.pid} ({decision.process_name or '?'})")
        print(f"Action     : {decision.action.value} (demandee: {decision.requested_action.value})")
        print(f"Confiance  : {decision.confidence}/100")
        print(f"Dry-run    : {decision.dry_run}")
        if decision.refused_reason:
            print(f"Refusee    : {decision.refused_reason}")
        if decision.error:
            print(f"Erreur     : {decision.error}")
        if decision.executed:
            print("Resultat   : EXECUTE")
            if decision.action.value == "suspend":
                print("  -> process gele. Reveiller : biocybe nk resume --pid "
                      f"{decision.pid}")
        elif decision.dry_run and decision.action.value != "none":
            print("Resultat   : DRY-RUN (rien execute). Ajoute --execute pour agir.")

    # Exit : 0 si action effectuee ou dry-run propre, 1 si refusee/erreur
    if decision.error or (decision.refused_reason and decision.action.value == "none"):
        return 1
    return 0


def cmd_nk_resume(args: argparse.Namespace) -> int:
    """Réveille un process suspendu par la NK cell."""
    from .nk_cells import NKCell, NKConfig

    nk = NKCell(NKConfig(enabled=True, dry_run=False))
    ok = nk.resume_process(args.pid)
    if ok:
        print(f"Process {args.pid} repris.")
        return 0
    print(f"Echec du resume pour {args.pid} (process absent ou access denied).", file=sys.stderr)
    return 1


def cmd_nk_status(args: argparse.Namespace) -> int:
    """Affiche la config NK + teste si un PID est protégé."""
    from .nk_cells import NKCell, NKConfig

    cfg = _load_config(args.config) or {}
    nk_cfg = cfg.get("nk") or {}
    nk = NKCell(
        NKConfig(
            enabled=nk_cfg.get("enabled", False),
            dry_run=nk_cfg.get("dry_run", True),
            min_confidence=nk_cfg.get("min_confidence", 90),
            allow_kill=nk_cfg.get("allow_kill", False),
        )
    )
    info = {
        "enabled": nk.config.enabled,
        "dry_run": nk.config.dry_run,
        "min_confidence": nk.config.min_confidence,
        "allow_kill": nk.config.allow_kill,
        "default_action": nk.config.default_action.value,
        "max_actions_per_minute": nk.config.max_actions_per_minute,
    }
    if args.pid is not None:
        process_name = ""
        try:
            import psutil

            process_name = psutil.Process(args.pid).name()
        except Exception:
            pass
        protected = nk.is_protected(args.pid, process_name)
        info["pid_test"] = {
            "pid": args.pid,
            "process_name": process_name,
            "protected": protected is not None,
            "protected_reason": protected,
        }

    if args.json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
    else:
        print("Cellule NK — configuration effective")
        print(f"  enabled         : {info['enabled']}")
        print(f"  dry_run         : {info['dry_run']}")
        print(f"  min_confidence  : {info['min_confidence']}")
        print(f"  allow_kill      : {info['allow_kill']}")
        print(f"  default_action  : {info['default_action']}")
        print(f"  max_actions/min : {info['max_actions_per_minute']}")
        if "pid_test" in info:
            t = info["pid_test"]
            print(f"\n  Test PID {t['pid']} ({t['process_name'] or '?'}) :")
            print(f"    protege : {t['protected']}"
                  + (f" ({t['protected_reason']})" if t["protected_reason"] else ""))
    return 0


def cmd_dashboard_serve(args: argparse.Namespace) -> int:
    """Lance le dashboard web de triage SOC (Phase 2.3.c)."""
    from .dashboard.data import DashboardConfig

    cfg = DashboardConfig(
        quarantine_dir=args.quarantine_dir,
        audit_path=args.audit_path,
        signatures_db_path=args.db_path,
    )
    try:
        from .dashboard.app import DashboardUnavailable, serve_dashboard
    except ImportError:
        print(
            "Dependances dashboard absentes. Installe : pip install biocybe[web]",
            file=sys.stderr,
        )
        return 2

    try:
        print(
            f"Dashboard BioCybe : http://{args.host}:{args.port} "
            f"(refresh {args.refresh_seconds}s, Ctrl+C pour arreter)",
            file=sys.stderr,
        )
        serve_dashboard(
            cfg,
            host=args.host,
            port=args.port,
            refresh_seconds=args.refresh_seconds,
            debug=args.debug,
        )
    except DashboardUnavailable as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nDashboard arrete.", file=sys.stderr)
    return 0


def _format_netmon_record(r) -> str:
    """Formate une ConnectionRecord en ligne lisible CLI."""
    marker = "!! IOC " if r.is_malicious else "   ok  "
    base = (
        f"{marker} pid={r.pid or '?':>6} {r.process_name[:24]:<24} "
        f"-> {r.raddr:<22} [{r.status}]"
    )
    if r.is_malicious and r.hit is not None:
        base += (
            f"  | {r.hit.source} malware={r.hit.malware} conf={r.hit.confidence}"
        )
    if r.reverse_dns:
        base += f"  ({r.reverse_dns})"
    return base


def cmd_netmon_scan(args: argparse.Namespace) -> int:
    """Snapshot ponctuel des connexions sortantes (Phase 3.f)."""
    from .intel.ioc_lookup import IOCLookup
    from .network_monitor import NetworkMonitor

    lookup = IOCLookup.from_db(args.db_path)
    if lookup.total == 0:
        print(
            "Aucun IOC charge. Lance d'abord : biocybe intel update --source all",
            file=sys.stderr,
        )
        return 2

    monitor = NetworkMonitor(lookup, reverse_dns=args.reverse_dns)
    records = monitor.snapshot()

    malicious = [r for r in records if r.is_malicious]

    if args.json:
        print(
            json.dumps(
                {
                    "total_connections": len(records),
                    "malicious_count": len(malicious),
                    "ioc_lookup_total": lookup.total,
                    "records": [r.to_dict() for r in (records if args.all else malicious)],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(f"BioCybe netmon scan — {len(records)} connexion(s) sortante(s) observee(s)")
        print(f"  IOCs charges : {lookup.total}")
        print(f"  Matchs       : {len(malicious)}")
        print("-" * 90)
        to_show = records if args.all else malicious
        if not to_show:
            print("(aucune connexion a afficher — utilise --all pour tout voir)")
        for r in to_show:
            print(_format_netmon_record(r))

    return 1 if malicious else 0


def cmd_netmon_watch(args: argparse.Namespace) -> int:
    """Surveillance continue (Phase 3.f)."""
    import signal as _signal

    from .intel.ioc_lookup import IOCLookup
    from .network_monitor import NetworkMonitor

    lookup = IOCLookup.from_db(args.db_path)
    if lookup.total == 0:
        print(
            "Aucun IOC charge. Lance d'abord : biocybe intel update --source all",
            file=sys.stderr,
        )
        return 2

    def _on_match(r):
        ts = datetime.now().isoformat(timespec="seconds")
        print(f"[{ts}] {_format_netmon_record(r)}", flush=True)

    monitor = NetworkMonitor(
        lookup,
        interval=args.interval,
        reverse_dns=args.reverse_dns,
        on_match=_on_match,
    )

    stop_event = threading.Event()

    def _signal_handler(signum, frame):
        print("\nArret demande, fermeture du monitor...", file=sys.stderr)
        stop_event.set()

    _signal.signal(_signal.SIGINT, _signal_handler)
    if hasattr(_signal, "SIGTERM"):
        _signal.signal(_signal.SIGTERM, _signal_handler)

    monitor.start()
    print(
        f"BioCybe netmon watch demarre (intervalle {args.interval}s, "
        f"{lookup.total} IOCs). Ctrl+C pour arreter.",
        file=sys.stderr,
    )
    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=1.0)
    finally:
        monitor.stop()
    return 0


def cmd_netmon_block_apply(args: argparse.Namespace) -> int:
    """Sinkhole DNS via fichier hosts (Phase 3.f)."""
    from .intel.ioc_lookup import IOCLookup
    from .network_monitor import HostsBlocker

    if not args.yes:
        print(
            "Refus : mutation du fichier hosts requiert --yes (confirmation explicite).\n"
            "  Cette commande ajoute une section BioCybe redirigeant les hostnames\n"
            "  malveillants vers 0.0.0.0. Elle est reversible via `netmon block clear`.",
            file=sys.stderr,
        )
        return 2

    lookup = IOCLookup.from_db(args.db_path)
    if lookup.total == 0:
        print(
            "Aucun IOC charge. Lance d'abord : biocybe intel update --source all",
            file=sys.stderr,
        )
        return 2

    # Filtre par confidence minimal — pas question de sinkholer en
    # production des hostnames a 30/100
    min_conf = int(args.min_confidence)
    candidates: list[str] = []
    for host, meta in lookup._hostnames.items():  # accès interne assumé
        if int(meta.get("confidence", 0) or 0) >= min_conf:
            candidates.append(host)

    blocker = HostsBlocker(Path(args.hosts_path) if args.hosts_path else None)
    try:
        stats = blocker.apply(candidates)
    except PermissionError as exc:
        print(
            f"Permission denied : {exc}\n"
            f"  Le fichier {blocker.hosts_path} requiert root/admin.",
            file=sys.stderr,
        )
        return 3

    print(f"Section BioCybe ecrite dans {blocker.hosts_path}")
    print(f"  Sinkholes : {len(stats.blocked)}")
    if stats.skipped_invalid:
        print(f"  Invalides (skip) : {len(stats.skipped_invalid)}")
    if stats.capped:
        print(f"  Limite atteinte : {len(stats.blocked)} entrees (cap anti-DoS)")
    print(f"  Backup : {blocker.backup_path}")
    print("  Pour annuler : biocybe netmon block clear --yes")
    return 0


def cmd_netmon_block_clear(args: argparse.Namespace) -> int:
    from .network_monitor import HostsBlocker

    if not args.yes:
        print("Refus : retrait de section requiert --yes", file=sys.stderr)
        return 2
    blocker = HostsBlocker(Path(args.hosts_path) if args.hosts_path else None)
    try:
        removed = blocker.clear()
    except PermissionError as exc:
        print(f"Permission denied : {exc}", file=sys.stderr)
        return 3
    print(f"Section BioCybe retiree de {blocker.hosts_path} ({removed} entrees)")
    return 0


def cmd_netmon_block_status(args: argparse.Namespace) -> int:
    from .network_monitor import HostsBlocker

    blocker = HostsBlocker(Path(args.hosts_path) if args.hosts_path else None)
    info = blocker.status()
    if args.json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
    else:
        print(f"Fichier hosts : {info['hosts_path']}")
        print(f"  Existe       : {info['exists']}")
        print(f"  Writable     : {info['writable']}")
        print(f"  Entrees BioCybe : {info['blocked_count']}")
        if info["blocked_sample"]:
            print("  Exemple (5 premiers) :")
            for h in info["blocked_sample"]:
                print(f"    - {h}")
        print(f"  Backup       : {info['backup_exists']}")
    return 0


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
    # Windows envoie SIGBREAK (Ctrl+Break) plutôt que SIGTERM ; sans
    # handler explicite Python lève KeyboardInterrupt — on s'arrête
    # proprement comme pour SIGINT.
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _handle_signal)

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

    # ---- Network monitor live (Phase 3.h) ----
    # Surveille les connexions sortantes contre les feeds IOC, alerte via
    # NotifierManager + audit log. Recharge les IOCs si un cron intel
    # update a tourné (sans redémarrer le daemon).
    netmon_service = _build_network_monitor_service_from_config(
        config, notify_mgr, cli_args=args
    )
    if netmon_service is not None:
        netmon_service.start()
        logger.info(
            "Network monitor actif : %d IOCs chargés, surveillance des connexions sortantes",
            netmon_service.ioc_total,
        )

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
    if netmon_service is not None:
        print(
            f"Network monitor : {netmon_service.ioc_total} IOCs, "
            "surveillance des connexions sortantes"
        )
    print("Appuyez sur Ctrl+C pour arrêter le système")

    try:
        interval = config.get("core", {}).get("state_save_interval", 300)
        # Recharge les feeds IOC toutes les 5 min (peu coûteux : compare
        # un fingerprint des last_update.txt, ne relit que si changé).
        netmon_reload_interval = 300
        last_save = time.time()
        last_netmon_reload = time.time()
        while _running:
            now = time.time()
            if now - last_save >= interval:
                _core.save_status()
                last_save = now
            if netmon_service is not None and now - last_netmon_reload >= netmon_reload_interval:
                try:
                    netmon_service.maybe_reload()
                except Exception as exc:
                    logger.error("netmon reload a échoué : %s", exc)
                last_netmon_reload = now
            time.sleep(1)
    except Exception as exc:
        logger.error("Erreur dans la boucle principale : %s", exc)
    finally:
        if netmon_service is not None:
            netmon_service.stop()
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
    parser.add_argument(
        "--netmon",
        action="store_true",
        dest="netmon",
        help="Active la surveillance live des connexions sortantes (Phase 3.h). "
        "Sinon utilise netmon.enabled de la config.",
    )
    parser.add_argument(
        "--netmon-interval",
        type=float,
        default=None,
        dest="netmon_interval",
        help="Intervalle de polling du network monitor en secondes (défaut config ou 5s).",
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
    scan_p.add_argument(
        "--network-scan",
        action="store_true",
        help="Phase 3.e : cherche aussi des IOCs réseau (URLs/IPs/hosts/hashes) "
        "dans le contenu des fichiers, depuis les feeds URLhaus + ThreatFox. "
        "Nécessite `biocybe intel update` au préalable.",
    )

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

    # intel update : feeds abuse.ch (MalwareBazaar / URLhaus / ThreatFox)
    intel_up = intel_sub.add_parser(
        "update",
        help="Télécharge les IOCs depuis abuse.ch (MalwareBazaar/URLhaus/ThreatFox)",
    )
    intel_up.add_argument(
        "--source",
        choices=["malwarebazaar", "urlhaus", "threatfox", "all"],
        default="malwarebazaar",
        help="Source à interroger (défaut malwarebazaar, `all` pour tout)",
    )
    intel_up.add_argument(
        "--selector",
        default="100",
        help="MalwareBazaar selector : 'time' (60 min), '100' ou '1000' derniers",
    )
    intel_up.add_argument(
        "--threatfox-days",
        type=int,
        default=1,
        help="ThreatFox : nombre de jours à récupérer (1-7, défaut 1)",
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

    # Phase 3.b : précompile le cache .yarc à la demande (Docker build,
    # provisioning, cron post-update, etc.).
    rules_cache = intel_rules_sub.add_parser(
        "build-cache",
        help="Pré-compile le cache YARA (compiled.yarc) pour démarrage rapide",
    )
    rules_cache.add_argument(
        "--db-path",
        default="db/signatures",
        help="Dossier signatures (défaut : db/signatures)",
    )
    rules_cache.add_argument(
        "--skip-sync",
        action="store_true",
        help="Ne pas re-sync depuis rules/yara/ (juste compile ce qui est en db/)",
    )
    rules_cache.add_argument(
        "--force",
        action="store_true",
        help="Supprime le cache existant avant recompilation",
    )
    rules_cache.add_argument("--json", action="store_true")

    # Phase 3.e : lookup IOC + stats des feeds chargés en mémoire
    intel_lookup_p = intel_sub.add_parser(
        "lookup",
        help="Cherche une valeur (hash/host/url/ip) dans les feeds IOC indexés",
    )
    intel_lookup_p.add_argument(
        "value",
        help="Valeur à chercher (hash, hostname, URL, IP — type auto-détecté)",
    )
    intel_lookup_p.add_argument(
        "--type",
        choices=["auto", "hash", "hostname", "url", "ip"],
        default="auto",
        help="Force le type d'IOC (défaut : auto-détection)",
    )
    intel_lookup_p.add_argument(
        "--db-path",
        default="db/signatures",
        help="Dossier signatures (défaut : db/signatures)",
    )
    intel_lookup_p.add_argument("--json", action="store_true")

    intel_stats_p = intel_sub.add_parser(
        "stats",
        help="Affiche les compteurs IOC chargés depuis les feeds locaux",
    )
    intel_stats_p.add_argument(
        "--db-path",
        default="db/signatures",
        help="Dossier signatures (défaut : db/signatures)",
    )
    intel_stats_p.add_argument("--json", action="store_true")

    # Phase 3.g : âge des feeds (cron monitoring, alerte si stale)
    intel_age_p = intel_sub.add_parser(
        "age",
        help="Affiche l'age des feeds threat intel. Exit 1 si au moins un est stale.",
    )
    intel_age_p.add_argument(
        "--db-path",
        default="db/signatures",
        help="Dossier signatures (defaut : db/signatures)",
    )
    intel_age_p.add_argument(
        "--stale-after",
        type=int,
        default=48 * 3600,
        help="Seuil en secondes au-dela duquel un feed est considere stale (defaut 48h)",
    )
    intel_age_p.add_argument("--json", action="store_true")

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

    # ---------------- netmon (Phase 3.f — surveillance connexions live) ------
    netmon_p = subparsers.add_parser(
        "netmon",
        help="Surveille les connexions reseau sortantes contre les feeds IOC",
    )
    netmon_sub = netmon_p.add_subparsers(dest="netmon_command", required=True)

    netmon_scan = netmon_sub.add_parser(
        "scan", help="Snapshot ponctuel : connexions sortantes + lookup IOC"
    )
    netmon_scan.add_argument(
        "--db-path", default="db/signatures", help="Dossier signatures (defaut: db/signatures)"
    )
    netmon_scan.add_argument(
        "--reverse-dns",
        action="store_true",
        help="Active reverse DNS sur les IPs sans match direct (lent mais enrichit)",
    )
    netmon_scan.add_argument(
        "--all",
        action="store_true",
        help="Affiche TOUTES les connexions, pas seulement les IOCs (mode debug)",
    )
    netmon_scan.add_argument("--json", action="store_true")

    netmon_watch = netmon_sub.add_parser(
        "watch",
        help="Surveillance continue. Ctrl+C pour arreter.",
    )
    netmon_watch.add_argument("--db-path", default="db/signatures")
    netmon_watch.add_argument(
        "--interval", type=float, default=5.0, help="Intervalle entre polls (defaut 5.0s)"
    )
    netmon_watch.add_argument("--reverse-dns", action="store_true")

    netmon_block_p = netmon_sub.add_parser(
        "block",
        help="Sinkhole DNS via fichier hosts (necessite root/admin)",
    )
    netmon_block_sub = netmon_block_p.add_subparsers(dest="block_command", required=True)

    block_apply = netmon_block_sub.add_parser(
        "apply", help="Ecrit les hostnames des feeds dans /etc/hosts (sinkhole 0.0.0.0)"
    )
    block_apply.add_argument(
        "--db-path", default="db/signatures", help="Dossier signatures (defaut: db/signatures)"
    )
    block_apply.add_argument(
        "--hosts-path",
        default=None,
        help="Override du fichier hosts (defaut: /etc/hosts ou %SystemRoot%\\System32\\drivers\\etc\\hosts)",
    )
    block_apply.add_argument(
        "--yes",
        action="store_true",
        help="Confirme la mutation du fichier hosts (obligatoire)",
    )
    block_apply.add_argument(
        "--min-confidence",
        type=int,
        default=75,
        help="Confidence min des IOCs a sinkholer (defaut 75/100)",
    )

    block_clear = netmon_block_sub.add_parser(
        "clear", help="Retire la section BioCybe du fichier hosts"
    )
    block_clear.add_argument("--hosts-path", default=None)
    block_clear.add_argument("--yes", action="store_true")

    block_status = netmon_block_sub.add_parser(
        "status", help="Affiche l'etat actuel de la section BioCybe"
    )
    block_status.add_argument("--hosts-path", default=None)
    block_status.add_argument("--json", action="store_true")

    # ---------------- memory (Mémoire immunitaire persistante) ---------------
    mem_p = subparsers.add_parser(
        "memory",
        help="Memoire immunitaire : apprentissage cross-session des menaces",
    )
    mem_sub = mem_p.add_subparsers(dest="memory_command", required=True)

    DEFAULT_MEM_DB = "db/memory/immune_memory.db"

    mem_stats = mem_sub.add_parser("stats", help="Compteurs de la memoire")
    mem_stats.add_argument("--db-path", default=DEFAULT_MEM_DB)
    mem_stats.add_argument("--json", action="store_true")

    mem_recall = mem_sub.add_parser("recall", help="Cherche un indicateur en memoire")
    mem_recall.add_argument("indicator", help="Hash, IP, hostname, URL, chemin...")
    mem_recall.add_argument("--type", default=None, help="Type d'indicateur (sinon auto)")
    mem_recall.add_argument("--db-path", default=DEFAULT_MEM_DB)
    mem_recall.add_argument("--json", action="store_true")

    mem_recent = mem_sub.add_parser("recent", help="Dernieres entrees vues")
    mem_recent.add_argument("--limit", type=int, default=20)
    mem_recent.add_argument("--most-seen", action="store_true", help="Trie par frequence")
    mem_recent.add_argument("--db-path", default=DEFAULT_MEM_DB)
    mem_recent.add_argument("--json", action="store_true")

    mem_mark = mem_sub.add_parser(
        "mark", help="Feedback analyste : marque un indicateur (FP ou confirme)"
    )
    mem_mark.add_argument("indicator")
    mem_mark.add_argument("--type", required=True, help="Type d'indicateur")
    mem_mark.add_argument(
        "--as",
        dest="disposition",
        required=True,
        choices=["benign", "malicious", "unreviewed"],
        help="benign = faux positif (supprime les futures alertes), malicious = confirme",
    )
    mem_mark.add_argument("--notes", default=None)
    mem_mark.add_argument("--db-path", default=DEFAULT_MEM_DB)

    mem_forget = mem_sub.add_parser("forget", help="Supprime une entree de la memoire")
    mem_forget.add_argument("indicator")
    mem_forget.add_argument("--type", required=True)
    mem_forget.add_argument("--db-path", default=DEFAULT_MEM_DB)

    # ---------------- nk (Cellules NK — réponse active) ---------------------
    nk_p = subparsers.add_parser(
        "nk",
        help="Cellules NK : reponse active sur processus malveillants (suspend/kill)",
    )
    nk_sub = nk_p.add_subparsers(dest="nk_command", required=True)

    nk_respond = nk_sub.add_parser(
        "respond", help="Repond a un processus (suspend par defaut, dry-run par defaut)"
    )
    nk_respond.add_argument("--pid", type=int, required=True, help="PID du processus cible")
    nk_respond.add_argument(
        "--action",
        choices=["suspend", "terminate", "kill"],
        default="suspend",
        help="Action (defaut suspend, reversible). kill exige --allow-kill.",
    )
    nk_respond.add_argument(
        "--confidence", type=int, default=100, help="Confiance de la detection (0-100)"
    )
    nk_respond.add_argument("--reason", default="manuel (analyste)", help="Raison de l'action")
    nk_respond.add_argument(
        "--execute",
        action="store_true",
        help="Execute REELLEMENT (sinon dry-run : decrit sans agir)",
    )
    nk_respond.add_argument(
        "--allow-kill",
        action="store_true",
        help="Autorise l'action kill (SIGKILL). Sans, kill est downgrade en suspend.",
    )
    nk_respond.add_argument(
        "--min-confidence", type=int, default=90, help="Seuil de confiance minimal (defaut 90)"
    )
    nk_respond.add_argument("--json", action="store_true")

    nk_resume = nk_sub.add_parser("resume", help="Reveille un processus suspendu")
    nk_resume.add_argument("--pid", type=int, required=True)

    nk_status = nk_sub.add_parser(
        "status", help="Affiche la config NK effective + process protege test"
    )
    nk_status.add_argument("--pid", type=int, default=None, help="Teste si ce PID est protege")
    nk_status.add_argument("--json", action="store_true")

    # ---------------- dashboard (Phase 2.3.c — UI triage SOC) ----------------
    dash_p = subparsers.add_parser(
        "dashboard",
        help="Dashboard web de triage SOC (lecture seule)",
    )
    dash_sub = dash_p.add_subparsers(dest="dashboard_command", required=True)

    dash_serve = dash_sub.add_parser("serve", help="Lance le dashboard web")
    dash_serve.add_argument("--host", default="127.0.0.1", help="Bind host (defaut 127.0.0.1)")
    dash_serve.add_argument("--port", type=int, default=8050, help="Port (defaut 8050)")
    dash_serve.add_argument(
        "--quarantine-dir", default="quarantine", help="Dossier quarantaine"
    )
    dash_serve.add_argument(
        "--audit-path", default="logs/audit.jsonl", help="Chemin de l'audit log"
    )
    dash_serve.add_argument(
        "--db-path", default="db/signatures", help="Dossier signatures (feeds intel)"
    )
    dash_serve.add_argument(
        "--refresh-seconds", type=int, default=15, help="Intervalle d'auto-refresh (defaut 15s)"
    )
    dash_serve.add_argument(
        "--debug",
        action="store_true",
        help="Mode debug Dash (NE PAS utiliser en production)",
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
            if args.rules_command == "build-cache":
                return cmd_intel_rules_build_cache(args)
        if args.intel_command == "lookup":
            return cmd_intel_lookup(args)
        if args.intel_command == "stats":
            return cmd_intel_stats(args)
        if args.intel_command == "age":
            return cmd_intel_age(args)
    if args.command == "memory":
        if args.memory_command == "stats":
            return cmd_memory_stats(args)
        if args.memory_command == "recall":
            return cmd_memory_recall(args)
        if args.memory_command == "recent":
            return cmd_memory_recent(args)
        if args.memory_command == "mark":
            return cmd_memory_mark(args)
        if args.memory_command == "forget":
            return cmd_memory_forget(args)
    if args.command == "nk":
        if args.nk_command == "respond":
            return cmd_nk_respond(args)
        if args.nk_command == "resume":
            return cmd_nk_resume(args)
        if args.nk_command == "status":
            return cmd_nk_status(args)
    if args.command == "dashboard":
        if args.dashboard_command == "serve":
            return cmd_dashboard_serve(args)
    if args.command == "netmon":
        if args.netmon_command == "scan":
            return cmd_netmon_scan(args)
        if args.netmon_command == "watch":
            return cmd_netmon_watch(args)
        if args.netmon_command == "block":
            if args.block_command == "apply":
                return cmd_netmon_block_apply(args)
            if args.block_command == "clear":
                return cmd_netmon_block_clear(args)
            if args.block_command == "status":
                return cmd_netmon_block_status(args)
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
