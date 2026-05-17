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

    logger.info("Démarrage du système BioCybe...")
    _core.start()

    print(_BANNER)
    print(f"Système démarré à {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Cellules actives : {len(_core.cells)}")
    print(f"Types de cellules : {', '.join(_core.cell_types.keys())}")
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
        if _core and _core.active:
            logger.info("Arrêt du système BioCybe...")
            _core.stop()
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
    return cmd_daemon(args)


if __name__ == "__main__":
    sys.exit(main())
