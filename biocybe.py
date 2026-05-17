#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BioCybe - Système de cyberdéfense bio-inspiré

Script principal pour démarrer le système immunitaire numérique BioCybe.
"""

import os
import sys
import argparse
import logging
import signal
import yaml
import time
from datetime import datetime

# Force UTF-8 sur stdout/stderr (Windows utilise cp1252 par défaut,
# qui ne peut pas imprimer le logo ASCII ni les accents des logs).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importer les modules BioCybe
from src.biocybe_core import BioCybeCore
import src.macrophages
import src.lymphocytes_b

# Configuration de la journalisation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("biocybe.log")
    ]
)
logger = logging.getLogger("biocybe.main")

# Variables globales
biocybe_core = None
running = True

def load_config(config_path):
    """
    Charge la configuration depuis un fichier YAML.
    
    Args:
        config_path: Chemin vers le fichier de configuration
    
    Returns:
        dict: Configuration chargée ou None en cas d'erreur
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            logger.info(f"Configuration chargée depuis {config_path}")
            return config
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la configuration: {e}")
        return None

def setup_logging(config):
    """
    Configure la journalisation selon les paramètres de configuration.
    
    Args:
        config: Configuration du système
    """
    log_level_str = config.get("core", {}).get("log_level", "INFO")
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    
    # Configurers tous les loggers
    for handler in logging.root.handlers:
        handler.setLevel(log_level)
    
    logging.root.setLevel(log_level)
    logger.setLevel(log_level)
    logger.info(f"Niveau de journalisation défini à {log_level_str}")

def handle_signal(signum, frame):
    """
    Gestionnaire de signaux pour l'arrêt propre du système.
    
    Args:
        signum: Numéro du signal
        frame: Frame courant
    """
    global running, biocybe_core
    
    signal_names = {
        signal.SIGINT: "SIGINT",
        signal.SIGTERM: "SIGTERM"
    }
    
    signal_name = signal_names.get(signum, str(signum))
    logger.info(f"Signal {signal_name} reçu, arrêt du système en cours...")
    
    running = False
    
    if biocybe_core:
        biocybe_core.stop()

def create_required_directories(config):
    """
    Crée les répertoires nécessaires au système.
    
    Args:
        config: Configuration du système
    """
    # Répertoires de base
    directories = [
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
        "templates/recovery"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    logger.info(f"Structure de répertoires créée")

def init_biocybe(config):
    """
    Initialise le système BioCybe.
    
    Args:
        config: Configuration du système
    
    Returns:
        BioCybeCore: Instance du noyau BioCybe ou None en cas d'erreur
    """
    try:
        # Créer le noyau
        core = BioCybeCore()
        
        # Charger automatiquement les cellules si configuré
        if config.get("cells", {}).get("autoload", True):
            enabled_types = config.get("cells", {}).get("enabled_types", [])
            
            # Cellules Macrophages
            if "macrophage" in enabled_types:
                logger.info("Chargement des cellules Macrophages")
                macrophage_cells = src.macrophages.create_cells(config)
                for cell in macrophage_cells:
                    core.register_cell(cell)
            
            # Cellules Lymphocytes B
            if "b_cell" in enabled_types:
                logger.info("Chargement des cellules Lymphocytes B")
                b_cells = src.lymphocytes_b.create_cells(config)
                for cell in b_cells:
                    core.register_cell(cell)
            
            # Autres types de cellules (à implémenter)
            # ...
        
        return core
    
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation du système BioCybe: {e}")
        return None

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="biocybe",
        description="BioCybe — Système de cyberdéfense bio-inspiré",
    )
    parser.add_argument("-c", "--config", default="config/biocybe.yaml",
                        help="Chemin vers le fichier de configuration")
    parser.add_argument("--debug", action="store_true",
                        help="Active le mode debug")

    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser(
        "scan",
        help="Scanne un fichier ou un dossier (one-shot, sans démarrer le daemon)",
    )
    scan_p.add_argument("path", help="Fichier ou dossier à analyser")
    scan_p.add_argument("--no-recursive", action="store_true",
                        help="Ne pas descendre dans les sous-dossiers")
    scan_p.add_argument("--quarantine", action="store_true",
                        help="Mettre en quarantaine les fichiers détectés")
    scan_p.add_argument("--json", action="store_true",
                        help="Sortie JSON (machine-readable) au lieu du rapport texte")

    return parser


def cmd_scan(args) -> int:
    """Exécute la sous-commande `scan`. Retourne un exit code."""
    from src.scanner import format_report, scan_path

    try:
        verdicts = scan_path(
            args.path,
            recursive=not args.no_recursive,
            quarantine=args.quarantine,
        )
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2

    if args.json:
        import json
        payload = [
            {
                "path": str(v.path),
                "result": v.result.to_dict(),
                "quarantine": (
                    {
                        "id": v.quarantine.quarantine_id,
                        "stored_filename": v.quarantine.stored_filename,
                    } if v.quarantine else None
                ),
            }
            for v in verdicts
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(format_report(verdicts))

    # Exit non-zéro s'il y a au moins une menace (utile pour CI/scripts).
    return 1 if any(v.is_malicious for v in verdicts) else 0


def main():
    """
    Point d'entrée principal du programme.
    """
    global biocybe_core, running

    parser = _build_parser()
    args = parser.parse_args()

    # Mode debug
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        logger.debug("Mode debug activé")

    # Sous-commande `scan` : pas besoin du daemon.
    if args.command == "scan":
        sys.exit(cmd_scan(args))
    
    # Charger la configuration
    config = load_config(args.config)
    if not config:
        logger.error("Impossible de charger la configuration, arrêt du programme")
        sys.exit(1)
    
    # Configurer la journalisation
    setup_logging(config)
    
    # Créer les répertoires nécessaires
    create_required_directories(config)
    
    # Enregistrer les gestionnaires de signaux
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Initialiser le système
    biocybe_core = init_biocybe(config)
    if not biocybe_core:
        logger.error("Échec de l'initialisation du système BioCybe, arrêt du programme")
        sys.exit(1)
    
    # Démarrer le système
    logger.info("Démarrage du système BioCybe...")
    biocybe_core.start()
    
    # Affichage du logo ASCII de BioCybe
    print("""
    ██████╗ ██╗ ██████╗  ██████╗██╗   ██╗██████╗ ███████╗
    ██╔══██╗██║██╔═══██╗██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝
    ██████╔╝██║██║   ██║██║      ╚████╔╝ ██████╔╝█████╗  
    ██╔══██╗██║██║   ██║██║       ╚██╔╝  ██╔══██╗██╔══╝  
    ██████╔╝██║╚██████╔╝╚██████╗   ██║   ██████╔╝███████╗
    ╚═════╝ ╚═╝ ╚═════╝  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝
                                                       
    Le système immunitaire numérique libre, modulaire et explicable.
    """)
    
    print(f"Système démarré à {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Cellules actives: {len(biocybe_core.cells)}")
    print(f"Types de cellules: {', '.join(biocybe_core.cell_types.keys())}")
    print("Appuyez sur Ctrl+C pour arrêter le système")
    
    # Boucle principale
    try:
        interval = config.get("core", {}).get("state_save_interval", 300)
        last_save = time.time()
        
        while running:
            # Sauvegarder l'état périodiquement
            current_time = time.time()
            if current_time - last_save >= interval:
                biocybe_core.save_status()
                last_save = current_time
            
            # Attendre un peu pour éviter de surconsommer le CPU
            time.sleep(1)
    
    except Exception as e:
        logger.error(f"Erreur dans la boucle principale: {e}")
    
    finally:
        # Arrêter le système si ce n'est pas déjà fait
        if biocybe_core and biocybe_core.active:
            logger.info("Arrêt du système BioCybe...")
            biocybe_core.stop()
        
        logger.info("Système BioCybe arrêté")

if __name__ == "__main__":
    main()
