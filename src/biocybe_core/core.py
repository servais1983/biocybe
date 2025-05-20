#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BioCybe Core - Noyau central du système immunitaire numérique.
Ce module est responsable de l'initialisation, coordination et communication
entre les différents modules "cellulaires" du système.
"""

import os
import sys
import logging
import yaml
import json
import threading
import queue
import importlib
import pkgutil
from datetime import datetime
from typing import Dict, List, Any, Callable, Optional, Union, Set

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("biocybe.log")
    ]
)
logger = logging.getLogger("biocybe.core")

class CellMessage:
    """
    Représente un message échangé entre les modules cellulaires,
    inspiré par la signalisation entre cellules du système immunitaire.
    """
    
    def __init__(self, 
                 msg_type: str, 
                 source: str, 
                 target: str = "broadcast",
                 payload: Any = None,
                 priority: int = 1,
                 timestamp: datetime = None):
        """
        Initialise un nouveau message cellulaire.
        
        Args:
            msg_type: Type du message (ex: "alert", "scan_result", "threat_detected")
            source: Module source du message
            target: Module destinataire (ou "broadcast" pour tous)
            payload: Contenu du message
            priority: Priorité du message (1-5, 5 étant le plus prioritaire)
            timestamp: Horodatage du message (défaut = maintenant)
        """
        self.msg_type = msg_type
        self.source = source
        self.target = target
        self.payload = payload
        self.priority = max(1, min(5, priority))  # Entre 1 et 5
        self.timestamp = timestamp or datetime.now()
        self.id = f"{source}_{self.timestamp.strftime('%Y%m%d%H%M%S%f')}"
    
    def __str__(self):
        return f"Message[{self.msg_type}] de {self.source} → {self.target} (priorité: {self.priority})"
    
    def to_dict(self):
        """Convertit le message en dictionnaire pour sérialisation"""
        return {
            "id": self.id,
            "type": self.msg_type,
            "source": self.source,
            "target": self.target,
            "priority": self.priority,
            "timestamp": self.timestamp.isoformat(),
            "payload": self.payload
        }

class BiologicalCell:
    """
    Classe de base pour tous les modules cellulaires de BioCybe.
    Définit l'interface commune et les fonctionnalités de base.
    """
    
    def __init__(self, name: str, cell_type: str, config: Dict = None):
        """
        Initialise une cellule du système immunitaire numérique.
        
        Args:
            name: Nom unique de cette instance
            cell_type: Type de cellule (ex: "macrophage", "t_cell")
            config: Configuration spécifique à la cellule
        """
        self.name = name
        self.cell_type = cell_type
        self.config = config or {}
        self.logger = logging.getLogger(f"biocybe.{cell_type}.{name}")
        self.status = "initialized"
        self.active = False
        self.message_queue = queue.PriorityQueue()
        self.message_handlers = {}
        self._stop_event = threading.Event()
        
        # Métriques et statistiques
        self.stats = {
            "messages_received": 0,
            "messages_sent": 0,
            "actions_performed": 0,
            "last_activity": datetime.now()
        }
        
        self.logger.info(f"Cellule {self.cell_type} '{self.name}' initialisée")
    
    def register_message_handler(self, msg_type: str, handler: Callable):
        """
        Enregistre un gestionnaire pour un type de message spécifique.
        
        Args:
            msg_type: Type de message à gérer
            handler: Fonction qui sera appelée avec le message comme paramètre
        """
        self.message_handlers[msg_type] = handler
        self.logger.debug(f"Gestionnaire enregistré pour les messages de type '{msg_type}'")
    
    def handle_message(self, message: CellMessage):
        """
        Traite un message reçu d'un autre module cellulaire.
        
        Args:
            message: Message à traiter
        
        Returns:
            bool: True si le message a été traité, False sinon
        """
        self.stats["messages_received"] += 1
        self.stats["last_activity"] = datetime.now()
        
        # Si un gestionnaire existe pour ce type de message, l'appeler
        if message.msg_type in self.message_handlers:
            try:
                self.message_handlers[message.msg_type](message)
                return True
            except Exception as e:
                self.logger.error(f"Erreur dans le gestionnaire de message '{message.msg_type}': {e}")
                return False
        else:
            self.logger.warning(f"Pas de gestionnaire pour le message de type '{message.msg_type}'")
            return False
    
    def send_message(self, msg_type: str, target: str = "broadcast", payload: Any = None, priority: int = 1):
        """
        Envoie un message à un autre module cellulaire via le noyau BioCybe.
        Cette méthode est généralement surchargée par le noyau lors de l'enregistrement
        de la cellule pour injecter la référence au bus de messages.
        
        Args:
            msg_type: Type du message
            target: Destinataire du message
            payload: Contenu du message
            priority: Priorité du message (1-5)
        
        Returns:
            bool: True si le message a été envoyé, False sinon
        """
        self.logger.warning("Méthode send_message non implémentée (cellule non connectée au noyau)")
        return False
    
    def start(self):
        """Démarre l'activité de la cellule"""
        if not self.active:
            self.active = True
            self.status = "active"
            self._worker_thread = threading.Thread(target=self._worker, daemon=True)
            self._worker_thread.start()
            self.logger.info(f"Cellule {self.cell_type} '{self.name}' démarrée")
    
    def stop(self):
        """Arrête l'activité de la cellule"""
        if self.active:
            self._stop_event.set()
            self.status = "stopping"
            self.logger.info(f"Arrêt de la cellule {self.cell_type} '{self.name}' demandé")
    
    def _worker(self):
        """
        Méthode principale du thread de travail.
        À surcharger dans les implémentations spécifiques.
        """
        self.logger.debug("Thread de travail démarré")
        
        try:
            while not self._stop_event.is_set():
                # Logique spécifique à la cellule
                # À implémenter dans les sous-classes
                self._process_cycle()
                
                # Éviter de surconsommer des ressources CPU
                self._stop_event.wait(0.1)
        
        except Exception as e:
            self.logger.error(f"Erreur dans le thread de travail: {e}")
        
        finally:
            self.active = False
            self.status = "stopped"
            self.logger.info(f"Cellule {self.cell_type} '{self.name}' arrêtée")
    
    def _process_cycle(self):
        """
        Traite un cycle d'activité de la cellule.
        À surcharger dans les implémentations spécifiques.
        """
        pass
    
    def get_status(self) -> Dict:
        """
        Retourne l'état actuel de la cellule.
        Utile pour le monitoring et le débogage.
        """
        return {
            "name": self.name,
            "type": self.cell_type,
            "status": self.status,
            "active": self.active,
            "stats": self.stats,
            "last_update": datetime.now().isoformat()
        }

class BioCybeCore:
    """
    Noyau central du système BioCybe.
    Gère l'initialisation, la coordination et la communication entre les modules.
    """
    
    def __init__(self, config_path: str = "config/biocybe.yaml"):
        """
        Initialise le noyau BioCybe.
        
        Args:
            config_path: Chemin vers le fichier de configuration
        """
        self.logger = logging.getLogger("biocybe.core")
        self.config = self._load_config(config_path)
        self.cells = {}  # name -> cell instance
        self.cell_types = {}  # type -> [cells of that type]
        self.message_bus = queue.PriorityQueue()
        self.active = False
        self._stop_event = threading.Event()
        
        # Statistiques et métriques
        self.stats = {
            "start_time": datetime.now(),
            "messages_processed": 0,
            "cells_loaded": 0,
            "last_alert": None
        }
        
        self.logger.info("Noyau BioCybe initialisé")
    
    def _load_config(self, config_path: str) -> Dict:
        """
        Charge la configuration depuis un fichier YAML.
        
        Args:
            config_path: Chemin vers le fichier de configuration
        
        Returns:
            Dict: Configuration chargée ou configuration par défaut
        """
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
                self.logger.info(f"Configuration chargée depuis {config_path}")
                return config
        except Exception as e:
            self.logger.warning(f"Erreur lors du chargement de la configuration: {e}")
            self.logger.info("Utilisation de la configuration par défaut")
            return {
                "core": {
                    "message_retention": 1000,
                    "log_level": "INFO",
                    "xai_enabled": True
                },
                "cells": {
                    "autoload": True,
                    "enabled_types": ["macrophage", "b_cell", "t_cell", "nk_cell", "memory_cell", "barrier_cell"]
                }
            }
    
    def register_cell(self, cell: BiologicalCell) -> bool:
        """
        Enregistre une cellule auprès du noyau.
        
        Args:
            cell: Instance de cellule à enregistrer
        
        Returns:
            bool: True si la cellule a été enregistrée, False sinon
        """
        if cell.name in self.cells:
            self.logger.warning(f"Une cellule avec le nom '{cell.name}' est déjà enregistrée")
            return False
        
        # Injecter la méthode d'envoi de messages
        def send_message_impl(msg_type, target="broadcast", payload=None, priority=1):
            """Implémentation de la méthode send_message injectée dans la cellule"""
            message = CellMessage(
                msg_type=msg_type,
                source=cell.name,
                target=target,
                payload=payload,
                priority=priority
            )
            self.message_bus.put((6 - priority, message))  # Inversion priorité pour file prioritaire
            cell.stats["messages_sent"] += 1
            cell.stats["last_activity"] = datetime.now()
            return True
        
        # Remplacer la méthode de la cellule
        cell.send_message = send_message_impl
        
        # Enregistrer la cellule
        self.cells[cell.name] = cell
        
        # Enregistrer par type
        if cell.cell_type not in self.cell_types:
            self.cell_types[cell.cell_type] = []
        self.cell_types[cell.cell_type].append(cell.name)
        
        self.stats["cells_loaded"] += 1
        self.logger.info(f"Cellule {cell.cell_type} '{cell.name}' enregistrée")
        return True
    
    def start(self):
        """Démarre le noyau BioCybe et toutes les cellules enregistrées"""
        if not self.active:
            self.active = True
            
            # Démarrer le thread de distribution des messages
            self._message_thread = threading.Thread(target=self._message_dispatcher, daemon=True)
            self._message_thread.start()
            
            # Démarrer toutes les cellules
            for name, cell in self.cells.items():
                cell.start()
            
            self.logger.info(f"Noyau BioCybe démarré avec {len(self.cells)} cellules")
            # Envoyer un message de démarrage du système
            system_message = CellMessage(
                msg_type="system_start",
                source="core",
                target="broadcast",
                payload={"timestamp": datetime.now().isoformat()}
            )
            self.message_bus.put((1, system_message))  # Haute priorité
    
    def stop(self):
        """Arrête le noyau BioCybe et toutes les cellules enregistrées"""
        if self.active:
            self.logger.info("Arrêt du noyau BioCybe demandé")
            
            # Envoyer un message d'arrêt du système
            system_message = CellMessage(
                msg_type="system_stop",
                source="core",
                target="broadcast",
                payload={"timestamp": datetime.now().isoformat()}
            )
            self.message_bus.put((1, system_message))  # Haute priorité
            
            # Attendre le traitement du message
            import time
            time.sleep(1)
            
            # Arrêter toutes les cellules
            for name, cell in self.cells.items():
                cell.stop()
            
            # Arrêter le thread de messages
            self._stop_event.set()
            
            # Attendre que tous les threads se terminent
            for name, cell in self.cells.items():
                if hasattr(cell, '_worker_thread') and cell._worker_thread.is_alive():
                    cell._worker_thread.join(timeout=5)
            
            if hasattr(self, '_message_thread') and self._message_thread.is_alive():
                self._message_thread.join(timeout=5)
            
            self.active = False
            self.logger.info("Noyau BioCybe arrêté")
    
    def _message_dispatcher(self):
        """
        Thread de distribution des messages entre les cellules.
        Lit les messages de la file et les distribue aux destinataires.
        """
        self.logger.debug("Dispatcher de messages démarré")
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Récupérer un message de la file (avec timeout pour vérifier _stop_event)
                    try:
                        priority, message = self.message_bus.get(timeout=0.5)
                    except queue.Empty:
                        continue
                    
                    # Traiter le message
                    self._dispatch_message(message)
                    
                    # Marquer comme traité
                    self.message_bus.task_done()
                    self.stats["messages_processed"] += 1
                    
                    # Si c'est une alerte, la stocker
                    if message.msg_type.startswith("alert_"):
                        self.stats["last_alert"] = {
                            "timestamp": message.timestamp,
                            "type": message.msg_type,
                            "source": message.source,
                            "payload": message.payload
                        }
                
                except Exception as e:
                    self.logger.error(f"Erreur dans le dispatcher de messages: {e}")
        
        except Exception as e:
            self.logger.error(f"Erreur critique dans le thread dispatcher: {e}")
        
        finally:
            self.logger.debug("Dispatcher de messages arrêté")
    
    def _dispatch_message(self, message: CellMessage):
        """
        Distribue un message aux cellules destinataires.
        
        Args:
            message: Message à distribuer
        """
        # Déterminer les destinataires
        if message.target == "broadcast":
            # Message pour toutes les cellules
            for name, cell in self.cells.items():
                if name != message.source:  # Éviter de renvoyer à l'expéditeur
                    cell.handle_message(message)
        
        elif message.target.startswith("type:"):
            # Message pour un type de cellule spécifique
            target_type = message.target[5:]  # Enlever "type:"
            if target_type in self.cell_types:
                for cell_name in self.cell_types[target_type]:
                    if cell_name != message.source:
                        self.cells[cell_name].handle_message(message)
        
        else:
            # Message pour une cellule spécifique
            if message.target in self.cells:
                self.cells[message.target].handle_message(message)
            else:
                self.logger.warning(f"Message destiné à une cellule inconnue: {message.target}")
    
    def load_cells_from_modules(self, module_path: str = "biocybe.cells"):
        """
        Charge automatiquement les cellules depuis les modules Python.
        
        Args:
            module_path: Chemin du package Python contenant les modules cellulaires
        """
        self.logger.info(f"Chargement automatique des cellules depuis {module_path}")
        
        try:
            package = importlib.import_module(module_path)
            for _, name, is_pkg in pkgutil.iter_modules(package.__path__, package.__name__ + '.'):
                if is_pkg:
                    try:
                        cell_module = importlib.import_module(name)
                        if hasattr(cell_module, 'create_cells'):
                            cells = cell_module.create_cells(self.config)
                            for cell in cells:
                                self.register_cell(cell)
                    except Exception as e:
                        self.logger.error(f"Erreur lors du chargement du module {name}: {e}")
        
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement automatique des cellules: {e}")
    
    def get_status(self) -> Dict:
        """
        Retourne l'état actuel du noyau et de toutes les cellules.
        Utile pour le monitoring et le débogage.
        """
        # État du noyau
        status = {
            "core": {
                "active": self.active,
                "uptime": (datetime.now() - self.stats["start_time"]).total_seconds(),
                "cells_count": len(self.cells),
                "messages_processed": self.stats["messages_processed"],
                "last_alert": self.stats["last_alert"]
            },
            "cells": {}
        }
        
        # État de chaque cellule
        for name, cell in self.cells.items():
            status["cells"][name] = cell.get_status()
        
        return status
    
    def save_status(self, file_path: str = "status/biocybe_status.json"):
        """
        Sauvegarde l'état actuel du système dans un fichier JSON.
        
        Args:
            file_path: Chemin où sauvegarder le fichier d'état
        """
        try:
            # Créer le répertoire si nécessaire
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Récupérer l'état actuel
            status = self.get_status()
            
            # Sauvegarder dans le fichier
            with open(file_path, "w") as f:
                json.dump(status, f, indent=2)
            
            self.logger.info(f"État du système sauvegardé dans {file_path}")
            return True
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde de l'état: {e}")
            return False

# Point d'entrée si exécuté directement
if __name__ == "__main__":
    logger.info("BioCybe Core démarré en tant que module principal")
    
    # Vérifier les arguments pour le chemin de configuration
    config_path = "config/biocybe.yaml"
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    # Créer et démarrer le noyau
    core = BioCybeCore(config_path)
    
    # Charger les cellules (si spécifié dans la configuration)
    if core.config.get("cells", {}).get("autoload", True):
        core.load_cells_from_modules()
    
    # Démarrer le système
    core.start()
    
    try:
        # Maintenir le programme actif
        while core.active:
            import time
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("Interruption clavier détectée, arrêt du système...")
    
    finally:
        # Arrêter proprement le système
        core.stop()
        logger.info("BioCybe Core terminé")
