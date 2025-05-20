#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Lymphocytes B pour BioCybe.

Ce module implémente la détection basée sur les signatures, similaire 
aux lymphocytes B du système immunitaire qui produisent des anticorps 
spécifiques pour identifier et neutraliser les pathogènes.
"""

import os
import sys
import logging
import json
import hashlib
import yaml
import time
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Any, Callable, Optional, Union, Set, Tuple
import yara  # Nécessite l'installation de yara-python

# Import des classes du noyau BioCybe
from biocybe_core import BiologicalCell, CellMessage

# Configuration du logger
logger = logging.getLogger("biocybe.b_cell")

class SignatureDatabase:
    """
    Base de données de signatures pour les Lymphocytes B.
    Stocke et gère les signatures de malware connues.
    """
    
    def __init__(self, db_path: str = "db/signatures"):
        """
        Initialise la base de données de signatures.
        
        Args:
            db_path: Chemin vers le répertoire de la base de données
        """
        self.db_path = db_path
        self.signatures = {}  # hash -> info
        self.rules = None  # Règles YARA compilées
        self.last_update = None
        self.update_lock = threading.Lock()
        
        # Création du répertoire si nécessaire
        os.makedirs(db_path, exist_ok=True)
        
        # Sous-répertoires
        self.hash_db_path = os.path.join(db_path, "hashes")
        self.yara_rules_path = os.path.join(db_path, "yara")
        os.makedirs(self.hash_db_path, exist_ok=True)
        os.makedirs(self.yara_rules_path, exist_ok=True)
        
        # Chargement initial
        self.load_database()
    
    def load_database(self):
        """Charge la base de données depuis le disque"""
        try:
            # Chargement des signatures hash
            signatures_path = os.path.join(self.hash_db_path, "signatures.json")
            if os.path.exists(signatures_path):
                with open(signatures_path, "r") as f:
                    self.signatures = json.load(f)
                logger.info(f"Chargement de {len(self.signatures)} signatures hash")
            
            # Compilation des règles YARA
            self._compile_yara_rules()
            
            # Dernière mise à jour
            update_path = os.path.join(self.db_path, "last_update.txt")
            if os.path.exists(update_path):
                with open(update_path, "r") as f:
                    self.last_update = datetime.fromisoformat(f.read().strip())
                logger.info(f"Dernière mise à jour de la base de données: {self.last_update}")
        
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la base de données: {e}")
    
    def _compile_yara_rules(self):
        """Compile les règles YARA dans le répertoire spécifié"""
        try:
            # Liste des fichiers de règles
            rule_files = []
            for root, _, files in os.walk(self.yara_rules_path):
                for file in files:
                    if file.endswith((".yar", ".yara")):
                        rule_files.append(os.path.join(root, file))
            
            if not rule_files:
                logger.warning(f"Aucun fichier de règles YARA trouvé dans {self.yara_rules_path}")
                return
            
            # Compilation des règles
            filepaths = {f"rule_{i}": path for i, path in enumerate(rule_files)}
            self.rules = yara.compile(filepaths=filepaths)
            
            logger.info(f"Compilation de {len(rule_files)} fichiers de règles YARA")
        
        except Exception as e:
            logger.error(f"Erreur lors de la compilation des règles YARA: {e}")
    
    def save_database(self):
        """Sauvegarde la base de données sur le disque"""
        try:
            # Sauvegarde des signatures hash
            signatures_path = os.path.join(self.hash_db_path, "signatures.json")
            with open(signatures_path, "w") as f:
                json.dump(self.signatures, f, indent=2)
            
            # Dernière mise à jour
            update_path = os.path.join(self.db_path, "last_update.txt")
            self.last_update = datetime.now()
            with open(update_path, "w") as f:
                f.write(self.last_update.isoformat())
            
            logger.info("Base de données de signatures sauvegardée")
        
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la base de données: {e}")
    
    def add_hash_signature(self, file_hash: str, info: Dict):
        """
        Ajoute une signature hash à la base de données.
        
        Args:
            file_hash: Empreinte hash du fichier malveillant
            info: Informations sur le malware associé
        """
        with self.update_lock:
            self.signatures[file_hash] = info
    
    def add_yara_rule(self, rule_name: str, rule_content: str):
        """
        Ajoute une règle YARA à la base de données.
        
        Args:
            rule_name: Nom de la règle (sera utilisé comme nom de fichier)
            rule_content: Contenu de la règle YARA
        
        Returns:
            bool: True si la règle a été ajoutée avec succès, False sinon
        """
        with self.update_lock:
            try:
                # Vérifier la validité de la règle
                yara.compile(source=rule_content)
                
                # Sauvegarder dans un fichier
                rule_path = os.path.join(self.yara_rules_path, f"{rule_name}.yar")
                with open(rule_path, "w") as f:
                    f.write(rule_content)
                
                # Recompiler toutes les règles
                self._compile_yara_rules()
                
                logger.info(f"Règle YARA '{rule_name}' ajoutée à la base de données")
                return True
            
            except Exception as e:
                logger.error(f"Erreur lors de l'ajout de la règle YARA '{rule_name}': {e}")
                return False
    
    def check_file_hash(self, file_path: str) -> Tuple[bool, Dict]:
        """
        Vérifie si un fichier correspond à une signature hash connue.
        
        Args:
            file_path: Chemin vers le fichier à vérifier
        
        Returns:
            Tuple[bool, Dict]: (est_malveillant, informations)
        """
        try:
            # Calcul des hashes
            with open(file_path, "rb") as f:
                content = f.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha1_hash = hashlib.sha1(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
            
            # Vérification dans la base de données
            for hash_value in [md5_hash, sha1_hash, sha256_hash]:
                if hash_value in self.signatures:
                    return True, self.signatures[hash_value]
            
            return False, {}
        
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du hash du fichier {file_path}: {e}")
            return False, {"error": str(e)}
    
    def check_file_yara(self, file_path: str) -> Tuple[bool, List[Dict]]:
        """
        Vérifie si un fichier correspond à des règles YARA connues.
        
        Args:
            file_path: Chemin vers le fichier à vérifier
        
        Returns:
            Tuple[bool, List[Dict]]: (est_malveillant, règles correspondantes)
        """
        if not self.rules:
            logger.warning("Aucune règle YARA disponible pour l'analyse")
            return False, []
        
        try:
            # Recherche de correspondances
            matches = self.rules.match(file_path)
            
            if matches:
                results = []
                for match in matches:
                    results.append({
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": [(s.identifier, s.offset, s.data) for s in match.strings]
                    })
                
                return True, results
            
            return False, []
        
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse YARA du fichier {file_path}: {e}")
            return False, [{"error": str(e)}]
    
    def update_from_community(self, community_url: str = None):
        """
        Met à jour la base de données depuis des sources communautaires.
        
        Args:
            community_url: URL de la source communautaire (optionnel)
        
        Returns:
            bool: True si la mise à jour a réussi, False sinon
        """
        # Implémentation basique, à développer avec des sources réelles
        logger.info("Mise à jour depuis les sources communautaires non implémentée")
        return False


class ScanResult:
    """Classe représentant le résultat d'une analyse de signatures"""
    
    def __init__(self):
        self.is_malicious = False
        self.confidence = 0.0
        self.malware_family = None
        self.severity = "unknown"
        self.matched_signatures = []
        self.matched_rules = []
        self.detection_time = datetime.now()
        self.scan_duration = 0.0
        self.file_info = {}
    
    def __str__(self):
        if self.is_malicious:
            return (f"Malveillant: Oui | Famille: {self.malware_family} | "
                   f"Sévérité: {self.severity} | Confiance: {self.confidence:.2f}")
        else:
            return f"Malveillant: Non | Confiance: {self.confidence:.2f}"
    
    def to_dict(self):
        """Convertit le résultat en dictionnaire"""
        return {
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "malware_family": self.malware_family,
            "severity": self.severity,
            "matched_signatures": self.matched_signatures,
            "matched_rules": self.matched_rules,
            "detection_time": self.detection_time.isoformat(),
            "scan_duration": self.scan_duration,
            "file_info": self.file_info
        }


class BCell(BiologicalCell):
    """
    Cellule Lymphocyte B de BioCybe.
    
    Analyse les fichiers en se basant sur des signatures connues (hashes, YARA)
    pour détecter des menaces connues, similaire aux anticorps du système immunitaire.
    """
    
    def __init__(self, name: str, config: Dict = None):
        """
        Initialise une cellule Lymphocyte B.
        
        Args:
            name: Nom unique de cette instance
            config: Configuration spécifique à la cellule
        """
        super().__init__(name, "b_cell", config)
        
        # Configuration
        self.config = config or {}
        self.db_path = self.config.get("db_path", "db/signatures")
        self.scan_queue = queue.PriorityQueue()
        self.results_cache = {}  # file_path -> (timestamp, result)
        self.cache_expiry = timedelta(minutes=self.config.get("cache_expiry_minutes", 30))
        
        # Initialisation de la base de données
        self.db = SignatureDatabase(self.db_path)
        
        # État
        self.files_scanned = 0
        self.malware_detected = 0
        
        # Enregistrer les gestionnaires de messages
        self.register_message_handler("scan_request", self._handle_scan_request)
        self.register_message_handler("alert_anomaly", self._handle_anomaly_alert)
        self.register_message_handler("update_signatures", self._handle_update_signatures)
        
        self.logger.info(f"Lymphocyte B '{name}' initialisé avec {len(self.db.signatures)} signatures hash")
    
    def _process_cycle(self):
        """
        Traitement d'un cycle d'activité de la cellule.
        Vérifie s'il y a des tâches de scan en attente.
        """
        try:
            # Récupération d'une tâche (avec timeout pour ne pas bloquer)
            try:
                priority, task = self.scan_queue.get(block=False)
                
                # Traitement de la tâche
                file_path, callback = task
                result = self._scan_file(file_path)
                
                # Mise en cache
                self.results_cache[file_path] = (datetime.now(), result)
                
                # Callback si fourni
                if callback:
                    callback(result)
                
                # Marquer comme terminé
                self.scan_queue.task_done()
                
                # Si malveillant, alerter les autres cellules
                if result.is_malicious:
                    self.malware_detected += 1
                    self._alert_malware_detection(file_path, result)
            
            except queue.Empty:
                pass
        
        except Exception as e:
            self.logger.error(f"Erreur dans le cycle de traitement: {e}")
    
    def scan_file(self, file_path: str, callback: Callable = None, priority: int = 2):
        """
        Ajoute un fichier à la file d'attente de scan.
        
        Args:
            file_path: Chemin vers le fichier à scanner
            callback: Fonction à appeler avec le résultat du scan
            priority: Priorité du scan (1=haute, 5=basse)
        """
        # Vérifier si le résultat est en cache et toujours valide
        if file_path in self.results_cache:
            timestamp, result = self.results_cache[file_path]
            if datetime.now() - timestamp < self.cache_expiry:
                if callback:
                    callback(result)
                return
        
        # Sinon, ajouter à la file d'attente
        self.scan_queue.put((priority, (file_path, callback)))
        self.logger.debug(f"Fichier {file_path} ajouté à la file de scan (priorité: {priority})")
    
    def scan_file_sync(self, file_path: str) -> ScanResult:
        """
        Scanne un fichier de manière synchrone et retourne le résultat.
        
        Args:
            file_path: Chemin vers le fichier à scanner
        
        Returns:
            ScanResult: Résultat de l'analyse
        """
        return self._scan_file(file_path)
    
    def _scan_file(self, file_path: str) -> ScanResult:
        """
        Effectue l'analyse d'un fichier à la recherche de signatures connues.
        
        Args:
            file_path: Chemin vers le fichier à scanner
        
        Returns:
            ScanResult: Résultat de l'analyse
        """
        result = ScanResult()
        start_time = time.time()
        
        try:
            # Vérifier que le fichier existe
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"Le fichier {file_path} n'existe pas")
            
            # Informations sur le fichier
            file_stats = os.stat(file_path)
            result.file_info = {
                "path": file_path,
                "size": file_stats.st_size,
                "modified": datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                "created": datetime.fromtimestamp(file_stats.st_ctime).isoformat()
            }
            
            # Vérification par hash
            is_malicious, hash_info = self.db.check_file_hash(file_path)
            
            if is_malicious:
                result.is_malicious = True
                result.confidence = 1.0  # Confiance maximale pour une correspondance par hash
                result.malware_family = hash_info.get("family", "unknown")
                result.severity = hash_info.get("severity", "high")
                result.matched_signatures.append({
                    "type": "hash",
                    "value": hash_info.get("hash", "unknown"),
                    "info": hash_info
                })
            else:
                # Vérification par règles YARA
                is_malicious_yara, yara_matches = self.db.check_file_yara(file_path)
                
                if is_malicious_yara:
                    result.is_malicious = True
                    
                    # Analyse des résultats YARA
                    severities = []
                    families = []
                    
                    for match in yara_matches:
                        result.matched_rules.append(match)
                        
                        # Extraction des métadonnées
                        meta = match.get("meta", {})
                        if "severity" in meta:
                            severities.append(meta["severity"])
                        
                        if "family" in meta:
                            families.append(meta["family"])
                    
                    # Détermination de la famille
                    if families:
                        # Prendre la famille la plus fréquente
                        from collections import Counter
                        family_counts = Counter(families)
                        result.malware_family = family_counts.most_common(1)[0][0]
                    
                    # Détermination de la sévérité
                    if severities:
                        severity_order = {
                            "critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0
                        }
                        result.severity = max(
                            severities, key=lambda s: severity_order.get(s, 0)
                        )
                    
                    # Confiance basée sur le nombre de règles correspondantes
                    result.confidence = min(0.95, len(yara_matches) / 10.0 + 0.5)
            
            # Mettre à jour les statistiques
            self.files_scanned += 1
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse du fichier {file_path}: {e}")
            result.file_info["error"] = str(e)
        
        # Durée du scan
        result.scan_duration = time.time() - start_time
        result.detection_time = datetime.now()
        
        return result
    
    def _alert_malware_detection(self, file_path: str, result: ScanResult):
        """
        Alerte les autres cellules de la détection d'un malware.
        
        Args:
            file_path: Chemin vers le fichier détecté
            result: Résultat de l'analyse
        """
        # Déterminer la priorité en fonction de la sévérité
        severity_priority = {
            "critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1
        }
        priority = severity_priority.get(result.severity, 3)
        
        # Envoyer une alerte aux cellules NK pour action immédiate si critique ou élevé
        if result.severity in ["critical", "high"]:
            self.send_message(
                msg_type="alert_malware",
                target="type:nk_cell",
                payload={
                    "file_path": file_path,
                    "result": result.to_dict(),
                    "action_required": True,
                    "detected_by": self.name
                },
                priority=priority
            )
        
        # Envoyer l'information à toutes les cellules
        self.send_message(
            msg_type="malware_detected",
            target="broadcast",
            payload={
                "file_path": file_path,
                "result": result.to_dict(),
                "detected_by": self.name
            },
            priority=3
        )
        
        # Envoyer aux cellules de mémoire pour apprentissage
        self.send_message(
            msg_type="learn_signature",
            target="type:memory_cell",
            payload={
                "file_path": file_path,
                "result": result.to_dict(),
                "hash_signatures": {
                    key: self.db.signatures[key] 
                    for key in result.matched_signatures if key in self.db.signatures
                },
                "detected_by": self.name
            },
            priority=2
        )
        
        self.logger.info(
            f"Alerte malware émise pour {file_path}: {result.malware_family} "
            f"(Sévérité: {result.severity}, Confiance: {result.confidence:.2f})"
        )
        self.stats["actions_performed"] += 1
    
    def _handle_scan_request(self, message: CellMessage):
        """
        Gère une demande de scan.
        
        Args:
            message: Message de demande de scan
        """
        # Extraire les paramètres de la demande
        payload = message.payload or {}
        file_path = payload.get("file_path")
        
        if not file_path:
            self.logger.warning(f"Demande de scan sans chemin de fichier reçue de {message.source}")
            return
        
        # Préparer une fonction de callback pour répondre
        def scan_callback(result):
            self.send_message(
                msg_type="scan_result",
                target=message.source,
                payload={
                    "file_path": file_path,
                    "result": result.to_dict(),
                    "scanned_by": self.name
                }
            )
        
        # Lancer le scan
        priority = payload.get("priority", 2)
        self.scan_file(file_path, scan_callback, priority)
        self.logger.info(f"Demande de scan pour {file_path} reçue de {message.source}")
    
    def _handle_anomaly_alert(self, message: CellMessage):
        """
        Gère une alerte d'anomalie des macrophages ou cellules T.
        
        Args:
            message: Message d'alerte d'anomalie
        """
        payload = message.payload or {}
        anomaly_type = payload.get("type")
        
        # Si c'est une anomalie liée à un fichier, le scanner
        if anomaly_type in ["suspicious_file_created", "unknown_executable"]:
            anomalies = payload.get("anomalies", [])
            
            for anomaly in anomalies:
                file_path = anomaly.get("details", {}).get("path")
                if file_path and os.path.exists(file_path):
                    self.logger.info(f"Scan de fichier suspect suite à une alerte: {file_path}")
                    
                    # Scanner avec priorité élevée
                    self.scan_file(file_path, priority=1)
    
    def _handle_update_signatures(self, message: CellMessage):
        """
        Gère une demande de mise à jour des signatures.
        
        Args:
            message: Message de demande de mise à jour
        """
        payload = message.payload or {}
        source_url = payload.get("source_url")
        
        self.logger.info(f"Mise à jour des signatures demandée par {message.source}")
        
        # Tenter la mise à jour
        success = self.db.update_from_community(source_url)
        
        # Répondre
        self.send_message(
            msg_type="update_result",
            target=message.source,
            payload={
                "success": success,
                "timestamp": datetime.now().isoformat(),
                "message": "Mise à jour des signatures effectuée" if success else 
                           "Échec de la mise à jour des signatures"
            }
        )

def create_cells(config: Dict) -> List[BiologicalCell]:
    """
    Crée les instances de cellules Lymphocytes B selon la configuration.
    
    Args:
        config: Configuration du système
    
    Returns:
        List[BiologicalCell]: Liste des cellules créées
    """
    cells = []
    
    # Configuration des lymphocytes B
    b_cell_config = config.get("cells", {}).get("b_cell", {})
    
    # Créer les instances par défaut si aucune configuration spécifique
    if not b_cell_config:
        cells.append(BCell("b_cell_main"))
    else:
        # Créer les instances selon la configuration
        instances = b_cell_config.get("instances", [{"name": "b_cell_main"}])
        for instance in instances:
            cell_name = instance.get("name", f"b_cell_{len(cells)}")
            cell_config = instance.get("config", {})
            cells.append(BCell(cell_name, cell_config))
    
    return cells

# Test si exécuté directement
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Test du module Lymphocyte B")
    
    # Créer une cellule de test
    cell = BCell("test_b_cell")
    
    # Tester sur un fichier
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        logger.info(f"Analyse du fichier: {file_path}")
        
        result = cell.scan_file_sync(file_path)
        
        print(f"Résultat: {result}")
        if result.is_malicious:
            print(f"Malware détecté!")
            print(f"Famille: {result.malware_family}")
            print(f"Sévérité: {result.severity}")
            print(f"Confiance: {result.confidence:.2f}")
            
            if result.matched_signatures:
                print("Signatures correspondantes:")
                for sig in result.matched_signatures:
                    print(f"  - {sig['type']}: {sig.get('value', 'N/A')}")
            
            if result.matched_rules:
                print("Règles YARA correspondantes:")
                for rule in result.matched_rules:
                    print(f"  - {rule['rule']}")
        else:
            print("Aucun malware détecté")
