#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de détection par signatures pour BioCybe.
Fonctionne comme les anticorps du système immunitaire en identifiant
des signatures spécifiques de malwares.
"""

import os
import logging
import yara
import hashlib
import magic
import time
import yaml
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Union, Set
import threading
import queue

# Configuration du logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class SignatureResult:
    """Classe représentant le résultat d'une analyse de signatures"""
    
    def __init__(self):
        self.is_malicious = False
        self.matched_rules = []
        self.malware_family = None
        self.severity = "unknown"
        self.confidence = 0.0
        self.metadata = {}
        self.scan_time = None
        self.file_info = {}
    
    def __str__(self):
        if self.is_malicious:
            return f"Malveillant: Oui | Famille: {self.malware_family} | Sévérité: {self.severity} | Confiance: {self.confidence:.2f} | Règles: {', '.join(self.matched_rules)}"
        else:
            return f"Malveillant: Non | Confiance: {self.confidence:.2f}"
    
    def to_dict(self):
        """Convertit le résultat en dictionnaire"""
        return {
            "is_malicious": self.is_malicious,
            "matched_rules": self.matched_rules,
            "malware_family": self.malware_family,
            "severity": self.severity,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "scan_time": self.scan_time.isoformat() if self.scan_time else None,
            "file_info": self.file_info
        }

class SignatureDatabase:
    """Gère la base de données de signatures (analogue à la mémoire immunitaire)"""
    
    def __init__(self, db_path="db/signatures"):
        self.db_path = db_path
        self.signatures = {}  # hash -> info
        self.yara_rules = {}  # rule_name -> info
        self.last_update = None
        self.update_lock = threading.Lock()
        
        # Création du répertoire si nécessaire
        os.makedirs(db_path, exist_ok=True)
        
        # Chargement initial
        self.load_database()
    
    def load_database(self):
        """Charge la base de données depuis le disque"""
        try:
            sig_path = os.path.join(self.db_path, "hash_signatures.json")
            if os.path.exists(sig_path):
                with open(sig_path, "r") as f:
                    self.signatures = json.load(f)
                logger.info(f"Chargement de {len(self.signatures)} signatures hash")
            
            yara_path = os.path.join(self.db_path, "yara_info.json")
            if os.path.exists(yara_path):
                with open(yara_path, "r") as f:
                    self.yara_rules = json.load(f)
                logger.info(f"Chargement de {len(self.yara_rules)} informations sur les règles YARA")
            
            # Dernière mise à jour
            update_path = os.path.join(self.db_path, "last_update.txt")
            if os.path.exists(update_path):
                with open(update_path, "r") as f:
                    self.last_update = datetime.fromisoformat(f.read().strip())
                logger.info(f"Dernière mise à jour: {self.last_update}")
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la base de données: {e}")
    
    def save_database(self):
        """Sauvegarde la base de données sur le disque"""
        try:
            # Sauvegarde des signatures hash
            sig_path = os.path.join(self.db_path, "hash_signatures.json")
            with open(sig_path, "w") as f:
                json.dump(self.signatures, f, indent=2)
            
            # Sauvegarde des infos YARA
            yara_path = os.path.join(self.db_path, "yara_info.json")
            with open(yara_path, "w") as f:
                json.dump(self.yara_rules, f, indent=2)
            
            # Dernière mise à jour
            update_path = os.path.join(self.db_path, "last_update.txt")
            self.last_update = datetime.now()
            with open(update_path, "w") as f:
                f.write(self.last_update.isoformat())
            
            logger.info("Base de données de signatures sauvegardée")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la base de données: {e}")
    
    def add_hash_signature(self, file_hash, info):
        """Ajoute une signature hash à la base de données"""
        with self.update_lock:
            self.signatures[file_hash] = info
    
    def add_yara_rule_info(self, rule_name, info):
        """Ajoute des informations sur une règle YARA"""
        with self.update_lock:
            self.yara_rules[rule_name] = info
    
    def check_hash(self, file_hash):
        """Vérifie si un hash est dans la base de données"""
        return file_hash in self.signatures
    
    def get_hash_info(self, file_hash):
        """Récupère les informations associées à un hash"""
        return self.signatures.get(file_hash, None)
    
    def get_yara_rule_info(self, rule_name):
        """Récupère les informations associées à une règle YARA"""
        return self.yara_rules.get(rule_name, None)
    
    def update_from_external(self, api_key=None, source="virustotal"):
        """Met à jour la base de données depuis une source externe"""
        # Cette fonction serait implémentée pour se connecter à des API externes
        # et récupérer de nouvelles signatures
        logger.info(f"Mise à jour depuis {source} non implémentée")
        return False

class SignatureDetector:
    """Détecteur de malwares basé sur les signatures (anticorps numériques)"""
    
    def __init__(self, config_path="config/detection.yaml"):
        """Initialisation du détecteur de signatures"""
        self.config = self._load_config(config_path)
        self.rules = None
        self.db = SignatureDatabase()
        self.external_apis = {}
        
        # Chargement des règles YARA
        self._load_yara_rules()
        
        # Configuration des API externes
        self._setup_external_apis()
        
        # File d'attente pour les analyses
        self.scan_queue = queue.Queue()
        self.results_cache = {}  # path -> result
        
        # Démarrage du thread de scan
        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()
    
    def _load_config(self, config_path):
        """Charge la configuration depuis un fichier YAML"""
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
                return config
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {e}")
            # Configuration par défaut
            return {
                "signatures": {
                    "yara_rules_path": "rules/yara",
                    "update_interval": 3600
                }
            }
    
    def _load_yara_rules(self):
        """Charge les règles YARA depuis le répertoire configuré"""
        try:
            rules_path = self.config.get("signatures", {}).get("yara_rules_path", "rules/yara")
            
            # Liste des fichiers de règles
            rule_files = []
            if os.path.isdir(rules_path):
                for root, _, files in os.walk(rules_path):
                    for file in files:
                        if file.endswith(('.yar', '.yara')):
                            rule_files.append(os.path.join(root, file))
            else:
                if os.path.exists(rules_path) and rules_path.endswith(('.yar', '.yara')):
                    rule_files.append(rules_path)
            
            if not rule_files:
                logger.warning(f"Aucun fichier de règles YARA trouvé dans {rules_path}")
                return
            
            # Compilation des règles
            filepaths = {f"rule_{i}": path for i, path in enumerate(rule_files)}
            self.rules = yara.compile(filepaths=filepaths)
            
            logger.info(f"Chargement de {len(rule_files)} fichiers de règles YARA")
        except Exception as e:
            logger.error(f"Erreur lors du chargement des règles YARA: {e}")
    
    def _setup_external_apis(self):
        """Configure les API externes pour la vérification de fichiers"""
        api_configs = self.config.get("signatures", {}).get("external_sources", {})
        
        for api_name, api_config in api_configs.items():
            if api_config.get("enabled", False) and api_config.get("api_key"):
                self.external_apis[api_name] = {
                    "api_key": api_config["api_key"],
                    "url": api_config.get("url", "")
                }
                logger.info(f"API externe configurée: {api_name}")
    
    def _scan_worker(self):
        """Thread travailleur pour traiter la file d'attente d'analyses"""
        while True:
            try:
                # Récupération d'une tâche
                task = self.scan_queue.get()
                if task is None:
                    break
                
                file_path, callback = task
                
                # Analyse du fichier
                result = self._scan_file_internal(file_path)
                
                # Cache du résultat
                self.results_cache[file_path] = result
                
                # Appel du callback si fourni
                if callback:
                    callback(result)
                
                # Marquer la tâche comme terminée
                self.scan_queue.task_done()
            except Exception as e:
                logger.error(f"Erreur dans le thread de scan: {e}")
    
    def scan_file(self, file_path, callback=None):
        """
        Analyse un fichier de manière asynchrone.
        Si callback est fourni, il sera appelé avec le résultat.
        """
        # Vérifier si le résultat est dans le cache
        if file_path in self.results_cache:
            if (datetime.now() - self.results_cache[file_path].scan_time) < timedelta(minutes=10):
                if callback:
                    callback(self.results_cache[file_path])
                return self.results_cache[file_path]
        
        # Ajouter à la file d'attente
        self.scan_queue.put((file_path, callback))
    
    def scan_file_sync(self, file_path):
        """Analyse un fichier de manière synchrone et retourne le résultat"""
        return self._scan_file_internal(file_path)
    
    def _scan_file_internal(self, file_path):
        """Effectue l'analyse complète d'un fichier"""
        # Initialisation du résultat
        result = SignatureResult()
        result.scan_time = datetime.now()
        
        try:
            # Vérification de l'existence du fichier
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                raise FileNotFoundError(f"Le fichier n'existe pas: {file_path}")
            
            # Collecte d'informations sur le fichier
            file_info = self._get_file_info(file_path)
            result.file_info = file_info
            
            # Vérification du hash
            if self.db.check_hash(file_info["md5"]):
                hash_info = self.db.get_hash_info(file_info["md5"])
                result.is_malicious = True
                result.malware_family = hash_info.get("family", "unknown")
                result.severity = hash_info.get("severity", "high")
                result.confidence = 1.0
                result.matched_rules.append(f"hash_match:{file_info['md5']}")
                result.metadata["hash_match"] = hash_info
                return result
            
            # Si le fichier est trop gros, on ne fait pas d'analyse YARA
            max_size = self.config.get("static_analysis", {}).get("max_file_size", 100000000)
            if file_info["size"] > max_size:
                logger.warning(f"Fichier trop volumineux pour l'analyse YARA: {file_path}")
                return result
            
            # Analyse YARA
            if self.rules:
                yara_matches = self.rules.match(file_path)
                if yara_matches:
                    result.is_malicious = True
                    
                    # Traitement des correspondances
                    severities = []
                    families = []
                    confidence = 0.0
                    
                    for match in yara_matches:
                        rule_name = match.rule
                        result.matched_rules.append(rule_name)
                        
                        # Récupération des métadonnées de la règle
                        rule_meta = match.meta
                        if "severity" in rule_meta:
                            severities.append(rule_meta["severity"])
                        
                        if "category" in rule_meta and rule_meta["category"] == "ransomware":
                            families.append("ransomware")
                        elif "family" in rule_meta:
                            families.append(rule_meta["family"])
                        
                        # Stockage des métadonnées
                        result.metadata[rule_name] = rule_meta
                        
                        # Confiance basée sur le nombre de chaînes correspondantes
                        match_confidence = min(1.0, len(match.strings) / 10.0)
                        confidence = max(confidence, match_confidence)
                    
                    # Détermination de la famille de malware
                    if families:
                        # Prendre la famille la plus fréquente
                        from collections import Counter
                        family_counts = Counter(families)
                        result.malware_family = family_counts.most_common(1)[0][0]
                    
                    # Détermination de la sévérité
                    if severities:
                        # Ordre de priorité
                        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
                        highest_severity = max(severities, key=lambda s: severity_order.get(s, 0))
                        result.severity = highest_severity
                    
                    # Confiance globale
                    result.confidence = min(0.95, confidence)
            
            # Analyse avec les API externes si nécessaire
            if not result.is_malicious and self.external_apis:
                for api_name, api_config in self.external_apis.items():
                    if api_name == "virustotal":
                        ext_result = self._check_virustotal(file_info["sha256"], api_config["api_key"])
                        if ext_result and ext_result.get("positives", 0) > 0:
                            result.is_malicious = True
                            result.confidence = min(0.99, ext_result.get("positives", 0) / ext_result.get("total", 1))
                            result.matched_rules.append(f"virustotal:{ext_result.get('positives')}/{ext_result.get('total')}")
                            result.metadata["virustotal"] = ext_result
                            break
            
            return result
        
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du fichier {file_path}: {e}")
            result.metadata["error"] = str(e)
            return result
    
    def _get_file_info(self, file_path):
        """Collecte les informations de base sur un fichier"""
        info = {}
        try:
            # Taille et timestamps
            stats = os.stat(file_path)
            info["size"] = stats.st_size
            info["created"] = datetime.fromtimestamp(stats.st_ctime).isoformat()
            info["modified"] = datetime.fromtimestamp(stats.st_mtime).isoformat()
            info["accessed"] = datetime.fromtimestamp(stats.st_atime).isoformat()
            
            # Type de fichier
            info["mime"] = magic.Magic(mime=True).from_file(file_path)
            
            # Calcul des hashes
            with open(file_path, "rb") as f:
                content = f.read()
                info["md5"] = hashlib.md5(content).hexdigest()
                info["sha1"] = hashlib.sha1(content).hexdigest()
                info["sha256"] = hashlib.sha256(content).hexdigest()
            
            # Entropie (mesure du caractère aléatoire/chiffré)
            import math
            entropy = 0.0
            if content:
                byte_counts = {}
                for byte in content:
                    if byte in byte_counts:
                        byte_counts[byte] += 1
                    else:
                        byte_counts[byte] = 1
                
                for count in byte_counts.values():
                    probability = count / len(content)
                    entropy -= probability * math.log2(probability)
            
            info["entropy"] = entropy
            
            return info
        except Exception as e:
            logger.error(f"Erreur lors de la collecte d'informations sur le fichier {file_path}: {e}")
            return {
                "error": str(e),
                "size": 0,
                "md5": "",
                "sha1": "",
                "sha256": "",
                "mime": "unknown",
                "entropy": 0.0
            }
    
    def _check_virustotal(self, file_hash, api_key):
        """Vérifie un hash sur VirusTotal"""
        try:
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {"apikey": api_key, "resource": file_hash}
            
            response = requests.get(url, params=params)
            if response.status_code == 200:
                result = response.json()
                return result
            else:
                logger.warning(f"Erreur lors de la vérification VirusTotal: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Erreur lors de la vérification VirusTotal: {e}")
            return None
    
    def update_rules(self):
        """Met à jour les règles YARA et la base de données de signatures"""
        try:
            # Rechargement des règles YARA
            self._load_yara_rules()
            
            # Mise à jour depuis les sources externes
            for api_name, api_config in self.external_apis.items():
                self.db.update_from_external(api_config["api_key"], source=api_name)
            
            # Sauvegarde de la base de données
            self.db.save_database()
            
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour des règles: {e}")
            return False
    
    def shutdown(self):
        """Arrête proprement le détecteur"""
        # Arrêt du thread de scan
        self.scan_queue.put(None)
        self.scan_thread.join(timeout=5)
        
        # Sauvegarde des données
        self.db.save_database()
        
        logger.info("Détecteur de signatures arrêté")

# Exemple d'utilisation
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python signature_detector.py <fichier_à_analyser>")
        sys.exit(1)
    
    detector = SignatureDetector()
    result = detector.scan_file_sync(sys.argv[1])
    
    print("=== Résultat de l'analyse ===")
    print(result)
    
    if result.is_malicious:
        print("\nDétails:")
        for rule in result.matched_rules:
            print(f"- Règle: {rule}")
        
        print(f"\nFamille de malware: {result.malware_family}")
        print(f"Sévérité: {result.severity}")
        print(f"Confiance: {result.confidence:.2f}")
    
    detector.shutdown()
