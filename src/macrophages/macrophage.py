#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Macrophages pour BioCybe.

Ce module implémente la détection passive des menaces à travers une surveillance
continue du système, similaire aux macrophages du système immunitaire qui
patrouillent constamment à la recherche de pathogènes.
"""

import os
import sys
import logging
import psutil
import time
import json
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Any, Set, Optional, Tuple
import hashlib

# Import des classes du noyau BioCybe
from biocybe_core import BiologicalCell, CellMessage

# Configuration du logger
logger = logging.getLogger("biocybe.macrophage")

class SystemMonitor:
    """
    Classe de surveillance du système et des métriques clés.
    Collecte les données que les Macrophages utiliseront pour la détection.
    """
    
    def __init__(self):
        """Initialise le moniteur système"""
        self.baseline = None  # Référence de base pour les métriques
        self.last_scan = None  # Dernière analyse complète
        self.anomalies = []  # Anomalies détectées
    
    def collect_system_metrics(self) -> Dict:
        """
        Collecte les métriques système essentielles.
        
        Returns:
            Dict: Métriques système collectées
        """
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "cpu": {
                "percent": psutil.cpu_percent(interval=1),
                "count": psutil.cpu_count(),
                "freq": psutil.cpu_freq().current if psutil.cpu_freq() else None,
                "load_avg": os.getloadavg() if hasattr(os, 'getloadavg') else None
            },
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent,
                "swap_percent": psutil.swap_memory().percent
            },
            "disk": {
                "usage_percent": psutil.disk_usage('/').percent,
                "io_counters": psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else None
            },
            "network": {
                "connections": len(psutil.net_connections()),
                "io_counters": psutil.net_io_counters()._asdict() if psutil.net_io_counters() else None
            },
            "processes": {
                "count": len(psutil.pids()),
                "new": []  # Sera rempli avec les nouveaux processus
            }
        }
        
        return metrics
    
    def scan_processes(self) -> Dict:
        """
        Analyse les processus en cours d'exécution pour identifier
        les nouveaux et les suspects.
        
        Returns:
            Dict: Résultats de l'analyse des processus
        """
        process_info = {}
        new_processes = []
        suspicious_processes = []
        
        # Liste des commandes suspectes (regex-like patterns)
        suspicious_commands = [
            "nc -e", "bash -i >", "sh -i", "python -c \"import os; os.system",
            "wget -O- | sh", "curl | sh", "chmod 777", "dd if=/dev/zero",
            "rm -rf /", ".decode('base64')", "eval(", "exec(", "base64 -d"
        ]
        
        # Récupérer les informations sur les processus
        for pid in psutil.pids():
            try:
                proc = psutil.Process(pid)
                
                # Informations de base sur le processus
                proc_info = {
                    "pid": pid,
                    "name": proc.name(),
                    "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
                    "user": proc.username(),
                    "status": proc.status(),
                    "cpu_percent": proc.cpu_percent(),
                    "memory_percent": proc.memory_percent()
                }
                
                # Récupérer la ligne de commande si possible
                try:
                    cmdline = " ".join(proc.cmdline())
                    proc_info["cmdline"] = cmdline
                    
                    # Vérifier si le processus est suspect
                    is_suspicious = False
                    for pattern in suspicious_commands:
                        if pattern in cmdline:
                            is_suspicious = True
                            break
                    
                    if is_suspicious:
                        proc_info["suspicious"] = True
                        proc_info["reason"] = f"Commande suspecte contenant '{pattern}'"
                        suspicious_processes.append(proc_info)
                
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    proc_info["cmdline"] = "Access denied"
                
                # Déterminer si c'est un nouveau processus
                if self.last_scan is not None:
                    # Considérer comme nouveau si créé après le dernier scan
                    proc_create_time = datetime.fromisoformat(proc_info["create_time"])
                    if proc_create_time > self.last_scan:
                        new_processes.append(proc_info)
                
                # Stocker les informations
                process_info[pid] = proc_info
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return {
            "timestamp": datetime.now().isoformat(),
            "processes": process_info,
            "new_processes": new_processes,
            "suspicious_processes": suspicious_processes,
            "process_count": len(process_info)
        }
    
    def scan_network_connections(self) -> Dict:
        """
        Analyse les connexions réseau pour identifier
        les connexions suspectes.
        
        Returns:
            Dict: Résultats de l'analyse réseau
        """
        connections = []
        suspicious_connections = []
        
        # Liste des ports suspects
        suspicious_ports = [4444, 1337, 31337, 8080, 31338, 4545]
        
        try:
            # Récupérer toutes les connexions
            for conn in psutil.net_connections():
                conn_info = {
                    "fd": conn.fd,
                    "family": conn.family,
                    "type": conn.type,
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid
                }
                
                # Ajouter le nom du processus si possible
                if conn.pid:
                    try:
                        conn_info["process_name"] = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        conn_info["process_name"] = "Unknown"
                
                # Vérifier si la connexion est suspecte
                is_suspicious = False
                if conn.raddr:
                    # Vérifier si le port distant est suspect
                    if conn.raddr.port in suspicious_ports:
                        is_suspicious = True
                        conn_info["suspicious"] = True
                        conn_info["reason"] = f"Port distant suspect: {conn.raddr.port}"
                
                connections.append(conn_info)
                if is_suspicious:
                    suspicious_connections.append(conn_info)
        
        except (psutil.AccessDenied, Exception) as e:
            logger.error(f"Erreur lors de l'analyse des connexions réseau: {e}")
        
        return {
            "timestamp": datetime.now().isoformat(),
            "connections": connections,
            "suspicious_connections": suspicious_connections,
            "connection_count": len(connections)
        }
    
    def scan_file_changes(self, directories: List[str]) -> Dict:
        """
        Analyse les modifications de fichiers dans les répertoires spécifiés.
        
        Args:
            directories: Liste des répertoires à surveiller
        
        Returns:
            Dict: Résultats de l'analyse des fichiers
        """
        file_changes = {
            "timestamp": datetime.now().isoformat(),
            "scanned_directories": directories,
            "new_files": [],
            "modified_files": [],
            "deleted_files": [],
            "suspicious_files": []
        }
        
        # Liste des extensions suspectes
        suspicious_extensions = [".exe", ".dll", ".sh", ".py", ".rb", ".pl"]
        
        # Parcourir les répertoires
        for directory in directories:
            if not os.path.exists(directory):
                continue
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Obtenir les statistiques du fichier
                        stats = os.stat(file_path)
                        
                        # Vérifier si c'est un fichier suspect (par extension)
                        _, ext = os.path.splitext(file_path)
                        if ext.lower() in suspicious_extensions:
                            file_changes["suspicious_files"].append({
                                "path": file_path,
                                "reason": f"Extension suspecte: {ext}",
                                "size": stats.st_size,
                                "modified": datetime.fromtimestamp(stats.st_mtime).isoformat()
                            })
                        
                        # Autres analyses de fichiers pourraient être ajoutées ici
                        
                    except (PermissionError, FileNotFoundError):
                        continue
        
        return file_changes
    
    def establish_baseline(self):
        """
        Établit une ligne de base pour les métriques système.
        Cette référence sera utilisée pour détecter les anomalies.
        """
        self.baseline = {
            "system_metrics": self.collect_system_metrics(),
            "processes": self.scan_processes(),
            "connections": self.scan_network_connections(),
            "timestamp": datetime.now().isoformat()
        }
        
        self.last_scan = datetime.now()
        logger.info("Baseline système établie")
    
    def detect_anomalies(self) -> List[Dict]:
        """
        Détecte les anomalies en comparant les métriques actuelles
        avec la ligne de base.
        
        Returns:
            List[Dict]: Liste des anomalies détectées
        """
        if not self.baseline:
            logger.warning("Aucune baseline établie, impossible de détecter les anomalies")
            return []
        
        anomalies = []
        current_metrics = self.collect_system_metrics()
        
        # Vérifier l'utilisation CPU anormale (si augmentation de plus de 30%)
        baseline_cpu = self.baseline["system_metrics"]["cpu"]["percent"]
        current_cpu = current_metrics["cpu"]["percent"]
        if current_cpu > (baseline_cpu * 1.3) and current_cpu > 70:
            anomalies.append({
                "type": "high_cpu_usage",
                "severity": "medium",
                "details": {
                    "baseline": baseline_cpu,
                    "current": current_cpu,
                    "increase_percent": ((current_cpu - baseline_cpu) / baseline_cpu) * 100
                },
                "timestamp": datetime.now().isoformat()
            })
        
        # Vérifier l'utilisation mémoire anormale
        baseline_mem = self.baseline["system_metrics"]["memory"]["percent"]
        current_mem = current_metrics["memory"]["percent"]
        if current_mem > (baseline_mem * 1.3) and current_mem > 80:
            anomalies.append({
                "type": "high_memory_usage",
                "severity": "medium",
                "details": {
                    "baseline": baseline_mem,
                    "current": current_mem,
                    "increase_percent": ((current_mem - baseline_mem) / baseline_mem) * 100
                },
                "timestamp": datetime.now().isoformat()
            })
        
        # Vérifier les connexions réseau
        current_connections = self.scan_network_connections()
        if current_connections["suspicious_connections"]:
            for conn in current_connections["suspicious_connections"]:
                anomalies.append({
                    "type": "suspicious_network_connection",
                    "severity": "high",
                    "details": conn,
                    "timestamp": datetime.now().isoformat()
                })
        
        # Vérifier les processus
        current_processes = self.scan_processes()
        if current_processes["suspicious_processes"]:
            for proc in current_processes["suspicious_processes"]:
                anomalies.append({
                    "type": "suspicious_process",
                    "severity": "high",
                    "details": proc,
                    "timestamp": datetime.now().isoformat()
                })
        
        self.last_scan = datetime.now()
        self.anomalies = anomalies
        return anomalies

class MacrophageCell(BiologicalCell):
    """
    Cellule Macrophage de BioCybe.
    
    Surveille activement le système pour détecter les signes de menace
    et alerte les autres cellules en cas d'anomalie.
    """
    
    def __init__(self, name: str, config: Dict = None):
        """
        Initialise une cellule Macrophage.
        
        Args:
            name: Nom unique de cette instance de macrophage
            config: Configuration spécifique à la cellule
        """
        super().__init__(name, "macrophage", config)
        
        # Initialiser le moniteur système
        self.monitor = SystemMonitor()
        
        # Configuration
        self.config = config or {}
        self.scan_interval = self.config.get("scan_interval", 300)  # 5 minutes par défaut
        self.directories_to_watch = self.config.get("watch_directories", ["/etc", "/tmp", "/var/log"])
        
        # État
        self.last_scan_time = None
        self.anomalies_found = []
        
        # Enregistrer les gestionnaires de messages
        self.register_message_handler("request_scan", self._handle_scan_request)
        self.register_message_handler("system_start", self._handle_system_start)
        
        self.logger.info(f"Macrophage '{name}' initialisé avec scan_interval={self.scan_interval}s")
    
    def _process_cycle(self):
        """
        Traite un cycle d'activité du macrophage.
        """
        current_time = datetime.now()
        
        # Si c'est le premier cycle ou si l'intervalle de scan est dépassé
        if not self.last_scan_time or (current_time - self.last_scan_time).total_seconds() >= self.scan_interval:
            self.logger.debug(f"Démarrage d'un scan complet")
            
            # Si baseline n'existe pas, l'établir
            if not self.monitor.baseline:
                self.monitor.establish_baseline()
                self.last_scan_time = current_time
                return
            
            # Détecter les anomalies
            anomalies = self.monitor.detect_anomalies()
            
            # Mettre à jour l'heure du dernier scan
            self.last_scan_time = current_time
            
            # Si des anomalies sont détectées, les signaler
            if anomalies:
                self.logger.info(f"Détection de {len(anomalies)} anomalies")
                
                # Regrouper les anomalies par type
                anomalies_by_type = {}
                for anomaly in anomalies:
                    anomaly_type = anomaly["type"]
                    if anomaly_type not in anomalies_by_type:
                        anomalies_by_type[anomaly_type] = []
                    anomalies_by_type[anomaly_type].append(anomaly)
                
                # Envoyer les alertes appropriées
                for anomaly_type, anomalies_list in anomalies_by_type.items():
                    severity = max(a["severity"] for a in anomalies_list)
                    if severity == "high":
                        # Alerter directement les cellules NK pour les menaces importantes
                        self.send_message(
                            msg_type="alert_high",
                            target="type:nk_cell",
                            payload={
                                "type": anomaly_type,
                                "anomalies": anomalies_list,
                                "detected_by": self.name
                            },
                            priority=4
                        )
                    
                    # Envoyer à tous pour analyse
                    self.send_message(
                        msg_type="alert_anomaly",
                        target="broadcast",
                        payload={
                            "type": anomaly_type,
                            "severity": severity,
                            "anomalies": anomalies_list,
                            "detected_by": self.name
                        },
                        priority=3
                    )
                
                # Stocker les anomalies trouvées
                self.anomalies_found.extend(anomalies)
                self.stats["actions_performed"] += 1
            
            else:
                self.logger.debug("Aucune anomalie détectée")
                
                # Périodiquement, envoyer un rapport de santé
                if self.stats["actions_performed"] % 10 == 0:
                    self.send_message(
                        msg_type="system_health",
                        target="broadcast",
                        payload={
                            "status": "healthy",
                            "metrics": self.monitor.collect_system_metrics(),
                            "monitored_by": self.name
                        },
                        priority=1
                    )
    
    def _handle_scan_request(self, message: CellMessage):
        """
        Gère une demande de scan immédiat.
        
        Args:
            message: Message de demande de scan
        """
        self.logger.info(f"Demande de scan reçue de {message.source}")
        
        # Vérifier si des répertoires spécifiques sont demandés
        if message.payload and "directories" in message.payload:
            dirs_to_scan = message.payload["directories"]
            scan_result = self.monitor.scan_file_changes(dirs_to_scan)
        else:
            # Scan général
            if not self.monitor.baseline:
                self.monitor.establish_baseline()
            
            scan_result = {
                "system_metrics": self.monitor.collect_system_metrics(),
                "processes": self.monitor.scan_processes(),
                "connections": self.monitor.scan_network_connections(),
                "file_changes": self.monitor.scan_file_changes(self.directories_to_watch)
            }
        
        # Détecter les anomalies si demandé
        if message.payload and message.payload.get("detect_anomalies", False):
            anomalies = self.monitor.detect_anomalies()
            scan_result["anomalies"] = anomalies
        
        # Répondre au demandeur
        self.send_message(
            msg_type="scan_result",
            target=message.source,
            payload={
                "result": scan_result,
                "timestamp": datetime.now().isoformat(),
                "scanned_by": self.name
            }
        )
        
        self.stats["actions_performed"] += 1
        self.last_scan_time = datetime.now()
    
    def _handle_system_start(self, message: CellMessage):
        """
        Gère le message de démarrage du système.
        
        Args:
            message: Message de démarrage système
        """
        self.logger.info("Système démarré, établissement de la baseline...")
        self.monitor.establish_baseline()
        
        # Informer les autres cellules que la baseline est établie
        self.send_message(
            msg_type="baseline_established",
            target="broadcast",
            payload={
                "timestamp": datetime.now().isoformat(),
                "established_by": self.name
            }
        )

def create_cells(config: Dict) -> List[BiologicalCell]:
    """
    Crée les instances de cellules Macrophage selon la configuration.
    
    Args:
        config: Configuration du système
    
    Returns:
        List[BiologicalCell]: Liste des cellules créées
    """
    cells = []
    
    # Configuration des macrophages
    macrophage_config = config.get("cells", {}).get("macrophage", {})
    
    # Créer les instances par défaut si aucune configuration spécifique
    if not macrophage_config:
        cells.append(MacrophageCell("macrophage_system"))
    else:
        # Créer les instances selon la configuration
        instances = macrophage_config.get("instances", [{"name": "macrophage_system"}])
        for instance in instances:
            cell_name = instance.get("name", f"macrophage_{len(cells)}")
            cell_config = instance.get("config", {})
            cells.append(MacrophageCell(cell_name, cell_config))
    
    return cells

# Test si exécuté directement
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Test du module Macrophage")
    
    # Créer une cellule de test
    cell = MacrophageCell("test_macrophage")
    
    # Simuler un cycle d'activité
    cell.monitor.establish_baseline()
    time.sleep(2)  # Attendre un peu
    
    # Détecter les anomalies
    anomalies = cell.monitor.detect_anomalies()
    
    # Afficher les résultats
    print(f"Anomalies détectées: {len(anomalies)}")
    for anomaly in anomalies:
        print(f"  - {anomaly['type']} (Sévérité: {anomaly['severity']})")
