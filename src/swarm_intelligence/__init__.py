#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'intelligence collective (Swarm Intelligence) pour Biocybe.

Ce module implémente des algorithmes inspirés des colonies d'insectes sociaux
pour la détection collaborative de menaces et l'optimisation des stratégies de défense.
"""

import os
import sys
import logging
import numpy as np
import networkx as nx
from datetime import datetime

# Configuration du logger
logger = logging.getLogger("biocybe.swarm_intelligence")

class SwarmNode:
    """
    Représente un nœud dans un réseau d'intelligence collective.
    
    Chaque nœud peut partager des informations avec ses pairs et participer
    à la prise de décision collective.
    """
    
    def __init__(self, node_id, config=None):
        """
        Initialise un nœud d'intelligence collective.
        
        Args:
            node_id (str): Identifiant unique du nœud
            config (dict, optional): Configuration du nœud
        """
        self.node_id = node_id
        self.config = config or {}
        self.peers = []
        self.local_findings = {}
        self.shared_data = {}
        self.trust_scores = {}
        self.last_update = datetime.now()
        
        logger.info(f"Nœud d'intelligence collective {node_id} initialisé")
    
    def add_peer(self, peer_id, initial_trust=0.5):
        """
        Ajoute un pair au réseau du nœud.
        
        Args:
            peer_id (str): Identifiant du pair à ajouter
            initial_trust (float, optional): Score de confiance initial (0-1)
        """
        if peer_id not in self.peers:
            self.peers.append(peer_id)
            self.trust_scores[peer_id] = initial_trust
            logger.debug(f"Pair {peer_id} ajouté au nœud {self.node_id}")
    
    def remove_peer(self, peer_id):
        """
        Supprime un pair du réseau du nœud.
        
        Args:
            peer_id (str): Identifiant du pair à supprimer
        """
        if peer_id in self.peers:
            self.peers.remove(peer_id)
            if peer_id in self.trust_scores:
                del self.trust_scores[peer_id]
            logger.debug(f"Pair {peer_id} supprimé du nœud {self.node_id}")
    
    def add_local_finding(self, finding_id, finding_data):
        """
        Ajoute une découverte locale au nœud.
        
        Args:
            finding_id (str): Identifiant de la découverte
            finding_data (dict): Données associées à la découverte
        """
        self.local_findings[finding_id] = {
            "data": finding_data,
            "timestamp": datetime.now(),
            "shared": False
        }
        logger.debug(f"Découverte locale {finding_id} ajoutée au nœud {self.node_id}")
    
    def share_information(self, peers=None):
        """
        Partage les découvertes locales avec les pairs spécifiés.
        
        Args:
            peers (list, optional): Liste des pairs avec qui partager.
                                   Si None, partage avec tous les pairs.
        
        Returns:
            dict: Informations partagées
        """
        peers = peers or self.peers
        shared_info = {}
        
        # Préparer les informations à partager
        for finding_id, finding in self.local_findings.items():
            if not finding["shared"]:
                shared_info[finding_id] = {
                    "data": finding["data"],
                    "source": self.node_id,
                    "timestamp": finding["timestamp"],
                    "confidence": self._calculate_confidence(finding["data"])
                }
                finding["shared"] = True
        
        logger.info(f"Nœud {self.node_id} partage {len(shared_info)} découvertes avec {len(peers)} pairs")
        return shared_info
    
    def receive_information(self, source_id, shared_info):
        """
        Reçoit des informations partagées par un pair.
        
        Args:
            source_id (str): Identifiant du pair source
            shared_info (dict): Informations partagées
        """
        if source_id not in self.peers:
            logger.warning(f"Information reçue d'un pair inconnu: {source_id}")
            return
        
        # Mettre à jour les données partagées
        for finding_id, finding in shared_info.items():
            weighted_finding = self._apply_trust_weight(source_id, finding)
            
            if finding_id in self.shared_data:
                # Fusionner avec les données existantes
                self.shared_data[finding_id] = self._merge_findings(
                    self.shared_data[finding_id], 
                    weighted_finding
                )
            else:
                # Ajouter les nouvelles données
                self.shared_data[finding_id] = weighted_finding
        
        # Mettre à jour le score de confiance du pair
        self._update_trust_score(source_id, shared_info)
        self.last_update = datetime.now()
        
        logger.debug(f"Nœud {self.node_id} a reçu {len(shared_info)} découvertes de {source_id}")
    
    def collective_decision(self, threshold=0.7):
        """
        Prend une décision collective basée sur les données partagées.
        
        Args:
            threshold (float, optional): Seuil de confiance pour les décisions
        
        Returns:
            dict: Décisions collectives prises
        """
        decisions = {}
        
        # Combiner les découvertes locales et partagées
        all_findings = {**self.local_findings, **self.shared_data}
        
        # Regrouper les découvertes similaires
        grouped_findings = self._group_similar_findings(all_findings)
        
        # Prendre des décisions basées sur les groupes
        for group_id, group in grouped_findings.items():
            avg_confidence = sum(f.get("confidence", 0.5) for f in group) / len(group)
            
            if avg_confidence >= threshold:
                decisions[group_id] = {
                    "confidence": avg_confidence,
                    "supporting_nodes": len(set(f.get("source", self.node_id) for f in group)),
                    "data": self._aggregate_group_data(group)
                }
        
        logger.info(f"Nœud {self.node_id} a pris {len(decisions)} décisions collectives")
        return decisions
    
    def visualize_network(self, output_file=None):
        """
        Génère une visualisation du réseau de pairs.
        
        Args:
            output_file (str, optional): Chemin du fichier de sortie
        
        Returns:
            networkx.Graph: Graphe représentant le réseau
        """
        G = nx.Graph()
        
        # Ajouter les nœuds
        G.add_node(self.node_id, type="self")
        for peer in self.peers:
            G.add_node(peer, type="peer")
        
        # Ajouter les arêtes avec les scores de confiance
        for peer, trust in self.trust_scores.items():
            G.add_edge(self.node_id, peer, weight=trust)
        
        # Sauvegarder la visualisation si demandé
        if output_file:
            try:
                import matplotlib.pyplot as plt
                plt.figure(figsize=(10, 8))
                pos = nx.spring_layout(G)
                nx.draw_networkx_nodes(G, pos, 
                                      node_color=['red' if n == self.node_id else 'blue' for n in G.nodes])
                nx.draw_networkx_edges(G, pos, width=[G[u][v]['weight'] * 3 for u, v in G.edges])
                nx.draw_networkx_labels(G, pos)
                plt.axis('off')
                plt.savefig(output_file)
                plt.close()
                logger.info(f"Visualisation du réseau sauvegardée dans {output_file}")
            except Exception as e:
                logger.error(f"Erreur lors de la création de la visualisation: {e}")
        
        return G
    
    def explain_decision(self, decision_id, decisions=None):
        """
        Fournit une explication humainement compréhensible d'une décision.
        
        Args:
            decision_id (str): Identifiant de la décision à expliquer
            decisions (dict, optional): Dictionnaire de décisions
        
        Returns:
            str: Explication textuelle de la décision
        """
        if decisions is None:
            decisions = self.collective_decision()
        
        if decision_id not in decisions:
            return f"Aucune décision trouvée avec l'identifiant {decision_id}"
        
        decision = decisions[decision_id]
        
        explanation = [
            f"Décision collective: {decision_id}",
            f"Niveau de confiance: {decision['confidence']:.2f}",
            f"Nœuds contributeurs: {decision['supporting_nodes']}",
            "Facteurs contribuant à cette décision:"
        ]
        
        # Ajouter des détails sur les facteurs contribuant à la décision
        for i, (key, value) in enumerate(decision['data'].items(), 1):
            if isinstance(value, dict):
                explanation.append(f"  {i}. {key}: {value.get('summary', str(value))}")
            else:
                explanation.append(f"  {i}. {key}: {value}")
        
        return "\n".join(explanation)
    
    def _calculate_confidence(self, finding_data):
        """
        Calcule un score de confiance pour une découverte.
        
        Args:
            finding_data (dict): Données de la découverte
        
        Returns:
            float: Score de confiance (0-1)
        """
        # Implémentation simple - à personnaliser selon les besoins
        base_confidence = finding_data.get("confidence", 0.5)
        evidence_strength = min(1.0, len(finding_data.get("evidence", [])) / 5)
        
        return (base_confidence + evidence_strength) / 2
    
    def _apply_trust_weight(self, source_id, finding):
        """
        Applique un poids basé sur la confiance à une découverte.
        
        Args:
            source_id (str): Identifiant de la source
            finding (dict): Découverte à pondérer
        
        Returns:
            dict: Découverte pondérée
        """
        trust_score = self.trust_scores.get(source_id, 0.5)
        weighted_finding = finding.copy()
        
        if "confidence" in weighted_finding:
            weighted_finding["confidence"] *= trust_score
        
        weighted_finding["trust_weight"] = trust_score
        return weighted_finding
    
    def _merge_findings(self, existing, new):
        """
        Fusionne deux découvertes similaires.
        
        Args:
            existing (dict): Découverte existante
            new (dict): Nouvelle découverte
        
        Returns:
            dict: Découverte fusionnée
        """
        merged = existing.copy()
        
        # Fusionner les données
        if "data" in new and "data" in existing:
            for key, value in new["data"].items():
                if key in merged["data"]:
                    # Si la clé existe déjà, prendre la valeur la plus récente
                    if new.get("timestamp", datetime.now()) > existing.get("timestamp", datetime.min):
                        merged["data"][key] = value
                else:
                    merged["data"][key] = value
        
        # Mettre à jour la confiance (moyenne pondérée)
        if "confidence" in new and "confidence" in existing:
            w1 = existing.get("trust_weight", 1.0)
            w2 = new.get("trust_weight", 1.0)
            merged["confidence"] = (existing["confidence"] * w1 + new["confidence"] * w2) / (w1 + w2)
        
        # Ajouter la source si elle n'est pas déjà présente
        if "sources" not in merged:
            merged["sources"] = [existing.get("source")]
        
        if new.get("source") not in merged["sources"]:
            merged["sources"].append(new.get("source"))
        
        # Utiliser l'horodatage le plus récent
        if "timestamp" in new and "timestamp" in existing:
            merged["timestamp"] = max(existing["timestamp"], new["timestamp"])
        
        return merged
    
    def _group_similar_findings(self, findings):
        """
        Regroupe les découvertes similaires.
        
        Args:
            findings (dict): Dictionnaire de découvertes
        
        Returns:
            dict: Groupes de découvertes similaires
        """
        groups = {}
        processed = set()
        
        for id1, finding1 in findings.items():
            if id1 in processed:
                continue
                
            # Créer un nouveau groupe
            group_id = f"group_{len(groups)}"
            groups[group_id] = [finding1]
            processed.add(id1)
            
            # Trouver des découvertes similaires
            for id2, finding2 in findings.items():
                if id2 != id1 and id2 not in processed:
                    if self._are_findings_similar(finding1, finding2):
                        groups[group_id].append(finding2)
                        processed.add(id2)
        
        return groups
    
    def _are_findings_similar(self, finding1, finding2):
        """
        Détermine si deux découvertes sont similaires.
        
        Args:
            finding1 (dict): Première découverte
            finding2 (dict): Deuxième découverte
        
        Returns:
            bool: True si les découvertes sont similaires
        """
        # Extraire les données réelles
        data1 = finding1.get("data", finding1)
        data2 = finding2.get("data", finding2)
        
        # Vérifier les identifiants de menace
        if "threat_id" in data1 and "threat_id" in data2:
            return data1["threat_id"] == data2["threat_id"]
        
        # Vérifier les hachages
        if "hash" in data1 and "hash" in data2:
            return data1["hash"] == data2["hash"]
        
        # Vérifier les signatures
        if "signature" in data1 and "signature" in data2:
            return data1["signature"] == data2["signature"]
        
        # Vérifier les cibles
        if "target" in data1 and "target" in data2:
            return data1["target"] == data2["target"]
        
        # Par défaut, considérer comme différents
        return False
    
    def _aggregate_group_data(self, group):
        """
        Agrège les données d'un groupe de découvertes.
        
        Args:
            group (list): Liste de découvertes similaires
        
        Returns:
            dict: Données agrégées
        """
        if not group:
            return {}
        
        # Commencer avec les données de la première découverte
        base_data = group[0].get("data", {}).copy()
        
        # Agréger les données des autres découvertes
        for finding in group[1:]:
            data = finding.get("data", {})
            for key, value in data.items():
                if key in base_data:
                    # Si la clé existe déjà, fusionner ou mettre à jour
                    if isinstance(value, list) and isinstance(base_data[key], list):
                        # Fusionner les listes sans doublons
                        base_data[key] = list(set(base_data[key] + value))
                    elif isinstance(value, dict) and isinstance(base_data[key], dict):
                        # Fusionner les dictionnaires
                        base_data[key].update(value)
                    elif finding.get("timestamp", datetime.min) > group[0].get("timestamp", datetime.min):
                        # Utiliser la valeur la plus récente
                        base_data[key] = value
                else:
                    # Ajouter la nouvelle clé
                    base_data[key] = value
        
        # Ajouter des métadonnées sur l'agrégation
        base_data["aggregated"] = True
        base_data["sources_count"] = len(set(f.get("source", "unknown") for f in group))
        
        return base_data
    
    def _update_trust_score(self, source_id, shared_info):
        """
        Met à jour le score de confiance d'un pair.
        
        Args:
            source_id (str): Identifiant du pair
            shared_info (dict): Informations partagées par le pair
        """
        # Implémentation simple - à personnaliser selon les besoins
        current_score = self.trust_scores.get(source_id, 0.5)
        
        # Vérifier la qualité des informations partagées
        quality_score = 0
        for finding_id, finding in shared_info.items():
            # Vérifier si la découverte est corroborée par d'autres pairs
            if finding_id in self.shared_data:
                quality_score += 0.1
            
            # Vérifier si la découverte est corroborée par nos propres découvertes
            if finding_id in self.local_findings:
                quality_score += 0.2
        
        # Normaliser le score de qualité
        if shared_info:
            quality_score = min(1.0, quality_score / len(shared_info))
        
        # Mettre à jour le score de confiance (moyenne mobile)
        alpha = 0.3  # Facteur de lissage
        new_score = (1 - alpha) * current_score + alpha * quality_score
        
        # Limiter le score entre 0 et 1
        self.trust_scores[source_id] = max(0.1, min(1.0, new_score))
        
        logger.debug(f"Score de confiance de {source_id} mis à jour: {current_score:.2f} -> {self.trust_scores[source_id]:.2f}")


class AntColonyDetector:
    """
    Détecteur basé sur l'algorithme de colonies de fourmis pour l'identification
    de chemins d'attaque et de propagation de menaces.
    """
    
    def __init__(self, config=None):
        """
        Initialise un détecteur basé sur les colonies de fourmis.
        
        Args:
            config (dict, optional): Configuration du détecteur
        """
        self.config = config or {}
        self.graph = nx.DiGraph()
        self.pheromones = {}
        self.evaporation_rate = self.config.get("evaporation_rate", 0.1)
        self.alpha = self.config.get("alpha", 1.0)  # Importance des phéromones
        self.beta = self.config.get("beta", 2.0)    # Importance de l'heuristique
        
        logger.info("Détecteur de colonies de fourmis initialisé")
    
    def add_node(self, node_id, attributes=None):
        """
        Ajoute un nœud au graphe.
        
        Args:
            node_id (str): Identifiant du nœud
            attributes (dict, optional): Attributs du nœud
        """
        self.graph.add_node(node_id, **(attributes or {}))
    
    def add_edge(self, source, target, weight=1.0, attributes=None):
        """
        Ajoute une arête au graphe.
        
        Args:
            source (str): Nœud source
            target (str): Nœud cible
            weight (float, optional): Poids de l'arête
            attributes (dict, optional): Attributs de l'arête
        """
        edge_attrs = {"weight": weight}
        if attributes:
            edge_attrs.update(attributes)
        
        self.graph.add_edge(source, target, **edge_attrs)
        
        # Initialiser les phéromones
        self.pheromones[(source, target)] = self.config.get("initial_pheromone", 0.1)
    
    def detect_paths(self, start_nodes, target_nodes, n_ants=10, max_iterations=100):
        """
        Détecte les chemins potentiels entre les nœuds de départ et les nœuds cibles.
        
        Args:
            start_nodes (list): Liste des nœuds de départ
            target_nodes (list): Liste des nœuds cibles
            n_ants (int, optional): Nombre de fourmis par itération
            max_iterations (int, optional): Nombre maximum d'itérations
        
        Returns:
            list: Liste des chemins détectés avec leurs scores
        """
        best_paths = []
        best_path_score = float('inf')
        
        for iteration in range(max_iterations):
            # Pour chaque fourmi
            for ant in range(n_ants):
                # Choisir un nœud de départ aléatoire
                current = np.random.choice(start_nodes)
                path = [current]
                path_length = 0
                
                # Construire un chemin jusqu'à atteindre un nœud cible ou une impasse
                while current not in target_nodes:
                    # Obtenir les voisins possibles
                    neighbors = list(self.graph.successors(current))
                    
                    # Si pas de voisins ou tous les voisins déjà visités, c'est une impasse
                    unvisited = [n for n in neighbors if n not in path]
                    if not unvisited:
                        break
                    
                    # Calculer les probabilités de transition
                    probabilities = self._calculate_transition_probs(current, unvisited)
                    
                    # Choisir le prochain nœud
                    next_node = np.random.choice(unvisited, p=probabilities)
                    
                    # Mettre à jour le chemin
                    path.append(next_node)
                    path_length += self.graph[current][next_node].get("weight", 1.0)
                    current = next_node
                
                # Si un chemin complet a été trouvé
                if current in target_nodes:
                    # Mettre à jour les phéromones sur ce chemin
                    pheromone_deposit = 1.0 / path_length
                    for i in range(len(path) - 1):
                        edge = (path[i], path[i+1])
                        self.pheromones[edge] += pheromone_deposit
                    
                    # Mettre à jour le meilleur chemin
                    if path_length < best_path_score:
                        best_path_score = path_length
                        best_paths = [(path, path_length)]
                    elif path_length == best_path_score:
                        best_paths.append((path, path_length))
            
            # Évaporation des phéromones
            for edge in self.pheromones:
                self.pheromones[edge] *= (1 - self.evaporation_rate)
        
        logger.info(f"Détection de chemins terminée: {len(best_paths)} chemins trouvés")
        return best_paths
    
    def visualize_paths(self, paths, output_file=None):
        """
        Génère une visualisation des chemins détectés.
        
        Args:
            paths (list): Liste des chemins à visualiser
            output_file (str, optional): Chemin du fichier de sortie
        """
        try:
            import matplotlib.pyplot as plt
            
            plt.figure(figsize=(12, 10))
            pos = nx.spring_layout(self.graph)
            
            # Dessiner le graphe de base
            nx.draw_networkx_nodes(self.graph, pos, node_size=300, node_color='lightblue')
            nx.draw_networkx_edges(self.graph, pos, width=1, alpha=0.3, edge_color='gray')
            nx.draw_networkx_labels(self.graph, pos)
            
            # Dessiner les chemins détectés
            colors = ['red', 'green', 'blue', 'purple', 'orange']
            for i, (path, score) in enumerate(paths[:5]):  # Limiter à 5 chemins pour la lisibilité
                color = colors[i % len(colors)]
                
                # Dessiner les nœuds du chemin
                path_nodes = set(path)
                nx.draw_networkx_nodes(self.graph, pos, 
                                      nodelist=path_nodes,
                                      node_color=color,
                                      node_size=500)
                
                # Dessiner les arêtes du chemin
                path_edges = [(path[i], path[i+1]) for i in range(len(path)-1)]
                nx.draw_networkx_edges(self.graph, pos,
                                      edgelist=path_edges,
                                      width=3,
                                      alpha=0.7,
                                      edge_color=color)
                
                # Ajouter une légende pour ce chemin
                plt.plot([], [], color=color, label=f"Chemin {i+1} (score: {score:.2f})")
            
            plt.legend()
            plt.axis('off')
            
            if output_file:
                plt.savefig(output_file)
                logger.info(f"Visualisation des chemins sauvegardée dans {output_file}")
            else:
                plt.show()
            
            plt.close()
            
        except Exception as e:
            logger.error(f"Erreur lors de la création de la visualisation: {e}")
    
    def explain_path(self, path, score):
        """
        Fournit une explication humainement compréhensible d'un chemin détecté.
        
        Args:
            path (list): Chemin à expliquer
            score (float): Score du chemin
        
        Returns:
            str: Explication textuelle du chemin
        """
        explanation = [
            f"Chemin de propagation potentiel (score: {score:.2f}):",
            "→ ".join(path),
            "",
            "Détails du chemin:"
        ]
        
        # Ajouter des détails sur chaque étape du chemin
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i+1]
            edge_attrs = self.graph[source][target]
            
            step_details = [f"Étape {i+1}: {source} → {target}"]
            
            # Ajouter les attributs de l'arête
            for key, value in edge_attrs.items():
                if key != "weight":
                    step_details.append(f"  - {key}: {value}")
            
            # Ajouter le niveau de phéromones
            pheromone_level = self.pheromones.get((source, target), 0)
            step_details.append(f"  - Niveau de phéromones: {pheromone_level:.4f}")
            
            explanation.append("\n".join(step_details))
        
        # Ajouter une conclusion
        explanation.append("")
        explanation.append("Ce chemin représente une séquence possible d'événements ou d'actions qui pourrait indiquer une propagation de menace dans le système.")
        
        return "\n".join(explanation)
    
    def _calculate_transition_probs(self, current, neighbors):
        """
        Calcule les probabilités de transition vers les voisins.
        
        Args:
            current (str): Nœud actuel
            neighbors (list): Liste des voisins possibles
        
        Returns:
            numpy.ndarray: Tableau des probabilités
        """
        probabilities = np.zeros(len(neighbors))
        
        for i, neighbor in enumerate(neighbors):
            # Niveau de phéromones
            pheromone = self.pheromones.get((current, neighbor), self.config.get("initial_pheromone", 0.1))
            
            # Heuristique (inverse du poids)
            weight = self.graph[current][neighbor].get("weight", 1.0)
            heuristic = 1.0 / weight
            
            # Probabilité selon la formule ACO
            probabilities[i] = (pheromone ** self.alpha) * (heuristic ** self.beta)
        
        # Normaliser les probabilités
        probabilities = probabilities / probabilities.sum()
        
        return probabilities


def create_cells(config=None):
    """
    Crée et configure les cellules d'intelligence collective.
    
    Args:
        config (dict, optional): Configuration globale
    
    Returns:
        list: Liste des cellules créées
    """
    cells = []
    
    # Configuration spécifique aux cellules d'intelligence collective
    swarm_config = config.get("swarm_intelligence", {}) if config else {}
    
    # Créer un réseau de nœuds SwarmNode
    if swarm_config.get("enable_swarm_nodes", True):
        node_count = swarm_config.get("node_count", 3)
        
        for i in range(node_count):
            node = SwarmNode(f"swarm_node_{i}", swarm_config)
            cells.append(node)
        
        # Connecter les nœuds entre eux
        for i in range(node_count):
            for j in range(node_count):
                if i != j:
                    cells[i].add_peer(f"swarm_node_{j}")
    
    # Créer un détecteur basé sur les colonies de fourmis
    if swarm_config.get("enable_ant_colony", True):
        detector = AntColonyDetector(swarm_config)
        cells.append(detector)
    
    logger.info(f"Créé {len(cells)} cellules d'intelligence collective")
    return cells


if __name__ == "__main__":
    # Configuration de test
    logging.basicConfig(level=logging.INFO)
    
    # Créer un réseau de test
    nodes = [SwarmNode(f"node_{i}") for i in range(5)]
    
    # Connecter les nœuds
    for i, node in enumerate(nodes):
        for j in range(5):
            if i != j:
                node.add_peer(f"node_{j}")
    
    # Ajouter des découvertes locales
    nodes[0].add_local_finding("threat_1", {
        "type": "malware",
        "confidence": 0.8,
        "evidence": ["signature_match", "behavioral_anomaly"]
    })
    
    nodes[1].add_local_finding("threat_2", {
        "type": "intrusion",
        "confidence": 0.6,
        "evidence": ["unusual_login", "privilege_escalation"]
    })
    
    # Partager les informations
    shared_from_0 = nodes[0].share_information()
    nodes[1].receive_information("node_0", shared_from_0)
    
    shared_from_1 = nodes[1].share_information()
    nodes[0].receive_information("node_1", shared_from_1)
    
    # Prendre des décisions collectives
    decisions_0 = nodes[0].collective_decision()
    decisions_1 = nodes[1].collective_decision()
    
    print(f"Node 0 decisions: {len(decisions_0)}")
    print(f"Node 1 decisions: {len(decisions_1)}")
    
    # Tester le détecteur de colonies de fourmis
    detector = AntColonyDetector()
    
    # Créer un graphe de test
    for i in range(10):
        detector.add_node(f"host_{i}")
    
    # Ajouter des connexions
    detector.add_edge("host_0", "host_1", 1.0)
    detector.add_edge("host_1", "host_2", 1.0)
    detector.add_edge("host_1", "host_3", 2.0)
    detector.add_edge("host_2", "host_4", 1.0)
    detector.add_edge("host_3", "host_4", 1.0)
    detector.add_edge("host_4", "host_5", 1.0)
    detector.add_edge("host_5", "host_6", 1.0)
    detector.add_edge("host_5", "host_7", 2.0)
    detector.add_edge("host_6", "host_8", 1.0)
    detector.add_edge("host_7", "host_8", 1.0)
    detector.add_edge("host_8", "host_9", 1.0)
    
    # Détecter les chemins
    paths = detector.detect_paths(["host_0"], ["host_9"], n_ants=20, max_iterations=50)
    
    print(f"Detected {len(paths)} paths:")
    for path, score in paths:
        print(f"Path: {' -> '.join(path)}, Score: {score}")
        print(detector.explain_path(path, score))
