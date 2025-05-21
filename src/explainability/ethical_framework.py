#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BioCybe - Module de cadre éthique et conformité RGPD

Ce module implémente le cadre éthique de BioCybe pour assurer la conformité RGPD
et garantir une utilisation éthique de l'IA dans la cyberdéfense.
"""

import logging
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
import os
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class DataProcessingActivity:
    """Représente une activité de traitement des données personnelles selon le RGPD."""
    
    name: str
    purpose: str
    data_categories: List[str]
    legal_basis: str
    retention_period: str
    security_measures: List[str]
    responsible_person: str
    cross_border_transfer: bool = False
    transfer_safeguards: Optional[str] = None
    processors: List[str] = None
    
    def as_dict(self) -> Dict[str, Any]:
        """Convertit l'activité en dictionnaire."""
        return {
            'name': self.name,
            'purpose': self.purpose,
            'data_categories': self.data_categories,
            'legal_basis': self.legal_basis,
            'retention_period': self.retention_period,
            'security_measures': self.security_measures,
            'responsible_person': self.responsible_person,
            'cross_border_transfer': self.cross_border_transfer,
            'transfer_safeguards': self.transfer_safeguards,
            'processors': self.processors or [],
            'last_updated': datetime.now().isoformat()
        }


class EthicalFramework:
    """
    Implémente le cadre éthique de BioCybe pour une IA explicable et respectueuse de la vie privée.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialise le cadre éthique.
        
        Args:
            config_path: Chemin vers le fichier de configuration du cadre éthique (JSON)
        """
        self.processing_activities = []
        self.consent_log = {}
        self.data_subject_requests = {}
        self.config = {
            'privacy': {
                'data_minimization': True,
                'local_processing': True,
                'anonymization': True,
                'max_retention_days': 30
            },
            'explainability': {
                'required_explainability_score': 0.7,
                'explanation_levels': ['technical', 'intermediate', 'simplified'],
                'visualizations_enabled': True
            },
            'transparency': {
                'alert_detailed_explanation': True,
                'model_documentation_required': True,
                'tracking_notification': True
            },
            'user_control': {
                'allow_opt_out': True,
                'granular_consent': True,
                'correction_mechanism': True
            }
        }
        
        # Charger la configuration si spécifiée
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                    # Mettre à jour la configuration avec les valeurs chargées
                    for section, settings in loaded_config.items():
                        if section in self.config:
                            self.config[section].update(settings)
                logger.info(f"Ethical framework configuration loaded from {config_path}")
            except Exception as e:
                logger.error(f"Error loading ethical framework configuration: {str(e)}")
    
    def register_processing_activity(self, activity: DataProcessingActivity) -> bool:
        """
        Enregistre une nouvelle activité de traitement dans le registre RGPD.
        
        Args:
            activity: L'activité de traitement à enregistrer
            
        Returns:
            bool: True si l'activité a été enregistrée avec succès
        """
        try:
            self.processing_activities.append(activity.as_dict())
            logger.info(f"Registered processing activity: {activity.name}")
            return True
        except Exception as e:
            logger.error(f"Error registering processing activity: {str(e)}")
            return False
    
    def check_data_minimization(self, required_data_fields: List[str], available_fields: List[str]) -> List[str]:
        """
        Vérifie le principe de minimisation des données en ne retenant que les champs nécessaires.
        
        Args:
            required_data_fields: Liste des champs de données requis pour la fonctionnalité
            available_fields: Liste complète des champs disponibles
            
        Returns:
            List[str]: Liste des champs conformes au principe de minimisation
        """
        if not self.config['privacy']['data_minimization']:
            return available_fields
        
        # Ne conserver que les champs nécessaires
        minimized_fields = [field for field in available_fields if field in required_data_fields]
        
        # Loguer l'action de minimisation
        excluded_fields = set(available_fields) - set(minimized_fields)
        if excluded_fields:
            logger.info(f"Data minimization applied: excluded {len(excluded_fields)} fields")
        
        return minimized_fields
    
    def anonymize_data(self, data: Dict[str, Any], sensitive_fields: List[str]) -> Dict[str, Any]:
        """
        Anonymise les données sensibles.
        
        Args:
            data: Dictionnaire de données à anonymiser
            sensitive_fields: Liste des champs sensibles à anonymiser
            
        Returns:
            Dict[str, Any]: Données anonymisées
        """
        if not self.config['privacy']['anonymization']:
            return data
        
        anonymized_data = data.copy()
        
        for field in sensitive_fields:
            if field in anonymized_data:
                # Remplacer par un hash ou une valeur anonymisée selon le type
                if isinstance(anonymized_data[field], str):
                    # Hash simple pour les chaînes
                    anonymized_data[field] = hashlib.sha256(anonymized_data[field].encode()).hexdigest()[:8]
                elif isinstance(anonymized_data[field], (int, float)):
                    # Bruit pour les valeurs numériques
                    anonymized_data[field] = 0  # Valeur neutre pour les démonstrations
        
        logger.info(f"Data anonymized for {len(sensitive_fields)} sensitive fields")
        return anonymized_data
    
    def log_consent(self, user_id: str, consent_type: str, granted: bool, 
                   timestamp: Optional[datetime] = None) -> None:
        """
        Enregistre le consentement d'un utilisateur.
        
        Args:
            user_id: Identifiant (anonymisé) de l'utilisateur
            consent_type: Type de consentement ('data_collection', 'analysis', etc.)
            granted: Si le consentement a été accordé
            timestamp: Horodatage du consentement (par défaut: maintenant)
        """
        if user_id not in self.consent_log:
            self.consent_log[user_id] = {}
        
        self.consent_log[user_id][consent_type] = {
            'granted': granted,
            'timestamp': (timestamp or datetime.now()).isoformat()
        }
        
        logger.info(f"Consent logged for user {user_id}, type {consent_type}, granted: {granted}")
    
    def check_consent(self, user_id: str, consent_type: str) -> bool:
        """
        Vérifie si un utilisateur a donné son consentement pour un type spécifique.
        
        Args:
            user_id: Identifiant de l'utilisateur
            consent_type: Type de consentement à vérifier
            
        Returns:
            bool: True si le consentement a été accordé, False sinon
        """
        if user_id in self.consent_log and consent_type in self.consent_log[user_id]:
            return self.consent_log[user_id][consent_type]['granted']
        
        # Par défaut, considérer qu'il n'y a pas de consentement
        return False
    
    def register_data_subject_request(self, request_id: str, user_id: str, 
                                    request_type: str, details: str) -> None:
        """
        Enregistre une demande d'un sujet de données (accès, effacement, etc.).
        
        Args:
            request_id: Identifiant unique de la demande
            user_id: Identifiant de l'utilisateur
            request_type: Type de demande ('access', 'erasure', 'portability', etc.)
            details: Détails de la demande
        """
        self.data_subject_requests[request_id] = {
            'user_id': user_id,
            'request_type': request_type,
            'details': details,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'completed_at': None,
            'response': None
        }
        
        logger.info(f"Data subject request registered: {request_type} for user {user_id}")
    
    def update_data_subject_request(self, request_id: str, status: str, 
                                   response: Optional[str] = None) -> bool:
        """
        Met à jour le statut d'une demande d'un sujet de données.
        
        Args:
            request_id: Identifiant de la demande
            status: Nouveau statut ('completed', 'rejected', etc.)
            response: Réponse optionnelle
            
        Returns:
            bool: True si la mise à jour a réussi
        """
        if request_id not in self.data_subject_requests:
            logger.warning(f"Data subject request {request_id} not found")
            return False
        
        self.data_subject_requests[request_id]['status'] = status
        
        if status in ('completed', 'rejected'):
            self.data_subject_requests[request_id]['completed_at'] = datetime.now().isoformat()
        
        if response:
            self.data_subject_requests[request_id]['response'] = response
        
        logger.info(f"Data subject request {request_id} updated to status: {status}")
        return True
    
    def format_explanation(self, explanation: Dict[str, Any], level: str = 'intermediate') -> str:
        """
        Formate une explication selon le niveau de détail demandé.
        
        Args:
            explanation: Dictionnaire contenant les données d'explication
            level: Niveau de détail ('technical', 'intermediate', 'simplified')
            
        Returns:
            str: Explication formatée
        """
        if level not in self.config['explainability']['explanation_levels']:
            level = 'intermediate'  # Niveau par défaut
        
        # Extraire les éléments pertinents
        method = explanation.get('method', 'unknown')
        features = explanation.get('features', [])
        
        # Formater selon le niveau
        if level == 'technical':
            # Explication technique détaillée
            lines = [f"Méthode d'explication: {method}"]
            lines.append("Caractéristiques contributives:")
            
            for i, feature in enumerate(features):
                lines.append(f"  {i+1}. {feature['feature']}: {feature['importance']:.6f}")
                
                # Ajouter des détails techniques supplémentaires si disponibles
                if 'value' in feature:
                    lines.append(f"     Valeur: {feature['value']}")
            
            return "\n".join(lines)
            
        elif level == 'intermediate':
            # Niveau intermédiaire avec un équilibre d'informations
            lines = [f"Cette décision a été prise en utilisant la méthode {method}."]
            lines.append("Les facteurs les plus importants sont:")
            
            for i, feature in enumerate(features[:5]):  # Top 5 seulement
                direction = "augmenté" if feature['importance'] > 0 else "diminué"
                lines.append(f"  • {feature['feature']} a {direction} le niveau de risque")
            
            return "\n".join(lines)
            
        else:  # simplified
            # Version très simple
            if features:
                top_feature = features[0]['feature']
                direction = "positif" if features[0]['importance'] > 0 else "négatif"
                return f"Cette décision est principalement due à un impact {direction} du facteur '{top_feature}'."
            
            return "La décision est basée sur l'analyse des motifs détectés."
    
    def validate_model_explainability(self, explainability_metrics: Dict[str, float]) -> bool:
        """
        Valide si un modèle répond aux critères d'explicabilité minimums.
        
        Args:
            explainability_metrics: Métriques d'explicabilité du modèle
            
        Returns:
            bool: True si le modèle est suffisamment explicable
        """
        required_score = self.config['explainability']['required_explainability_score']
        
        # Vérifier si le score global est suffisant
        if 'global_score' in explainability_metrics:
            meets_threshold = explainability_metrics['global_score'] >= required_score
            
            if not meets_threshold:
                logger.warning(f"Model does not meet explainability threshold: "
                              f"{explainability_metrics['global_score']:.2f} < {required_score:.2f}")
            
            return meets_threshold
        
        # Si pas de score global, vérifier les scores spécifiques
        if not explainability_metrics:
            logger.error("No explainability metrics provided")
            return False
        
        # Moyenner les scores disponibles
        avg_score = sum(explainability_metrics.values()) / len(explainability_metrics)
        meets_threshold = avg_score >= required_score
        
        if not meets_threshold:
            logger.warning(f"Model does not meet explainability threshold: "
                          f"{avg_score:.2f} < {required_score:.2f}")
        
        return meets_threshold
    
    def export_processing_register(self, output_path: str) -> bool:
        """
        Exporte le registre des activités de traitement au format JSON.
        
        Args:
            output_path: Chemin du fichier d'export
            
        Returns:
            bool: True si l'export a réussi
        """
        try:
            with open(output_path, 'w') as f:
                json.dump({
                    'processing_activities': self.processing_activities,
                    'generated_at': datetime.now().isoformat(),
                    'framework_version': '1.0.0'
                }, f, indent=2)
            
            logger.info(f"Processing activities register exported to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting processing register: {str(e)}")
            return False
    
    def export_config(self, output_path: str) -> bool:
        """
        Exporte la configuration du cadre éthique au format JSON.
        
        Args:
            output_path: Chemin du fichier d'export
            
        Returns:
            bool: True si l'export a réussi
        """
        try:
            with open(output_path, 'w') as f:
                json.dump({
                    'config': self.config,
                    'exported_at': datetime.now().isoformat(),
                    'framework_version': '1.0.0'
                }, f, indent=2)
            
            logger.info(f"Ethical framework configuration exported to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting ethical framework configuration: {str(e)}")
            return False


# Définition de quelques activités de traitement préenregistrées pour BioCybe
DEFAULT_PROCESSING_ACTIVITIES = [
    DataProcessingActivity(
        name="Détection de comportements suspects",
        purpose="Identification d'activités potentiellement malveillantes sur les systèmes",
        data_categories=["Logs système", "Comportement utilisateur", "Activité réseau"],
        legal_basis="Intérêt légitime",
        retention_period="30 jours",
        security_measures=["Chiffrement", "Contrôle d'accès", "Anonymisation"],
        responsible_person="Responsable Sécurité"
    ),
    DataProcessingActivity(
        name="Amélioration des modèles de détection",
        purpose="Affiner les algorithmes pour réduire les faux positifs",
        data_categories=["Alertes historiques", "Données d'apprentissage anonymisées"],
        legal_basis="Consentement",
        retention_period="1 an",
        security_measures=["Anonymisation", "Agrégation", "Contrôle d'accès renforcé"],
        responsible_person="Responsable IA"
    ),
    DataProcessingActivity(
        name="Analyse forensique post-incident",
        purpose="Investigation approfondie suite à un incident de sécurité confirmé",
        data_categories=["Logs système", "Communication réseau", "Fichiers système"],
        legal_basis="Intérêt légitime / Obligation légale",
        retention_period="5 ans",
        security_measures=["Chiffrement", "Cloisonnement", "Journalisation des accès"],
        responsible_person="Équipe CERT"
    )
]
