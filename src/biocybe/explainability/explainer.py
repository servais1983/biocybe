#!/usr/bin/env python3

"""
BioCybe - Explications des décisions d'IA

Ce module fournit des classes pour rendre les décisions d'IA explicables
et interprétables, en s'inspirant des principes de l'IA explicable (XAI).
"""

import logging

import lime
import lime.lime_tabular
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
from captum.attr import DeepLift, GradientShap, IntegratedGradients

logger = logging.getLogger(__name__)


class ExplainableDecision:
    """
    Classe de base pour rendre les décisions d'IA explicables.
    Cette classe encapsule une décision d'IA et fournit des méthodes
    pour l'expliquer.
    """

    def __init__(self, model, model_type, feature_names=None):
        """
        Initialiser un objet ExplainableDecision.

        Args:
            model: Le modèle d'IA à expliquer
            model_type: Le type de modèle ('neural_network', 'tree', 'ensemble', etc.)
            feature_names: Liste des noms des fonctionnalités du modèle
        """
        self.model = model
        self.model_type = model_type
        self.feature_names = feature_names
        self.explainers = {}
        self._initialize_explainers()

    def _initialize_explainers(self):
        """Initialise les explainers appropriés selon le type de modèle."""
        try:
            if "neural_network" in self.model_type:
                # Explainers for neural networks
                if hasattr(self.model, "predict"):
                    self.explainers["shap"] = shap.DeepExplainer(
                        self.model, np.zeros((1, len(self.feature_names)))
                    )

                    # Captum explainers (pour les modèles PyTorch)
                    if "torch" in str(type(self.model)):
                        self.explainers["integrated_gradients"] = IntegratedGradients(self.model)
                        self.explainers["deep_lift"] = DeepLift(self.model)
                        self.explainers["gradient_shap"] = GradientShap(self.model)

            elif "tree" in self.model_type or "ensemble" in self.model_type:
                # TreeExplainer for tree-based models (Random Forest, XGBoost, etc.)
                self.explainers["shap"] = shap.TreeExplainer(self.model)

            else:
                # KernelExplainer as a fallback for all models
                self.explainers["shap"] = shap.KernelExplainer(
                    self.model.predict, np.zeros((1, len(self.feature_names)))
                )

            # LIME explainer for all models
            self.explainers["lime"] = lime.lime_tabular.LimeTabularExplainer(
                np.zeros((1, len(self.feature_names))),
                feature_names=self.feature_names,
                discretize_continuous=True,
            )

            logger.info(
                f"Initialized explainers for {self.model_type} model: {list(self.explainers.keys())}"
            )
        except Exception as e:
            logger.error(f"Error initializing explainers: {e!s}")
            raise

    def explain_prediction(self, input_data, method="shap", num_features=10):
        """
        Explique une prédiction particulière.

        Args:
            input_data: Les données d'entrée pour la prédiction à expliquer
            method: La méthode d'explication à utiliser ('shap', 'lime', etc.)
            num_features: Nombre de caractéristiques à inclure dans l'explication

        Returns:
            Un dictionnaire contenant les informations d'explication
        """
        explanation = {"method": method, "features": []}

        try:
            if method == "shap" and "shap" in self.explainers:
                # Calcul des valeurs SHAP
                shap_values = self.explainers["shap"].shap_values(input_data)

                # Format des données d'explication
                if isinstance(shap_values, list):
                    # Classification multi-classe
                    shap_values = shap_values[0]  # On prend la première classe pour simplifier

                # Création d'un DataFrame avec les valeurs d'importance
                importance_df = pd.DataFrame(
                    {
                        "feature": self.feature_names,
                        "importance": np.abs(shap_values).mean(axis=0)
                        if len(shap_values.shape) > 1
                        else np.abs(shap_values),
                        "value": input_data[0] if input_data.ndim > 1 else input_data,
                    }
                )

                # Tri par importance décroissante
                importance_df = importance_df.sort_values("importance", ascending=False).head(
                    num_features
                )

                # Ajout à l'explication
                explanation["features"] = importance_df.to_dict(orient="records")

            elif method == "lime" and "lime" in self.explainers:
                # Explication LIME
                lime_exp = self.explainers["lime"].explain_instance(
                    input_data[0] if input_data.ndim > 1 else input_data,
                    self.model.predict_proba,
                    num_features=num_features,
                )

                # Extraction des caractéristiques les plus importantes
                features = lime_exp.as_list()
                explanation["features"] = [{"feature": f[0], "importance": f[1]} for f in features]

            else:
                raise ValueError(f"Unsupported explanation method: {method}")

            logger.info(
                f"Generated explanation using {method} with {len(explanation['features'])} features"
            )
            return explanation

        except Exception as e:
            logger.error(f"Error generating explanation: {e!s}")
            explanation["error"] = str(e)
            return explanation

    def generate_explanation_text(self, explanation):
        """
        Génère une explication en langage naturel à partir des données d'explication.

        Args:
            explanation: Dictionnaire d'explication généré par explain_prediction

        Returns:
            str: Explication en langage naturel
        """
        try:
            if "error" in explanation:
                return f"Impossible de générer une explication: {explanation['error']}"

            # Construction du texte d'explication
            text = []
            text.append(f"Explication de la décision (méthode: {explanation['method']}):")
            text.append("")

            # Ajoute les caractéristiques les plus importantes
            text.append("Facteurs les plus importants dans cette décision:")

            for i, feature in enumerate(explanation["features"][:5]):  # Top 5 features
                importance = abs(feature["importance"])
                feature_name = feature["feature"]

                # Formatage de l'importance pour la lisibilité
                if importance < 0.01:
                    importance_str = f"{importance:.6f}"
                else:
                    importance_str = f"{importance:.4f}"

                # Direction de l'impact (positif ou négatif)
                direction = "augmenté" if feature["importance"] > 0 else "diminué"

                text.append(
                    f"  {i + 1}. {feature_name}: a {direction} le risque (importance: {importance_str})"
                )

            return "\n".join(text)

        except Exception as e:
            logger.error(f"Error generating explanation text: {e!s}")
            return f"Erreur lors de la génération de l'explication: {e!s}"


class DecisionVisualizer:
    """
    Classe pour visualiser les explications de décisions.
    """

    def __init__(self, dark_mode=False):
        """
        Initialise le visualiseur de décisions.

        Args:
            dark_mode: Si True, utilise un thème sombre pour les visualisations
        """
        self.dark_mode = dark_mode
        self._set_plot_style()

    def _set_plot_style(self):
        """Configure le style des graphiques selon le mode."""
        if self.dark_mode:
            plt.style.use("dark_background")
        else:
            plt.style.use("default")

    def plot_feature_importance(
        self, explanation, title="Importance des caractéristiques", figsize=(10, 6)
    ):
        """
        Génère un graphique d'importance des caractéristiques.

        Args:
            explanation: Dictionnaire d'explication
            title: Titre du graphique
            figsize: Taille de la figure (largeur, hauteur)

        Returns:
            matplotlib.figure.Figure: La figure générée
        """
        try:
            fig, ax = plt.subplots(figsize=figsize)

            # Extraction des données
            features = [f["feature"] for f in explanation["features"]]
            importances = [f["importance"] for f in explanation["features"]]

            # Création du graphique à barres horizontales
            ax.barh(range(len(features)), importances, color="#3498db")
            ax.set_yticks(range(len(features)))
            ax.set_yticklabels(features)
            ax.set_xlabel("Importance")
            ax.set_title(title)

            # Inversion pour avoir la plus importante en haut
            ax.invert_yaxis()

            plt.tight_layout()
            return fig

        except Exception as e:
            logger.error(f"Error plotting feature importance: {e!s}")
            fig, ax = plt.subplots(figsize=(8, 2))
            ax.text(
                0.5,
                0.5,
                f"Erreur lors de la création du graphique: {e!s}",
                ha="center",
                va="center",
            )
            return fig

    def plot_shap_summary(self, explainer, X_sample, max_display=20):
        """
        Génère un résumé SHAP pour un ensemble de données.

        Args:
            explainer: Un explainer SHAP initialisé
            X_sample: Échantillon de données pour l'explication
            max_display: Nombre maximum de caractéristiques à afficher

        Returns:
            matplotlib.figure.Figure: La figure générée
        """
        try:
            # Calcul des valeurs SHAP
            shap_values = explainer.shap_values(X_sample)

            # Création de la figure
            fig = plt.figure(figsize=(10, 8))

            # Création du résumé SHAP
            if isinstance(shap_values, list):
                # Multi-classe - on prend la première classe
                shap.summary_plot(shap_values[0], X_sample, show=False, max_display=max_display)
            else:
                # Binaire ou régression
                shap.summary_plot(shap_values, X_sample, show=False, max_display=max_display)

            plt.tight_layout()
            return fig

        except Exception as e:
            logger.error(f"Error plotting SHAP summary: {e!s}")
            fig, ax = plt.subplots(figsize=(8, 2))
            ax.text(
                0.5,
                0.5,
                f"Erreur lors de la création du résumé SHAP: {e!s}",
                ha="center",
                va="center",
            )
            return fig

    def plot_decision_tree(
        self, tree_model, feature_names, class_names=None, max_depth=3, figsize=(15, 10)
    ):
        """
        Visualise un arbre de décision pour une meilleure explicabilité.

        Args:
            tree_model: Un modèle d'arbre de décision
            feature_names: Noms des caractéristiques
            class_names: Noms des classes (pour les modèles de classification)
            max_depth: Profondeur maximale de l'arbre à visualiser
            figsize: Taille de la figure

        Returns:
            matplotlib.figure.Figure: La figure générée
        """
        try:
            from sklearn.tree import plot_tree

            fig, ax = plt.subplots(figsize=figsize)
            plot_tree(
                tree_model,
                feature_names=feature_names,
                class_names=class_names,
                filled=True,
                rounded=True,
                max_depth=max_depth,
                ax=ax,
            )

            plt.tight_layout()
            return fig

        except Exception as e:
            logger.error(f"Error plotting decision tree: {e!s}")
            fig, ax = plt.subplots(figsize=(8, 2))
            ax.text(
                0.5,
                0.5,
                f"Erreur lors de la visualisation de l'arbre: {e!s}",
                ha="center",
                va="center",
            )
            return fig


class ThreatExplainer:
    """
    Classe spécialisée pour expliquer les détections de menaces.
    """

    def __init__(self, detection_model, feature_names, threshold=0.5):
        """
        Initialise l'expliqueur de menaces.

        Args:
            detection_model: Le modèle de détection de menaces
            feature_names: Noms des caractéristiques utilisées par le modèle
            threshold: Seuil de décision pour la classification des menaces
        """
        self.model = detection_model
        self.feature_names = feature_names
        self.threshold = threshold
        self.explainable_decision = ExplainableDecision(
            detection_model, "neural_network", feature_names
        )

    def explain_threat_detection(self, input_data, explanation_method="shap"):
        """
        Explique pourquoi une détection de menace a été déclenchée.

        Args:
            input_data: Données d'entrée qui ont déclenché la détection
            explanation_method: Méthode d'explication à utiliser

        Returns:
            dict: Explication détaillée de la détection
        """
        # Obtenir la prédiction
        prediction = self.model.predict(input_data)
        prediction_proba = (
            self.model.predict_proba(input_data) if hasattr(self.model, "predict_proba") else None
        )

        # Déterminer si c'est une menace
        is_threat = (
            prediction[0] > self.threshold
            if hasattr(prediction, "__iter__")
            else prediction > self.threshold
        )

        # Préparer le résultat
        threat_explanation = {
            "is_threat": bool(is_threat),
            "confidence": float(prediction_proba[0][1])
            if prediction_proba is not None
            else float(prediction[0]),
            "threshold": self.threshold,
        }

        # Obtenir l'explication détaillée
        explanation = self.explainable_decision.explain_prediction(
            input_data, method=explanation_method
        )
        threat_explanation["explanation"] = explanation

        # Générer le texte d'explication
        threat_explanation["explanation_text"] = self.generate_threat_explanation_text(
            threat_explanation
        )

        return threat_explanation

    def generate_threat_explanation_text(self, threat_explanation):
        """
        Génère une explication en langage naturel pour une détection de menace.

        Args:
            threat_explanation: Dictionnaire contenant l'explication de la menace

        Returns:
            str: Explication en langage naturel
        """
        is_threat = threat_explanation["is_threat"]
        confidence = threat_explanation["confidence"] * 100  # Conversion en pourcentage

        # Construction du texte d'explication
        if is_threat:
            text = [
                f"🔴 ALERTE: Détection d'une activité suspecte (confiance: {confidence:.1f}%)",
                "",
                "BioCybe a identifié une menace potentielle basée sur les indicateurs suivants:",
            ]
        else:
            text = [
                f"🟢 Information: Activité analysée et jugée sûre (confiance: {100 - confidence:.1f}%)",
                "",
                "BioCybe a analysé cette activité et l'a jugée bénigne pour les raisons suivantes:",
            ]

        # Ajouter les facteurs les plus importants
        for i, feature in enumerate(threat_explanation["explanation"]["features"][:5]):
            feature_name = feature["feature"]
            importance = feature["importance"]
            direction = "augmenté" if importance > 0 else "diminué"

            text.append(f"  {i + 1}. {feature_name}: a {direction} le niveau de risque")

        # Ajouter des conseils si c'est une menace
        if is_threat:
            text.append("")
            text.append("Actions recommandées:")
            text.append("  - Isoler le processus suspect")
            text.append("  - Examiner les journaux d'activité")
            text.append("  - Vérifier les connexions réseau associées")

        return "\n".join(text)
