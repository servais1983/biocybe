#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de Reinforcement Learning pour BioCybe
Implémente l'apprentissage par renforcement basé sur la Danger Theory
"""

import os
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model, load_model
from tensorflow.keras.layers import Dense, Input, Flatten, Concatenate
from tensorflow.keras.optimizers import Adam
import logging
import yaml
import pickle
from collections import deque
import random

# Configuration du logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class DangerSignals:
    """Classe représentant les signaux de danger observés dans le système"""
    
    def __init__(self):
        self.signals = {
            'cpu_usage': 0.0,              # 0.0-1.0, usage CPU anormal
            'file_operations': 0.0,        # 0.0-1.0, intensité des opérations fichiers
            'network_anomalies': 0.0,      # 0.0-1.0, anomalies réseau
            'process_injection': 0.0,      # 0.0-1.0, tentatives d'injection
            'privilege_escalation': 0.0,   # 0.0-1.0, tentatives d'élévation de privilèges
            'registry_modifications': 0.0, # 0.0-1.0, modifications du registre
            'encryption_patterns': 0.0,    # 0.0-1.0, patterns de chiffrement
            'memory_anomalies': 0.0,       # 0.0-1.0, anomalies mémoire
            'system_integrity': 0.0        # 0.0-1.0, altérations intégrité système
        }
        
    def update(self, signal_name, value):
        """Met à jour un signal de danger spécifique"""
        if signal_name in self.signals:
            self.signals[signal_name] = max(0.0, min(1.0, value))  # Clamp entre 0 et 1
            return True
        return False
    
    def get_state(self):
        """Retourne l'état actuel des signaux de danger sous forme de tableau numpy"""
        return np.array(list(self.signals.values()), dtype=np.float32)
    
    def get_total_danger(self):
        """Calcule le niveau de danger total"""
        # On pourrait appliquer une pondération ici
        weights = {
            'cpu_usage': 0.7,
            'file_operations': 0.9,
            'network_anomalies': 0.8,
            'process_injection': 1.0,
            'privilege_escalation': 1.0,
            'registry_modifications': 0.8,
            'encryption_patterns': 0.9,
            'memory_anomalies': 0.7,
            'system_integrity': 1.0
        }
        
        weighted_sum = sum(self.signals[key] * weights[key] for key in self.signals)
        return weighted_sum / sum(weights.values())

class DefenseAction:
    """Représente une action défensive que le système peut prendre"""
    
    # Actions possibles
    MONITOR = 0         # Surveiller seulement
    ISOLATE_PROCESS = 1 # Isoler le processus
    QUARANTINE_FILE = 2 # Mettre en quarantaine un fichier
    TERMINATE = 3       # Terminer le processus
    RESTORE_BACKUP = 4  # Restaurer depuis une sauvegarde
    PATCH_SYSTEM = 5    # Appliquer un correctif
    
    @staticmethod
    def get_action_space():
        """Retourne le nombre d'actions possibles"""
        return 6
    
    @staticmethod
    def get_action_name(action_id):
        """Retourne le nom d'une action à partir de son ID"""
        action_names = {
            0: "MONITOR",
            1: "ISOLATE_PROCESS",
            2: "QUARANTINE_FILE",
            3: "TERMINATE",
            4: "RESTORE_BACKUP",
            5: "PATCH_SYSTEM"
        }
        return action_names.get(action_id, "UNKNOWN")

class Reward:
    """Gestionnaire de récompenses pour l'apprentissage par renforcement"""
    
    @staticmethod
    def calculate(danger_before, danger_after, action_taken, success, collateral_damage=0.0):
        """Calcule la récompense pour une action donnée"""
        
        # Réduction du danger
        danger_reduction = danger_before - danger_after
        
        # Récompenses de base
        base_rewards = {
            DefenseAction.MONITOR: 0.5,           # Récompense faible pour la surveillance
            DefenseAction.ISOLATE_PROCESS: 2.0,   # Bonne récompense pour l'isolation
            DefenseAction.QUARANTINE_FILE: 2.5,   # Bonne récompense pour la quarantaine
            DefenseAction.TERMINATE: 1.5,         # Récompense moyenne pour la terminaison
            DefenseAction.RESTORE_BACKUP: 3.0,    # Excellente récompense pour la restauration
            DefenseAction.PATCH_SYSTEM: 4.0       # Excellente récompense pour le correctif
        }
        
        # Pénalités possibles
        if not success:
            # L'action a échoué
            return -1.0
        
        if collateral_damage > 0:
            # Pénalité pour les dommages collatéraux (interruption de service, etc.)
            collateral_penalty = -5.0 * collateral_damage
        else:
            collateral_penalty = 0
        
        # Récompense finale
        reward = base_rewards[action_taken] * danger_reduction * 10 + collateral_penalty
        
        return reward

class ReplayBuffer:
    """Tampon de mémoire pour l'apprentissage par lots"""
    
    def __init__(self, capacity=10000):
        self.buffer = deque(maxlen=capacity)
    
    def add(self, state, action, reward, next_state, done):
        """Ajoute une expérience dans le tampon"""
        self.buffer.append((state, action, reward, next_state, done))
    
    def sample(self, batch_size):
        """Échantillonne un lot d'expériences"""
        return random.sample(self.buffer, min(len(self.buffer), batch_size))
    
    def size(self):
        """Retourne la taille actuelle du tampon"""
        return len(self.buffer)

class BioCybeRLAgent:
    """Agent d'apprentissage par renforcement pour BioCybe"""
    
    def __init__(self, state_size, action_size, config_path="config/learning.yaml"):
        """Initialise l'agent RL"""
        self.state_size = state_size
        self.action_size = action_size
        
        # Chargement de la configuration
        self.load_config(config_path)
        
        # Modèles (politique et valeur)
        self.policy_model = self._build_policy_network()
        self.value_model = self._build_value_network()
        
        # Tampon de mémoire
        self.memory = ReplayBuffer(capacity=self.replay_buffer_size)
        
        # Paramètres d'exploration
        self.epsilon = self.initial_epsilon
        self.epsilon_decay = (self.initial_epsilon - self.final_epsilon) / self.decay_steps
        
        # Métriques
        self.total_rewards = []
        self.avg_rewards = []
        self.training_episodes = 0
    
    def load_config(self, config_path):
        """Charge la configuration depuis un fichier YAML"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                rl_config = config.get('reinforcement_learning', {})
                
                # Paramètres d'entraînement
                training_config = rl_config.get('training', {})
                self.learning_rate = training_config.get('learning_rate', 0.0003)
                self.discount_factor = training_config.get('discount_factor', 0.99)
                self.episodes = training_config.get('episodes', 1000)
                self.batch_size = training_config.get('batch_size', 64)
                self.replay_buffer_size = training_config.get('replay_buffer_size', 10000)
                
                # Paramètres d'exploration
                exploration_config = rl_config.get('exploration', {})
                self.exploration_strategy = exploration_config.get('strategy', 'epsilon_greedy')
                self.initial_epsilon = exploration_config.get('initial_epsilon', 1.0)
                self.final_epsilon = exploration_config.get('final_epsilon', 0.1)
                self.decay_steps = exploration_config.get('decay_steps', 10000)
                
                logger.info(f"Configuration chargée: {config_path}")
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {e}")
            # Valeurs par défaut
            self.learning_rate = 0.0003
            self.discount_factor = 0.99
            self.episodes = 1000
            self.batch_size = 64
            self.replay_buffer_size = 10000
            self.exploration_strategy = 'epsilon_greedy'
            self.initial_epsilon = 1.0
            self.final_epsilon = 0.1
            self.decay_steps = 10000
    
    def _build_policy_network(self):
        """Construit le réseau de politique (policy network)"""
        inputs = Input(shape=(self.state_size,))
        x = Dense(256, activation='relu')(inputs)
        x = Dense(256, activation='relu')(x)
        outputs = Dense(self.action_size, activation='softmax')(x)
        
        model = Model(inputs=inputs, outputs=outputs)
        model.compile(optimizer=Adam(learning_rate=self.learning_rate),
                      loss='categorical_crossentropy')
        
        return model
    
    def _build_value_network(self):
        """Construit le réseau de valeur (value network)"""
        inputs = Input(shape=(self.state_size,))
        x = Dense(256, activation='relu')(inputs)
        x = Dense(256, activation='relu')(x)
        outputs = Dense(1, activation='linear')(x)
        
        model = Model(inputs=inputs, outputs=outputs)
        model.compile(optimizer=Adam(learning_rate=self.learning_rate),
                      loss='mse')
        
        return model
    
    def act(self, state, evaluate=False):
        """Choisit une action en fonction de l'état actuel"""
        state = np.reshape(state, [1, self.state_size])
        
        # Phase d'évaluation (sans exploration)
        if evaluate:
            action_probs = self.policy_model.predict(state, verbose=0)[0]
            return np.argmax(action_probs)
        
        # Phase d'entraînement (avec exploration)
        if self.exploration_strategy == 'epsilon_greedy':
            if np.random.rand() <= self.epsilon:
                return np.random.randint(self.action_size)
            else:
                action_probs = self.policy_model.predict(state, verbose=0)[0]
                return np.argmax(action_probs)
        
        elif self.exploration_strategy == 'boltzmann':
            action_probs = self.policy_model.predict(state, verbose=0)[0]
            # Application d'une distribution de Boltzmann
            temperature = max(0.1, self.epsilon)  # Température diminue avec epsilon
            exp_probs = np.exp(action_probs / temperature)
            action_probs = exp_probs / np.sum(exp_probs)
            return np.random.choice(self.action_size, p=action_probs)
        
        else:  # Stratégie par défaut
            action_probs = self.policy_model.predict(state, verbose=0)[0]
            return np.argmax(action_probs)
    
    def remember(self, state, action, reward, next_state, done):
        """Mémorise une expérience"""
        self.memory.add(state, action, reward, next_state, done)
    
    def replay(self, batch_size):
        """Apprentissage par lots depuis la mémoire"""
        if self.memory.size() < batch_size:
            return
        
        minibatch = self.memory.sample(batch_size)
        
        states = np.array([experience[0] for experience in minibatch])
        actions = np.array([experience[1] for experience in minibatch])
        rewards = np.array([experience[2] for experience in minibatch])
        next_states = np.array([experience[3] for experience in minibatch])
        dones = np.array([experience[4] for experience in minibatch])
        
        # Entraînement du réseau de valeur
        values = self.value_model.predict(states, verbose=0)
        next_values = self.value_model.predict(next_states, verbose=0)
        
        targets = rewards + self.discount_factor * next_values.flatten() * (1 - dones)
        targets = targets.reshape(-1, 1)
        
        self.value_model.fit(states, targets, epochs=1, verbose=0)
        
        # Entraînement du réseau de politique
        advantages = targets - values
        
        # Préparation des données pour l'entraînement
        action_masks = np.zeros((len(actions), self.action_size))
        action_masks[np.arange(len(actions)), actions] = 1
        
        # Pondération par avantages
        weighted_masks = action_masks * advantages
        
        self.policy_model.fit(states, weighted_masks, epochs=1, verbose=0)
        
        # Réduction d'epsilon pour l'exploration
        if self.epsilon > self.final_epsilon:
            self.epsilon -= self.epsilon_decay
    
    def save(self, directory="models/rl"):
        """Sauvegarde les modèles"""
        os.makedirs(directory, exist_ok=True)
        self.policy_model.save(os.path.join(directory, "policy_model.h5"))
        self.value_model.save(os.path.join(directory, "value_model.h5"))
        
        # Sauvegarde des hyperparamètres
        hyperparams = {
            "epsilon": self.epsilon,
            "total_rewards": self.total_rewards,
            "avg_rewards": self.avg_rewards,
            "training_episodes": self.training_episodes
        }
        
        with open(os.path.join(directory, "hyperparams.pkl"), "wb") as f:
            pickle.dump(hyperparams, f)
        
        logger.info(f"Modèles sauvegardés dans {directory}")
    
    def load(self, directory="models/rl"):
        """Charge les modèles"""
        try:
            self.policy_model = load_model(os.path.join(directory, "policy_model.h5"))
            self.value_model = load_model(os.path.join(directory, "value_model.h5"))
            
            # Chargement des hyperparamètres
            with open(os.path.join(directory, "hyperparams.pkl"), "rb") as f:
                hyperparams = pickle.load(f)
                self.epsilon = hyperparams["epsilon"]
                self.total_rewards = hyperparams["total_rewards"]
                self.avg_rewards = hyperparams["avg_rewards"]
                self.training_episodes = hyperparams["training_episodes"]
            
            logger.info(f"Modèles chargés depuis {directory}")
            return True
        except Exception as e:
            logger.error(f"Erreur lors du chargement des modèles: {e}")
            return False
    
    def train(self, env, episodes=None, render=False):
        """Entraîne l'agent dans un environnement"""
        if episodes is None:
            episodes = self.episodes
        
        for episode in range(episodes):
            state = env.reset()
            state = np.reshape(state, [1, self.state_size])[0]
            done = False
            total_reward = 0
            
            while not done:
                if render:
                    env.render()
                
                # Sélection de l'action
                action = self.act(state)
                
                # Exécution de l'action
                next_state, reward, done, _ = env.step(action)
                next_state = np.reshape(next_state, [1, self.state_size])[0]
                
                # Mémorisation de l'expérience
                self.remember(state, action, reward, next_state, done)
                
                # Apprentissage
                self.replay(self.batch_size)
                
                state = next_state
                total_reward += reward
            
            self.total_rewards.append(total_reward)
            avg_reward = np.mean(self.total_rewards[-100:])
            self.avg_rewards.append(avg_reward)
            self.training_episodes += 1
            
            if episode % 10 == 0:
                logger.info(f"Episode: {episode}/{episodes}, Reward: {total_reward}, Avg Reward: {avg_reward}, Epsilon: {self.epsilon:.4f}")
            
            if episode % 100 == 0:
                self.save()
        
        return self.avg_rewards

# Exemple d'utilisation
if __name__ == "__main__":
    # Taille de l'état (signaux de danger)
    state_size = 9
    
    # Taille de l'espace d'actions
    action_size = DefenseAction.get_action_space()
    
    # Création de l'agent
    agent = BioCybeRLAgent(state_size, action_size)
    
    print("Agent RL BioCybe initialisé")
    print(f"État: {state_size} dimensions")
    print(f"Actions: {action_size} possibles")
    
    # Simuler un état de danger
    danger = DangerSignals()
    danger.update('cpu_usage', 0.7)
    danger.update('file_operations', 0.9)
    danger.update('encryption_patterns', 0.8)
    
    state = danger.get_state()
    print(f"État de danger: {state}")
    print(f"Niveau de danger total: {danger.get_total_danger():.2f}")
    
    # Prédire une action
    action = agent.act(state, evaluate=True)
    print(f"Action recommandée: {DefenseAction.get_action_name(action)}")
