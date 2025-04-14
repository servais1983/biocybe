# Modèles d'Intelligence Artificielle

BioCybe utilise plusieurs approches d'IA pour reproduire les capacités du système immunitaire en matière de détection et d'apprentissage.

## 1. Détection de malwares par Deep Learning

### 1.1 CNN pour l'analyse d'images de malwares

Les fichiers binaires sont convertis en images (visualisation de l'entropie) puis analysés par des réseaux de neurones convolutifs :

```python
def create_malware_cnn():
    model = Sequential([
        Conv2D(32, (3, 3), activation='relu', input_shape=(256, 256, 1)),
        MaxPooling2D((2, 2)),
        Conv2D(64, (3, 3), activation='relu'),
        MaxPooling2D((2, 2)),
        Conv2D(128, (3, 3), activation='relu'),
        MaxPooling2D((2, 2)),
        Flatten(),
        Dense(128, activation='relu'),
        Dropout(0.5),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model
```

### 1.2 Transformers pour l'analyse de séquences

Pour l'analyse des séquences d'API calls et des chaînes de caractères :

```python
def create_api_sequence_transformer():
    input_layer = Input(shape=(MAX_SEQUENCE_LENGTH,))
    embedding_layer = Embedding(input_dim=VOCAB_SIZE, output_dim=EMBEDDING_DIM)(input_layer)
    transformer_block = TransformerBlock(embed_dim=EMBEDDING_DIM, num_heads=8, ff_dim=512)(embedding_layer)
    pooling = GlobalAveragePooling1D()(transformer_block)
    dropout = Dropout(0.1)(pooling)
    output = Dense(1, activation='sigmoid')(dropout)
    model = Model(inputs=input_layer, outputs=output)
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model
```

## 2. Reinforcement Learning pour la prise de décision

### 2.1 Architecture PPO (Proximal Policy Optimization)

Utilisée pour optimiser les décisions de réponse aux menaces :

```python
class CyberDefenseAgent:
    def __init__(self, state_dim, action_dim):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.policy = self._build_policy_network()
        self.value = self._build_value_network()
        self.optimizer = tf.keras.optimizers.Adam(learning_rate=0.0003)
        
    def _build_policy_network(self):
        inputs = Input(shape=(self.state_dim,))
        x = Dense(256, activation='relu')(inputs)
        x = Dense(256, activation='relu')(x)
        actions = Dense(self.action_dim, activation='softmax')(x)
        return Model(inputs=inputs, outputs=actions)
```

### 2.2 Fonction de récompense Danger Theory

```python
def calculate_reward(danger_signals_before, danger_signals_after, false_positive, damage):
    # Réduction des signaux de danger = récompense positive
    danger_reduction = sum(danger_signals_before) - sum(danger_signals_after)
    
    # Pénalisation pour faux positifs et dommages collatéraux
    penalty = 5.0 * false_positive + 10.0 * damage
    
    return danger_reduction - penalty
```

## 3. Détection d'anomalies non supervisée

### 3.1 Autoencodeurs pour la détection comportementale

```python
def create_autoencoder(input_dim):
    # Encodeur
    input_layer = Input(shape=(input_dim,))
    encoded = Dense(128, activation='relu')(input_layer)
    encoded = Dense(64, activation='relu')(encoded)
    encoded = Dense(32, activation='relu')(encoded)
    
    # Décodeur
    decoded = Dense(64, activation='relu')(encoded)
    decoded = Dense(128, activation='relu')(decoded)
    decoded = Dense(input_dim, activation='sigmoid')(decoded)
    
    # Modèle complet
    autoencoder = Model(input_layer, decoded)
    autoencoder.compile(optimizer='adam', loss='mse')
    
    return autoencoder
```

### 3.2 One-class SVM pour la détection des outliers

```python
def train_ocsvm(X_train):
    # Normalisation des données
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Entraînement du One-Class SVM
    ocsvm = OneClassSVM(nu=0.1, kernel="rbf", gamma=0.1)
    ocsvm.fit(X_train_scaled)
    
    return ocsvm, scaler
```

## 4. Apprentissage fédéré

Pour permettre le partage de connaissances sans compromettre les données sensibles :

```python
def federated_update(global_model, client_models, client_weights):
    # Initialisation du modèle global avec des zéros
    global_weights = [np.zeros_like(w) for w in global_model.get_weights()]
    
    # Moyenne pondérée des poids des clients
    for i, client_model in enumerate(client_models):
        client_w = client_model.get_weights()
        for j, w in enumerate(client_w):
            global_weights[j] += client_weights[i] * w
    
    # Mise à jour du modèle global
    global_model.set_weights(global_weights)
    return global_model
```

## 5. Pipeline d'entraînement et d'évaluation

```python
def training_pipeline():
    # Chargement des données
    X_train, X_test, y_train, y_test = load_dataset()
    
    # Entraînement du modèle statique
    static_model = create_malware_cnn()
    static_model.fit(X_train, y_train, epochs=20, validation_split=0.2)
    
    # Entraînement du détecteur d'anomalies
    autoencoder = create_autoencoder(X_train.shape[1])
    autoencoder.fit(X_train, X_train, epochs=50, batch_size=256, validation_split=0.2)
    
    # Initialisation de l'agent RL
    rl_agent = CyberDefenseAgent(state_dim=STATE_DIM, action_dim=ACTION_DIM)
    
    # Simulation pour entraîner l'agent RL
    train_rl_agent(rl_agent, static_model, autoencoder, episodes=1000)
    
    return static_model, autoencoder, rl_agent
```

Ces modèles sont en constante évolution dans le projet BioCybe, avec des améliorations régulières basées sur les performances en conditions réelles.