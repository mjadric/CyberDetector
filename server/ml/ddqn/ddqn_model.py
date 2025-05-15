#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - DDQN (Double Deep Q-Network) model
Implementacija DDQN modela za detekciju DDoS napada prema definiranoj metodologiji
"""

import os
import sys
import random
import json
import math
from datetime import datetime
from pathlib import Path
from collections import deque

# Enabling imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Provjera dostupnosti NumPy i TensorFlow
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: NumPy not available, using basic Python lists instead")

TF_AVAILABLE = False
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, load_model, Model
    from tensorflow.keras.layers import Dense, Input, BatchNormalization, Dropout
    from tensorflow.keras.optimizers import Adam
    TF_AVAILABLE = True
except ImportError:
    print("Warning: TensorFlow not available, using simplified model instead")

# Import iz našeg datasets paketa
try:
    from ml.ddqn.dataset_loader import DDQNDataLoader
except ImportError as e:
    print(f"Error importing dataset_loader module: {e}")

# Putanja za spremanje modela
MODEL_DIR = Path(__file__).parent.parent / "models"
MODEL_DIR.mkdir(exist_ok=True)

class SimplifiedDDQNAgent:
    """
    Pojednostavljeni DDQN agent za slučajeve kada TensorFlow nije dostupan.
    Koristi osnovne heuristike za detekciju napada.
    """
    
    def __init__(self, state_size=8, action_size=2):
        """
        Inicijalizacija jednostavnog DDQN agenta.
        
        Args:
            state_size: Veličina ulaznog stanja (broj značajki)
            action_size: Broj mogućih akcija (2: nema napada, ima napada)
        """
        self.state_size = state_size
        self.action_size = action_size
        
        # Pragovi za heuristike
        self.thresholds = {
            "source_entropy": 0.65,       # Visoka entropija izvorišnih IP-ova
            "destination_entropy": 0.3,    # Niska entropija odredišnih IP-ova
            "syn_ratio": 0.5,             # Visok omjer SYN paketa
            "traffic_volume": 0.6,         # Visok volumen prometa
            "packet_rate": 0.7,           # Visoka stopa paketa
            "unique_src_count": 0.6,      # Velik broj jedinstvenih izvorišnih IP-ova
            "unique_dst_count": 0.3,      # Mali broj jedinstvenih odredišnih IP-ova
            "protocol_imbalance": 0.4     # Srednja neravnoteža u distribuciji protokola
        }
        
        # Težine značajki
        self.feature_weights = [
            0.18,  # source_entropy
            0.12,  # destination_entropy
            0.25,  # syn_ratio
            0.15,  # traffic_volume
            0.20,  # packet_rate
            0.05,  # unique_src_ips_count
            0.02,  # unique_dst_ips_count
            0.03   # protocol_imbalance
        ]
    
    def act(self, state):
        """
        Odabire akciju na temelju trenutnog stanja.
        
        Args:
            state: Trenutno stanje (vektor značajki)
            
        Returns:
            int: 0 za normalno stanje, 1 za detektirani napad
        """
        # Jednostavni bodovni sustav na temelju heuristika
        suspicion_score = 0.0
        
        # Provjeri je li stanje NumPy array ili lista
        if isinstance(state, list) or (NUMPY_AVAILABLE and isinstance(state, np.ndarray)):
            # Izračunaj mjeru sumnje na temelju pragova i težina
            for i, feature in enumerate(state[:self.state_size]):
                feature_name = list(self.thresholds.keys())[i]
                threshold = self.thresholds[feature_name]
                weight = self.feature_weights[i]
                
                # Različite logike ovisno o značajki
                if feature_name in ["source_entropy", "syn_ratio", "traffic_volume", 
                                   "packet_rate", "unique_src_count"]:
                    # Za ove značajke, veće vrijednosti su sumnjivije
                    if feature > threshold:
                        suspicion_score += weight * (feature - threshold) / (1 - threshold)
                elif feature_name in ["destination_entropy", "unique_dst_count"]:
                    # Za ove značajke, manje vrijednosti su sumnjivije
                    if feature < threshold:
                        suspicion_score += weight * (threshold - feature) / threshold
                else:
                    # Za protokolnu neravnotežu, odstupanje od praga je sumnjivo
                    suspicion_score += weight * abs(feature - threshold)
        
        # Ako je suspicion_score veći od 0.5, to je napad
        return 1 if suspicion_score > 0.45 else 0
    
    def save(self, filepath):
        """
        Sprema parametre agenta.
        
        Args:
            filepath: Putanja za spremanje
        """
        params = {
            "thresholds": self.thresholds,
            "feature_weights": self.feature_weights,
            "state_size": self.state_size,
            "action_size": self.action_size,
            "saved_at": datetime.now().isoformat()
        }
        
        with open(filepath, 'w') as f:
            json.dump(params, f, indent=2)
        
        print(f"Parametri spremljeni u: {filepath}")
    
    def load(self, filepath):
        """
        Učitava parametre agenta.
        
        Args:
            filepath: Putanja za učitavanje
        """
        try:
            with open(filepath, 'r') as f:
                params = json.load(f)
            
            self.thresholds = params["thresholds"]
            self.feature_weights = params["feature_weights"]
            self.state_size = params["state_size"]
            self.action_size = params["action_size"]
            
            print(f"Parametri učitani iz: {filepath}")
            return True
        except Exception as e:
            print(f"Greška pri učitavanju parametara: {e}")
            return False
    
    def evaluate(self, states, labels):
        """
        Evaluira model na skupu podataka.
        
        Args:
            states: Lista stanja za evaluaciju
            labels: Lista stvarnih oznaka (0 za normalno, 1 za napad)
            
        Returns:
            dict: Metrike evaluacije
        """
        predictions = [self.act(state) for state in states]
        
        # Izračun metrika
        tp = sum(1 for p, l in zip(predictions, labels) if p == 1 and l == 1)
        fp = sum(1 for p, l in zip(predictions, labels) if p == 1 and l == 0)
        tn = sum(1 for p, l in zip(predictions, labels) if p == 0 and l == 0)
        fn = sum(1 for p, l in zip(predictions, labels) if p == 0 and l == 1)
        
        accuracy = (tp + tn) / len(labels) if len(labels) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn
        }


class DDQNAgent:
    """
    DDQN (Double Deep Q-Network) Agent za detekciju DDoS napada.
    Ova implementacija koristi TensorFlow i Keras za izgradnju modela.
    """
    
    def __init__(self, state_size=8, action_size=2, window_size=1):
        """
        Inicijalizacija DDQN agenta.
        
        Args:
            state_size: Veličina ulaznog stanja (broj značajki)
            action_size: Broj mogućih akcija (2: nema napada, ima napada)
            window_size: Veličina vremenskog prozora za ulaz
        """
        if not TF_AVAILABLE:
            print("TensorFlow nije dostupan, korištenje pojednostavljenog agenta.")
            self.simplified_agent = SimplifiedDDQNAgent(state_size, action_size)
            return
            
        self.state_size = state_size
        self.action_size = action_size
        self.window_size = window_size
        self.input_dim = state_size * window_size
        
        # Hiperparametri modela
        self.memory = deque(maxlen=2000)
        self.gamma = 0.95    # Discount factor
        self.epsilon = 1.0   # Exploration rate
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.learning_rate = 0.001
        self.update_target_frequency = 5  # Frekvencija ažuriranja target mreže
        
        # Izgradnja modela
        self.model = self._build_model()
        self.target_model = self._build_model()
        self.update_target_model()
        
        # Brojač koraka za target update
        self.target_update_counter = 0
    
    def _build_model(self):
        """
        Izgrađuje Deep Q-Network model.
        
        Returns:
            Kompilirani Keras model
        """
        if not TF_AVAILABLE:
            return None
            
        model = Sequential()
        
        # Izgradnja mreže prema metodologiji
        model.add(Dense(24, input_dim=self.input_dim, activation='relu'))
        model.add(BatchNormalization())
        model.add(Dense(48, activation='relu'))
        model.add(BatchNormalization())
        model.add(Dropout(0.2))
        model.add(Dense(24, activation='relu'))
        model.add(Dense(self.action_size, activation='linear'))
        
        model.compile(loss='mse', optimizer=Adam(learning_rate=self.learning_rate))
        return model
    
    def update_target_model(self):
        """
        Ažurira težine target mreže da odgovaraju glavnoj mreži.
        """
        if not TF_AVAILABLE:
            return
            
        self.target_model.set_weights(self.model.get_weights())
    
    def memorize(self, state, action, reward, next_state, done):
        """
        Sprema iskustvo u replay memoriju.
        
        Args:
            state: Trenutno stanje
            action: Poduzeta akcija
            reward: Primljena nagrada
            next_state: Sljedeće stanje
            done: Zastavica je li epizoda završena
        """
        if not TF_AVAILABLE:
            return
            
        self.memory.append((state, action, reward, next_state, done))
    
    def act(self, state):
        """
        Odabire akciju na temelju trenutnog stanja.
        
        Args:
            state: Trenutno stanje
            
        Returns:
            int: Odabrana akcija
        """
        if not TF_AVAILABLE:
            return self.simplified_agent.act(state)
            
        # Reshape stanja ako je potrebno
        if NUMPY_AVAILABLE and isinstance(state, np.ndarray):
            if len(state.shape) < 2:
                state = np.reshape(state, [1, self.input_dim])
        
        # Epsilon-greedy pristup
        if np.random.rand() <= self.epsilon:
            return random.randrange(self.action_size)
        
        act_values = self.model.predict(state)
        return np.argmax(act_values[0])
    
    def replay(self, batch_size):
        """
        Trenira model na batch-u iskustava iz replay memorije.
        
        Args:
            batch_size: Veličina batch-a
        """
        if not TF_AVAILABLE or len(self.memory) < batch_size:
            return
            
        minibatch = random.sample(self.memory, batch_size)
        
        for state, action, reward, next_state, done in minibatch:
            target = self.model.predict(state)
            
            if done:
                target[0][action] = reward
            else:
                t = self.target_model.predict(next_state)
                target[0][action] = reward + self.gamma * np.amax(t[0])
            
            self.model.fit(state, target, epochs=1, verbose=0)
        
        # Smanjenje epsilon za exploration
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        # Ažuriranje target mreže
        self.target_update_counter += 1
        if self.target_update_counter >= self.update_target_frequency:
            self.update_target_model()
            self.target_update_counter = 0
    
    def save(self, filepath):
        """
        Sprema DDQN model.
        
        Args:
            filepath: Putanja za spremanje
        """
        if not TF_AVAILABLE:
            # Ako TensorFlow nije dostupan, spremi parametre pojednostavljenog agenta
            simplified_filepath = filepath.replace(".h5", "_simplified.json")
            self.simplified_agent.save(simplified_filepath)
            return
            
        try:
            self.model.save(filepath)
            
            # Spremamo i konfiguraciju agenta
            config_path = filepath.replace(".h5", "_config.json")
            config = {
                "state_size": self.state_size,
                "action_size": self.action_size,
                "window_size": self.window_size,
                "gamma": self.gamma,
                "epsilon": self.epsilon,
                "epsilon_min": self.epsilon_min,
                "epsilon_decay": self.epsilon_decay,
                "learning_rate": self.learning_rate,
                "saved_at": datetime.now().isoformat()
            }
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"Model spremljen u: {filepath}")
            print(f"Konfiguracija spremljena u: {config_path}")
        except Exception as e:
            print(f"Greška pri spremanju modela: {e}")
    
    def load(self, filepath):
        """
        Učitava DDQN model.
        
        Args:
            filepath: Putanja za učitavanje
        """
        if not TF_AVAILABLE:
            # Ako TensorFlow nije dostupan, učitaj parametre pojednostavljenog agenta
            simplified_filepath = filepath.replace(".h5", "_simplified.json")
            return self.simplified_agent.load(simplified_filepath)
            
        try:
            self.model = load_model(filepath)
            self.target_model = load_model(filepath)
            
            # Učitavamo konfiguraciju agenta
            config_path = filepath.replace(".h5", "_config.json")
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            self.state_size = config["state_size"]
            self.action_size = config["action_size"]
            self.window_size = config["window_size"]
            self.input_dim = self.state_size * self.window_size
            self.gamma = config["gamma"]
            self.epsilon = config["epsilon"]
            self.epsilon_min = config["epsilon_min"]
            self.epsilon_decay = config["epsilon_decay"]
            self.learning_rate = config["learning_rate"]
            
            print(f"Model učitan iz: {filepath}")
            return True
        except Exception as e:
            print(f"Greška pri učitavanju modela: {e}")
            return False
    
    def evaluate(self, states, labels):
        """
        Evaluira model na skupu podataka.
        
        Args:
            states: Lista stanja za evaluaciju
            labels: Lista stvarnih oznaka (0 za normalno, 1 za napad)
            
        Returns:
            dict: Metrike evaluacije
        """
        if not TF_AVAILABLE:
            return self.simplified_agent.evaluate(states, labels)
            
        # Reshape stanja ako je potrebno
        if NUMPY_AVAILABLE and isinstance(states, np.ndarray):
            if len(states.shape) < 2:
                states = np.reshape(states, [-1, self.input_dim])
        
        # Predikcije modela
        q_values = self.model.predict(states)
        predictions = np.argmax(q_values, axis=1)
        
        # Izračun metrika
        tp = np.sum((predictions == 1) & (labels == 1))
        fp = np.sum((predictions == 1) & (labels == 0))
        tn = np.sum((predictions == 0) & (labels == 0))
        fn = np.sum((predictions == 0) & (labels == 1))
        
        accuracy = (tp + tn) / len(labels) if len(labels) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        # Dodatne metrike specifične za detekciju DDoS napada
        false_alarm_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        detection_rate = recall  # Isti kao i recall
        
        return {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "false_alarm_rate": float(false_alarm_rate),
            "detection_rate": float(detection_rate),
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn)
        }
    
    def train(self, dataset_loader, num_episodes=100, batch_size=32, 
              max_steps=None, early_stopping=True, validation_interval=5):
        """
        Trenira model na dataset-u.
        
        Args:
            dataset_loader: Loader za dataset
            num_episodes: Broj epizoda za trening
            batch_size: Veličina batch-a
            max_steps: Maksimalni broj koraka po epizodi
            early_stopping: Zastavica za rano zaustavljanje
            validation_interval: Interval epizoda za validaciju
            
        Returns:
            dict: Povijest treninga
        """
        if not TF_AVAILABLE:
            print("TensorFlow nije dostupan, trening nije moguć.")
            return None
            
        # Provjeri je li dataset učitan
        if not dataset_loader.dataset:
            success = dataset_loader.load()
            if not success:
                print("Učitavanje dataset-a nije uspjelo.")
                return None
        
        history = {
            "loss": [],
            "accuracy": [],
            "val_loss": [],
            "val_accuracy": [],
            "best_val_accuracy": 0.0,
            "best_model_episode": 0
        }
        
        for episode in range(num_episodes):
            print(f"Epizoda {episode+1}/{num_episodes}")
            
            # Dohvati slučajnu epizodu iz dataset-a
            train_episode = dataset_loader.get_episode(dataset_type="train")
            features = train_episode["features"]
            attack_labels = train_episode["attack_labels"]
            
            # Određivanje broja koraka u epizodi
            steps = min(len(features), max_steps) if max_steps else len(features)
            
            episode_loss = []
            episode_acc = []
            
            for step in range(steps):
                # Trenutno stanje
                if step < self.window_size:
                    # Za početne korake gdje nemamo dovoljno povijesti
                    state = features[:step+1]
                    # Dopuni do pune veličine prozora
                    while len(state) < self.window_size:
                        state.insert(0, state[0])
                else:
                    # Normalni slučaj
                    state = features[step-self.window_size+1:step+1]
                
                state = np.reshape(state, [1, -1])
                
                # Oznaka za trenutno stanje
                label = attack_labels[step]
                
                # Odabir akcije
                action = self.act(state)
                
                # Izračun nagrade
                reward = 1 if action == label else -1
                
                # Sljedeće stanje
                if step + 1 < steps:
                    next_features = features[step+1-self.window_size+1:step+2] if step + 1 >= self.window_size else features[:step+2]
                    while len(next_features) < self.window_size:
                        next_features.insert(0, next_features[0])
                    next_state = np.reshape(next_features, [1, -1])
                else:
                    # Ako smo na kraju epizode, koristimo trenutno stanje
                    next_state = state
                
                # Zastavica je li epizoda završena
                done = step + 1 >= steps
                
                # Spremanje iskustva
                self.memorize(state, action, reward, next_state, done)
                
                # Trening na batch-u
                if len(self.memory) >= batch_size:
                    self.replay(batch_size)
                
                # Bilježenje rezultata
                target = self.model.predict(state)
                target[0][action] = reward if done else reward + self.gamma * np.amax(self.target_model.predict(next_state)[0])
                loss = self.model.train_on_batch(state, target)
                episode_loss.append(loss)
                
                # Računanje točnosti
                q_values = self.model.predict(state)
                pred_action = np.argmax(q_values[0])
                acc = 1 if pred_action == label else 0
                episode_acc.append(acc)
            
            # Bilježenje rezultata epizode
            avg_loss = np.mean(episode_loss)
            avg_acc = np.mean(episode_acc)
            history["loss"].append(avg_loss)
            history["accuracy"].append(avg_acc)
            
            print(f"  Loss: {avg_loss:.4f}, Accuracy: {avg_acc:.4f}, Epsilon: {self.epsilon:.4f}")
            
            # Validacija na validacijskom skupu
            if (episode + 1) % validation_interval == 0:
                val_metrics = self.validate(dataset_loader)
                val_loss = val_metrics["loss"]
                val_acc = val_metrics["accuracy"]
                
                history["val_loss"].append(val_loss)
                history["val_accuracy"].append(val_acc)
                
                print(f"  Validacija - Loss: {val_loss:.4f}, Accuracy: {val_acc:.4f}")
                
                # Spremanje najboljeg modela
                if val_acc > history["best_val_accuracy"]:
                    history["best_val_accuracy"] = val_acc
                    history["best_model_episode"] = episode + 1
                    
                    # Spremanje najboljeg modela
                    best_model_path = MODEL_DIR / "ddqn_best_model.h5"
                    self.save(str(best_model_path))
                    
                    print(f"  Novi najbolji model spremljen! Val Accuracy: {val_acc:.4f}")
                    
                # Rano zaustavljanje
                if early_stopping and episode > 20 and val_acc < history["best_val_accuracy"] * 0.9:
                    print(f"Rano zaustavljanje! Nema poboljšanja u validacijskoj točnosti.")
                    break
        
        # Na kraju treninga, učitaj najbolji model
        best_model_path = MODEL_DIR / "ddqn_best_model.h5"
        if best_model_path.exists():
            self.load(str(best_model_path))
            print(f"Učitan najbolji model iz epizode {history['best_model_episode']}.")
        
        return history
    
    def validate(self, dataset_loader):
        """
        Validira model na validacijskom skupu.
        
        Args:
            dataset_loader: Loader za dataset
            
        Returns:
            dict: Metrike validacije
        """
        if not TF_AVAILABLE:
            print("TensorFlow nije dostupan, validacija nije moguća.")
            return None
            
        # Provjeri je li dataset učitan
        if not dataset_loader.dataset:
            success = dataset_loader.load()
            if not success:
                print("Učitavanje dataset-a nije uspjelo.")
                return None
        
        # Dohvati validacijske podatke
        X_val, y_val = dataset_loader.get_validation_data()
        
        if X_val is None or y_val is None:
            print("Validacijski podaci nisu dostupni.")
            return None
        
        # Reshape stanja ako je potrebno
        if NUMPY_AVAILABLE and isinstance(X_val, np.ndarray):
            if len(X_val.shape) < 2:
                X_val = np.reshape(X_val, [-1, self.input_dim])
        
        # Izračun loss-a i točnosti
        q_values = self.model.predict(X_val)
        predictions = np.argmax(q_values, axis=1)
        
        # MSE loss
        targets = np.zeros_like(q_values)
        for i, label in enumerate(y_val):
            targets[i, label] = 1
        loss = np.mean(np.square(q_values - targets))
        
        # Accuracy
        accuracy = np.mean(predictions == y_val)
        
        return {
            "loss": float(loss),
            "accuracy": float(accuracy)
        }
    
    def predict(self, state):
        """
        Predviđa akciju i Q-vrijednosti za dano stanje.
        
        Args:
            state: Stanje za predikciju
            
        Returns:
            tuple: (akcija, q_vrijednosti)
        """
        if not TF_AVAILABLE:
            action = self.simplified_agent.act(state)
            return action, [0.5, 0.5]  # Pojednostavljene Q-vrijednosti
            
        # Reshape stanja ako je potrebno
        if NUMPY_AVAILABLE and isinstance(state, np.ndarray):
            if len(state.shape) < 2:
                state = np.reshape(state, [1, self.input_dim])
        
        q_values = self.model.predict(state)[0]
        action = np.argmax(q_values)
        
        return action, q_values.tolist()


# Pomoćna funkcija za testiranje
def test_model():
    """
    Testna funkcija za provjeru funkcioniranja DDQN modela.
    """
    print("Inicijalizacija modela...")
    
    # Inicijaliziraj loader za dataset
    loader = DDQNDataLoader()
    success = loader.load()
    
    if not success:
        print("Učitavanje dataset-a nije uspjelo.")
        return False
        
    # Inicijaliziraj DDQN model
    agent = DDQNAgent(state_size=8, action_size=2, window_size=1)
    
    if TF_AVAILABLE:
        print("TensorFlow je dostupan, testiram DDQN model...")
        
        # Testiraj predikciju
        state = loader.get_episode()["features"][0]
        state = np.reshape(state, [1, 8]) if NUMPY_AVAILABLE else state
        
        action, q_values = agent.predict(state)
        print(f"Predikcija za testno stanje: Akcija={action}, Q-vrijednosti={q_values}")
        
        # Testiraj evaluaciju
        X_test, y_test = loader.get_test_data() or loader.get_validation_data()
        if X_test is not None and y_test is not None:
            metrics = agent.evaluate(X_test, y_test)
            print("\nMetrike evaluacije:")
            for key, value in metrics.items():
                print(f"  {key}: {value}")
                
        # Testiraj kratki trening
        if len(loader.dataset["train"]) > 0:
            print("\nTestiram kratki trening (2 epizode)...")
            history = agent.train(loader, num_episodes=2, batch_size=16)
            if history:
                print("Trening uspješno završen.")
                
                # Spremi i učitaj model
                model_path = MODEL_DIR / "ddqn_test_model.h5"
                agent.save(str(model_path))
                
                # Ponovna evaluacija nakon treninga
                metrics = agent.evaluate(X_test, y_test)
                print("\nMetrike evaluacije nakon treninga:")
                for key, value in metrics.items():
                    print(f"  {key}: {value}")
            
        return True
    else:
        print("TensorFlow nije dostupan, testiram pojednostavljeni model...")
        
        # Testiraj predikciju
        state = loader.get_episode()["features"][0]
        action = agent.act(state)
        print(f"Predikcija za testno stanje: Akcija={action}")
        
        # Testiraj evaluaciju
        X_test, y_test = loader.get_test_data() or loader.get_validation_data()
        if X_test is not None and y_test is not None:
            metrics = agent.evaluate(X_test, y_test)
            print("\nMetrike evaluacije:")
            for key, value in metrics.items():
                print(f"  {key}: {value}")
                
        # Spremi i učitaj model
        model_path = MODEL_DIR / "ddqn_test_model_simplified.json"
        agent.save(str(model_path))
        
        return True


# Ako se skripta izvršava direktno, testiraj model
if __name__ == "__main__":
    print("Testiranje DDQN modela...")
    test_model()