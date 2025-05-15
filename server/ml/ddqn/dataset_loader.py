#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Dataset Loader za DDQN model
Module for loading and processing datasets for DDQN training and evaluation
"""

import os
import sys
import json
import random
from datetime import datetime
from pathlib import Path

# Enabling imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Provjera je li NumPy dostupan
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: NumPy not available, using basic Python lists instead")

# Import iz našeg datasets paketa
try:
    from datasets import get_available_datasets, load_dataset, initialize_datasets
    from datasets import DATASET_ROOT, TRAINING_DATA_DIR
except ImportError as e:
    print(f"Error importing datasets module: {e}")
    # Fallback paths ako import ne uspije
    SCRIPT_DIR = Path(__file__).parent
    DATASET_ROOT = SCRIPT_DIR.parent.parent / "datasets"
    TRAINING_DATA_DIR = DATASET_ROOT / "training"

class DDQNDataLoader:
    """
    Loader za dataset-e korištene u DDQN modelu za detekciju DDoS napada
    """
    
    def __init__(self, dataset_path=None):
        """
        Inicijalizacija loadera za DDQN dataset-e.
        
        Args:
            dataset_path: Putanja do dataset-a. Ako nije navedena, koristi se najnoviji dostupni.
        """
        self.dataset_path = dataset_path
        self.dataset = None
        self.feature_names = [
            "source_entropy",
            "destination_entropy",
            "syn_ratio",
            "traffic_volume",
            "packet_rate",
            "unique_src_ips_count",
            "unique_dst_ips_count",
            "protocol_imbalance"
        ]
        
        # Provjeri dostupne dataset-e ako putanja nije navedena
        if not dataset_path:
            self._find_latest_dataset()
    
    def _find_latest_dataset(self):
        """
        Pronalazi najnoviji dostupni dataset za DDQN.
        """
        try:
            # Prvo pokušajmo koristiti funkciju iz datasets paketa
            datasets = get_available_datasets()
            training_datasets = datasets.get("training", [])
            
            if training_datasets:
                # Sortiraj po vremenu modifikacije (najnoviji prvi)
                latest = sorted(training_datasets, key=lambda x: x["modified"], reverse=True)[0]
                self.dataset_path = latest["path"]
                print(f"Najnoviji pronađeni dataset: {latest['filename']}")
            else:
                # Ako nema dataset-a, inicijaliziraj ih
                print("Nema dostupnih dataset-a, inicijaliziram demo dataset-e...")
                initialize_datasets()
                # Ponovno pokušaj pronaći dataset
                datasets = get_available_datasets()
                training_datasets = datasets.get("training", [])
                
                if training_datasets:
                    latest = sorted(training_datasets, key=lambda x: x["modified"], reverse=True)[0]
                    self.dataset_path = latest["path"]
                    print(f"Inicijalizirani dataset: {latest['filename']}")
                else:
                    self.dataset_path = None
                    print("Nije pronađen nijedan dataset.")
                    
        except (NameError, ImportError, Exception) as e:
            # Fallback metoda ako funkcije iz datasets paketa nisu dostupne
            print(f"Korištenje fallback metode za pronalazak dataset-a: {e}")
            
            try:
                # Pronađi sve JSON datoteke u training direktoriju
                json_files = list(TRAINING_DATA_DIR.glob("*.json"))
                
                if json_files:
                    # Sortiraj po vremenu modifikacije (najnoviji prvi)
                    latest = sorted(json_files, key=lambda x: x.stat().st_mtime, reverse=True)[0]
                    self.dataset_path = str(latest)
                    print(f"Najnoviji pronađeni dataset (fallback): {latest.name}")
                else:
                    self.dataset_path = None
                    print("Nije pronađen nijedan dataset (fallback).")
            except Exception as e2:
                print(f"Greška pri pronalasku dataset-a (fallback): {e2}")
                self.dataset_path = None
    
    def load(self):
        """
        Učitava dataset iz JSON datoteke.
        
        Returns:
            True ako je učitavanje uspješno, inače False
        """
        if not self.dataset_path:
            print("Putanja do dataset-a nije definirana.")
            return False
        
        try:
            # Prvo pokušajmo koristiti funkciju iz datasets paketa
            try:
                self.dataset = load_dataset(self.dataset_path)
            except (NameError, ImportError):
                # Fallback učitavanje ako funkcija iz paketa nije dostupna
                with open(self.dataset_path, 'r') as f:
                    self.dataset = json.load(f)
            
            if not self.dataset:
                print(f"Učitavanje dataset-a nije uspjelo: {self.dataset_path}")
                return False
            
            # Provjeri strukturu dataset-a
            required_keys = ["train", "validation", "test", "metadata"]
            if not all(key in self.dataset for key in required_keys):
                print(f"Dataset nema ispravnu strukturu: {self.dataset_path}")
                missing = [key for key in required_keys if key not in self.dataset]
                print(f"Nedostaje: {missing}")
                return False
            
            # Postavi nazive značajki iz metapodataka ako su dostupni
            if "feature_names" in self.dataset["metadata"]:
                self.feature_names = self.dataset["metadata"]["feature_names"]
            
            print(f"Dataset uspješno učitan: {self.dataset_path}")
            print(f"Broj epizoda za trening: {len(self.dataset['train'])}")
            print(f"Broj epizoda za validaciju: {len(self.dataset['validation'])}")
            print(f"Broj epizoda za testiranje: {len(self.dataset['test'])}")
            
            return True
            
        except Exception as e:
            print(f"Greška pri učitavanju dataset-a: {e}")
            return False
    
    def get_training_data(self):
        """
        Vraća podatke za trening.
        
        Returns:
            Tuple (X_train, y_train) ili None ako dataset nije učitan
        """
        if not self.dataset:
            if not self.load():
                return None
        
        return self._extract_features_and_labels(self.dataset["train"])
    
    def get_validation_data(self):
        """
        Vraća podatke za validaciju.
        
        Returns:
            Tuple (X_val, y_val) ili None ako dataset nije učitan
        """
        if not self.dataset:
            if not self.load():
                return None
        
        return self._extract_features_and_labels(self.dataset["validation"])
    
    def get_test_data(self):
        """
        Vraća podatke za testiranje.
        
        Returns:
            Tuple (X_test, y_test) ili None ako dataset nije učitan
        """
        if not self.dataset:
            if not self.load():
                return None
        
        return self._extract_features_and_labels(self.dataset["test"])
    
    def _extract_features_and_labels(self, episodes):
        """
        Izvlači značajke i oznake iz epizoda.
        
        Args:
            episodes: Lista epizoda iz dataset-a
            
        Returns:
            Tuple (X, y) gdje su X značajke a y oznake
        """
        if not episodes:
            return None
        
        all_features = []
        all_labels = []
        
        for episode in episodes:
            features = episode["features"]
            attack_labels = episode["attack_labels"]
            
            # Kod DDQN-a želimo sekvence uzastopnih stanja
            # Pa ćemo koristiti klizne prozore ako koristimo supervised learning pristup
            window_size = 5  # Koristi 5 uzastopnih stanja
            
            for i in range(len(features) - window_size + 1):
                window_features = features[i:i+window_size]
                window_label = attack_labels[i+window_size-1]  # Oznaka zadnjeg stanja u prozoru
                
                # Pretvaranje u ravnu listu (flatten)
                flattened_features = []
                for state in window_features:
                    if NUMPY_AVAILABLE:
                        flattened_features.extend(state)
                    else:
                        flattened_features.extend(state)
                
                all_features.append(flattened_features)
                all_labels.append(1 if window_label else 0)  # 1 za napad, 0 za normalno
        
        # Pretvaranje u NumPy array ako je dostupan
        if NUMPY_AVAILABLE:
            all_features = np.array(all_features)
            all_labels = np.array(all_labels)
        
        return all_features, all_labels
    
    def generate_batch(self, batch_size=32, dataset_type="train"):
        """
        Generira batch podataka za trening DQN mreže.
        
        Args:
            batch_size: Veličina batch-a
            dataset_type: Tip dataset-a ('train', 'validation', 'test')
            
        Returns:
            Batch podataka (značajke, oznake)
        """
        if not self.dataset:
            if not self.load():
                return None
        
        # Odabir odgovarajućeg skupa podataka
        if dataset_type not in self.dataset:
            print(f"Tip dataset-a '{dataset_type}' nije dostupan.")
            return None
        
        episodes = self.dataset[dataset_type]
        
        # Slučajni odabir epizode
        episode = random.choice(episodes)
        features = episode["features"]
        attack_labels = episode["attack_labels"]
        
        # Slučajni odabir indeksa za batch
        max_index = len(features) - 1
        indices = [random.randint(0, max_index) for _ in range(batch_size)]
        
        batch_features = [features[i] for i in indices]
        batch_labels = [1 if attack_labels[i] else 0 for i in indices]
        
        # Pretvaranje u NumPy array ako je dostupan
        if NUMPY_AVAILABLE:
            batch_features = np.array(batch_features)
            batch_labels = np.array(batch_labels)
        
        return batch_features, batch_labels
    
    def get_episode(self, episode_id=None, dataset_type="train"):
        """
        Vraća određenu epizodu iz dataset-a.
        
        Args:
            episode_id: ID epizode. Ako nije naveden, vraća slučajnu epizodu.
            dataset_type: Tip dataset-a ('train', 'validation', 'test')
            
        Returns:
            Dict s podacima epizode
        """
        if not self.dataset:
            if not self.load():
                return None
        
        # Odabir odgovarajućeg skupa podataka
        if dataset_type not in self.dataset:
            print(f"Tip dataset-a '{dataset_type}' nije dostupan.")
            return None
        
        episodes = self.dataset[dataset_type]
        
        if episode_id is not None:
            # Traži epizodu s odgovarajućim ID-om
            for episode in episodes:
                if episode["episode_id"] == episode_id:
                    return episode
            
            print(f"Epizoda s ID-om {episode_id} nije pronađena.")
            return None
        else:
            # Vraća slučajnu epizodu
            return random.choice(episodes)
    
    def get_dataset_stats(self):
        """
        Vraća statistiku dataset-a.
        
        Returns:
            Dict sa statistikom
        """
        if not self.dataset:
            if not self.load():
                return None
        
        stats = {
            "total_episodes": (
                len(self.dataset["train"]) + 
                len(self.dataset["validation"]) + 
                len(self.dataset["test"])
            ),
            "train_episodes": len(self.dataset["train"]),
            "validation_episodes": len(self.dataset["validation"]),
            "test_episodes": len(self.dataset["test"]),
            "feature_names": self.feature_names,
            "creation_date": self.dataset["metadata"].get("creation_date", "Unknown"),
            "attack_probability": self.dataset["metadata"].get("attack_probability", 0.5)
        }
        
        # Izračun omjera napada u dataset-u
        attack_counts = {
            "train": 0,
            "validation": 0,
            "test": 0
        }
        
        for dataset_type in ["train", "validation", "test"]:
            for episode in self.dataset[dataset_type]:
                # Ako postoji napad u metapodacima epizode, povećaj brojač
                if "metadata" in episode and "attack" in episode["metadata"] and episode["metadata"]["attack"] is not None:
                    attack_counts[dataset_type] += 1
        
        stats["attack_ratio"] = {
            "train": attack_counts["train"] / stats["train_episodes"] if stats["train_episodes"] else 0,
            "validation": attack_counts["validation"] / stats["validation_episodes"] if stats["validation_episodes"] else 0,
            "test": attack_counts["test"] / stats["test_episodes"] if stats["test_episodes"] else 0
        }
        
        return stats


# Pomoćna funkcija za testiranje
def test_loader():
    """
    Testna funkcija za provjeru funkcioniranja data loadera.
    """
    loader = DDQNDataLoader()
    success = loader.load()
    
    if success:
        # Ispisujemo statistiku
        stats = loader.get_dataset_stats()
        print("\nStatistika dataset-a:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        # Testiramo dohvat podataka
        X_train, y_train = loader.get_training_data()
        if X_train is not None and y_train is not None:
            print(f"\nVeličina training skupa: {len(X_train)} uzoraka")
            print(f"Omjer napada u training skupu: {sum(y_train) / len(y_train):.2f}")
            
            # Ispisujemo nekoliko uzoraka
            if NUMPY_AVAILABLE:
                print(f"Oblik značajki za trening: {X_train.shape}")
                print(f"Oblik oznaka za trening: {y_train.shape}")
            else:
                print(f"Broj značajki za trening: {len(X_train)}")
                print(f"Broj oznaka za trening: {len(y_train)}")
                
        # Testiramo batch generator
        batch_X, batch_y = loader.generate_batch(batch_size=10)
        print(f"\nGenerirani batch veličine: {len(batch_X)}")
        
        # Dohvaćamo jednu epizodu
        episode = loader.get_episode()
        print(f"\nSlučajna epizoda ID: {episode['episode_id']}")
        if "metadata" in episode and "attack" in episode["metadata"] and episode["metadata"]["attack"] is not None:
            print(f"Tip napada: {episode['metadata']['attack']['type']}")
            print(f"Intenzitet napada: {episode['metadata']['attack']['intensity']}")
        else:
            print("Epizoda ne sadrži napad.")
            
        return True
    else:
        print("Test nije uspio - učitavanje dataset-a nije uspjelo.")
        return False


# Ako se skripta izvršava direktno, testiraj loader
if __name__ == "__main__":
    print("Testiranje dataset loadera za DDQN...")
    test_loader()