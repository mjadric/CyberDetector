#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - DDQN Detektor
Implementacija DDQN detektora napada koji ima dva načina rada:
1. Online učenje - uči direktno iz okruženja/simulacije
2. Batch učenje - uči iz prethodno generiranih podataka
"""

import os
import sys
import json
import time
import math
from datetime import datetime, timedelta
from pathlib import Path

# Enabling imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Provjera dostupnosti NumPy i TensorFlow
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: NumPy not available, using basic Python lists instead")

# Import iz naših modula
try:
    from ml.ddqn.dataset_loader import DDQNDataLoader
    from ml.ddqn.ddqn_model import DDQNAgent
except ImportError as e:
    print(f"Error importing ML modules: {e}")

# Putanje do modela i dataset-a
MODEL_DIR = Path(__file__).parent / "models"
MODEL_DIR.mkdir(exist_ok=True)
DEFAULT_MODEL_PATH = MODEL_DIR / "ddqn_best_model.h5"
SIMPLIFIED_MODEL_PATH = MODEL_DIR / "ddqn_best_model_simplified.json"

class DDQNDetector:
    """
    DDQN detektor napada koji može raditi u dva moda:
    1. Online način - kontinuirano uči iz live okruženja/simulacije
    2. Batch način - uči iz prethodno generiranih podataka
    
    Detektor koristi DDQN (Double Deep Q-Network) za detekciju DDoS napada.
    """
    
    def __init__(self, model_path=None, window_size=5, online_learning=True):
        """
        Inicijalizacija detektora.
        
        Args:
            model_path: Putanja do modela. Ako nije navedena, koristi se zadani model.
            window_size: Veličina vremenskog prozora za analizu
            online_learning: Zastavica za online učenje
        """
        self.window_size = window_size
        self.model_path = model_path
        self.online_learning = online_learning
        self.agent = None
        self.traffic_history = []
        self.attack_history = []
        self.last_attack_time = None
        self.last_attack_type = None
        self.attack_in_progress = False
        self.current_attack_severity = 0.0
        
        # Inicijaliziraj dataset loader za batch učenje
        self.dataset_loader = DDQNDataLoader()
        
        # Učitaj ili inicijaliziraj model
        self._init_model()
    
    def _init_model(self):
        """
        Inicijalizira DDQN model/agent.
        """
        try:
            # Inicijaliziraj DDQN agent
            self.agent = DDQNAgent(state_size=8, action_size=2, window_size=self.window_size)
            
            # Ako je putanja navedena, učitaj postojeći model
            if self.model_path:
                result = self.agent.load(self.model_path)
                if result:
                    print(f"DDQN detektor uspješno učitao model iz: {self.model_path}")
                else:
                    print(f"Nije moguće učitati model iz {self.model_path}, inicijaliziran novi model.")
            # Inače, provjeri postoji li zadani model
            elif DEFAULT_MODEL_PATH.exists():
                result = self.agent.load(str(DEFAULT_MODEL_PATH))
                if result:
                    print(f"DDQN detektor uspješno učitao zadani model.")
                else:
                    print("Nije moguće učitati zadani model, inicijaliziran novi model.")
            elif SIMPLIFIED_MODEL_PATH.exists():
                result = self.agent.load(str(SIMPLIFIED_MODEL_PATH))
                if result:
                    print(f"DDQN detektor uspješno učitao pojednostavljeni model.")
                else:
                    print("Nije moguće učitati pojednostavljeni model, inicijaliziran novi model.")
            else:
                print("Model nije pronađen, inicijaliziran novi model.")
        except Exception as e:
            print(f"Greška pri inicijalizaciji modela: {e}")
            print("Inicijaliziran novi model.")
    
    def preprocess_traffic_data(self, traffic_data):
        """
        Predobrađuje podatke o prometu za DDQN model.
        
        Args:
            traffic_data: Podaci o prometu
            
        Returns:
            Predobrađeni vektor značajki
        """
        if not traffic_data:
            # Ako nema podataka, vraćamo nulti vektor
            return [0.0] * 8
        
        # Izvlačenje potrebnih značajki
        try:
            # Osnovne značajke
            source_ips = [packet.get("src_ip", "unknown") for packet in traffic_data]
            destination_ips = [packet.get("dst_ip", "unknown") for packet in traffic_data]
            
            unique_src_ips = set(source_ips)
            unique_dst_ips = set(destination_ips)
            
            # Računanje značajki
            protocol_counts = {}
            syn_count = 0
            total_packet_size = 0
            
            for packet in traffic_data:
                protocol = packet.get("protocol", "unknown")
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
                
                # SYN paketi
                if packet.get("tcp_flags") == "S":
                    syn_count += 1
                
                # Veličina paketa
                packet_size = packet.get("packet_size", 0)
                total_packet_size += packet_size
            
            # Normalizacija značajki
            total_packets = len(traffic_data)
            
            # Shannon entropija izvorišnih IP adresa
            source_entropy = self._calculate_entropy(source_ips)
            
            # Shannon entropija odredišnih IP adresa
            destination_entropy = self._calculate_entropy(destination_ips)
            
            # Omjer SYN paketa
            syn_ratio = syn_count / total_packets if total_packets > 0 else 0
            
            # Normalizacija prometa (logaritamska)
            traffic_volume = min(1.0, total_packet_size / 1000000) if total_packet_size > 0 else 0
            
            # Stopa paketa (paketi po sekundi)
            time_span = 1.0  # Pretpostavljamo da su podaci za 1 sekundu
            packet_rate = min(1.0, total_packets / (500 * time_span)) if time_span > 0 else 0
            
            # Broj jedinstvenih izvorišnih i odredišnih IP adresa
            unique_src_count = min(1.0, len(unique_src_ips) / 100) if unique_src_ips else 0
            unique_dst_count = min(1.0, len(unique_dst_ips) / 50) if unique_dst_ips else 0
            
            # Mjera neravnoteže u distribuciji protokola
            protocol_imbalance = self._calculate_entropy(list(protocol_counts.keys()))
            
            # Stvaranje vektora značajki
            features = [
                source_entropy,
                destination_entropy,
                syn_ratio,
                traffic_volume,
                packet_rate,
                unique_src_count,
                unique_dst_count,
                protocol_imbalance
            ]
            
            return features
            
        except Exception as e:
            print(f"Greška pri predobradi podataka: {e}")
            return [0.0] * 8
    
    def _calculate_entropy(self, values):
        """
        Izračunava Shannon entropiju za listu vrijednosti.
        
        Args:
            values: Lista vrijednosti
            
        Returns:
            Normalizirana Shannon entropija [0, 1]
        """
        if not values:
            return 0.0
            
        # Računamo frekvencije
        freq_dict = {}
        for val in values:
            freq_dict[val] = freq_dict.get(val, 0) + 1
            
        # Izračun entropije
        entropy = 0.0
        n = len(values)
        for count in freq_dict.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)
            
        # Normalizacija na raspon [0, 1]
        max_entropy = math.log2(len(freq_dict)) if freq_dict else 0
        if max_entropy > 0:
            return entropy / max_entropy
        return 0.0
    
    def detect(self, traffic_data, learn=True):
        """
        Detektira potencijalne DDoS napade u mrežnom prometu.
        U online modu također uči iz novih podataka.
        
        Args:
            traffic_data: Podaci o trenutnom mrežnom prometu
            learn: Zastavica za učenje iz novih podataka
            
        Returns:
            dict: Rezultati detekcije
        """
        # Provjeri je li agent inicijaliziran
        if not self.agent:
            self._init_model()
            
        # Dodaj trenutne podatke u povijest
        self.traffic_history.append(traffic_data)
        
        # Ograniči povijest na zadnjih N paketa
        max_history = 1000
        if len(self.traffic_history) > max_history:
            self.traffic_history = self.traffic_history[-max_history:]
        
        # Predobradi podatke za posljednjih X paketa
        current_window = self.traffic_history[-self.window_size:] if len(self.traffic_history) >= self.window_size else self.traffic_history
        
        # Za svaki prozor računamo značajke
        features = []
        for i in range(min(self.window_size, len(current_window))):
            window_data = current_window[i]
            window_features = self.preprocess_traffic_data(window_data)
            features.append(window_features)
        
        # Dopuni značajke ako nemamo dovoljno povijesti
        while len(features) < self.window_size:
            features.insert(0, features[0] if features else [0.0] * 8)
        
        # Pretvori značajke u format za model
        if NUMPY_AVAILABLE:
            state = np.array(features).flatten()
        else:
            # Flatten lista bez NumPy
            state = [item for sublist in features for item in sublist]
        
        # Detekcija napada pomoću DDQN agenta
        action, q_values = self.agent.predict(state)
        
        # Provjera je li detektiran napad
        is_attack = action == 1
        
        # Računanje konfidencije
        confidence = q_values[action]
        
        # Ažuriranje povijesti napada
        now = datetime.now()
        
        # Ako je detektiran napad, ažuriraj povijest
        if is_attack:
            # Ako nije u tijeku napad, započni novi
            if not self.attack_in_progress:
                self.attack_in_progress = True
                self.last_attack_time = now
                
                # Procijeni tip napada na temelju značajki
                attack_type = self._estimate_attack_type(features[-1])
                self.last_attack_type = attack_type
                
                # Zabilježi napad
                self.attack_history.append({
                    "start_time": now.isoformat(),
                    "type": attack_type,
                    "confidence": confidence,
                    "severity": self._estimate_attack_severity(features[-1]),
                    "features": features[-1]
                })
            else:
                # Ako je napad već u tijeku, ažuriraj zadnji napad
                if self.attack_history:
                    self.attack_history[-1]["last_detection"] = now.isoformat()
                    self.attack_history[-1]["confidence"] = max(self.attack_history[-1].get("confidence", 0), confidence)
                    
                    # Ažuriraj težinu napada
                    severity = self._estimate_attack_severity(features[-1])
                    self.attack_history[-1]["severity"] = max(self.attack_history[-1].get("severity", 0), severity)
                    self.current_attack_severity = severity
                    
                # Ažuriraj vrijeme zadnje detekcije
                self.last_attack_time = now
        else:
            # Ako je napad završio
            if self.attack_in_progress:
                # Provjeri je li prošlo dovoljno vremena bez detekcije za završetak napada
                if self.last_attack_time and (now - self.last_attack_time).total_seconds() > 30:
                    self.attack_in_progress = False
                    
                    # Označi kraj napada u povijesti
                    if self.attack_history:
                        self.attack_history[-1]["end_time"] = now.isoformat()
                        
                        # Računanje trajanja napada
                        start_time = datetime.fromisoformat(self.attack_history[-1]["start_time"])
                        duration = (now - start_time).total_seconds()
                        self.attack_history[-1]["duration"] = duration
        
        # Ako je uključeno online učenje i imamo dovoljno povijesti, uči iz trenutnog stanja
        if self.online_learning and learn and len(self.traffic_history) >= self.window_size:
            # Izračunaj nagradu: +1 za točnu detekciju, -1 za pogrešnu
            # U stvarnom okruženju bi trebali imati stvarne oznake, ovdje koristimo heuristiku
            # za demonstraciju principa
            reward = 1.0 if is_attack else -0.1
            
            # U online učenju simuliramo sljedeće stanje kao trenutno stanje
            # U stvarnom okruženju bi trebali imati stvarno sljedeće stanje
            next_state = state
            
            # Memoriziraj iskustvo (state, action, reward, next_state, done)
            if hasattr(self.agent, 'memorize'):
                self.agent.memorize(state, action, reward, next_state, False)
                
                # Treniraj na batch-u ako imamo dovoljno podataka
                if hasattr(self.agent, 'replay') and len(getattr(self.agent, 'memory', [])) >= 32:
                    self.agent.replay(32)
        
        # Izgradnja rezultata
        result = {
            "timestamp": now.isoformat(),
            "is_attack": is_attack,
            "confidence": confidence,
            "action": action,
            "q_values": q_values,
            "attack_in_progress": self.attack_in_progress,
            "features": features[-1],
            "current_attack": {
                "type": self.last_attack_type,
                "start_time": self.last_attack_time.isoformat() if self.last_attack_time else None,
                "duration": (now - self.last_attack_time).total_seconds() if self.last_attack_time else 0,
                "severity": self.current_attack_severity
            } if self.attack_in_progress else None,
            "recent_attacks": self.attack_history[-5:] if self.attack_history else []
        }
        
        return result
    
    def _estimate_attack_type(self, features):
        """
        Procjenjuje tip napada na temelju značajki.
        
        Args:
            features: Vektor značajki
            
        Returns:
            str: Procijenjeni tip napada
        """
        # Raspakiranje značajki
        source_entropy, destination_entropy, syn_ratio, traffic_volume, packet_rate, unique_src_count, unique_dst_count, protocol_imbalance = features
        
        # Jednostavna heuristika za određivanje tipa napada
        if syn_ratio > 0.6:
            return "TCP SYN Flood"
        elif protocol_imbalance < 0.3 and packet_rate > 0.7:
            return "UDP Flood"
        elif destination_entropy < 0.2 and packet_rate > 0.6:
            return "ICMP Flood"
        elif traffic_volume > 0.7 and unique_src_count > 0.6:
            return "Distributed Flood"
        elif syn_ratio < 0.3 and traffic_volume > 0.5:
            return "HTTP Flood"
        elif packet_rate < 0.4 and traffic_volume < 0.4:
            return "Slowloris"
        else:
            return "Unknown Attack"
    
    def _estimate_attack_severity(self, features):
        """
        Procjenjuje težinu napada na temelju značajki.
        
        Args:
            features: Vektor značajki
            
        Returns:
            float: Procjena težine napada [0, 1]
        """
        # Raspakiranje značajki
        source_entropy, destination_entropy, syn_ratio, traffic_volume, packet_rate, unique_src_count, unique_dst_count, protocol_imbalance = features
        
        # Kombinacija značajki za procjenu težine
        severity = 0.0
        severity += traffic_volume * 0.4  # Volumen ima najveći utjecaj
        severity += packet_rate * 0.3     # Stopa paketa je također važna
        severity += syn_ratio * 0.15      # SYN omjer ima srednji utjecaj
        severity += source_entropy * 0.1  # Entropija izvora ima manji utjecaj
        severity += (1 - destination_entropy) * 0.05  # Niska entropija odredišta može ukazivati na ciljani napad
        
        return min(1.0, severity)
    
    def train_batch(self, num_episodes=100, batch_size=32):
        """
        Trenira model u batch modu koristeći prethodno generirane podatke.
        
        Args:
            num_episodes: Broj epizoda za trening
            batch_size: Veličina batch-a
            
        Returns:
            dict: Povijest treninga
        """
        # Provjeri je li agent inicijaliziran
        if not self.agent:
            self._init_model()
        
        # Provjeri ima li agent metodu za trening
        if hasattr(self.agent, 'train'):
            # Učitaj dataset ako nije već učitan
            if not self.dataset_loader.dataset:
                success = self.dataset_loader.load()
                if not success:
                    return {"error": "Učitavanje dataset-a nije uspjelo"}
            
            # Pokreni trening
            history = self.agent.train(self.dataset_loader, num_episodes=num_episodes, batch_size=batch_size)
            
            # Spremi model nakon treninga
            if hasattr(self.agent, 'save'):
                model_path = MODEL_DIR / f"ddqn_model_trained_{datetime.now().strftime('%Y%m%d_%H%M%S')}.h5"
                self.agent.save(str(model_path))
                print(f"Model spremljen nakon treninga: {model_path}")
            
            return {"status": "success", "history": history, "model_path": str(model_path) if 'model_path' in locals() else None}
        else:
            return {"error": "Agent nema metodu za trening"}
    
    def evaluate(self, test_data=None):
        """
        Evaluira detektor na testnim podacima.
        
        Args:
            test_data: Testni podaci ili None za korištenje dataset-a
            
        Returns:
            dict: Metrike evaluacije
        """
        # Provjeri je li agent inicijaliziran
        if not self.agent:
            self._init_model()
            
        if not hasattr(self.agent, 'evaluate'):
            return {"error": "Agent nema metodu za evaluaciju"}
        
        if test_data is None:
            # Koristi dataset loader za dohvat testnih podataka
            if not self.dataset_loader.dataset:
                success = self.dataset_loader.load()
                if not success:
                    return {"error": "Učitavanje dataset-a nije uspjelo"}
            
            X_test, y_test = self.dataset_loader.get_test_data() or self.dataset_loader.get_validation_data()
            
            if X_test is None or y_test is None:
                return {"error": "Testni podaci nisu dostupni"}
                
            # Evaluacija na testnim podacima
            metrics = self.agent.evaluate(X_test, y_test)
            return metrics
        else:
            # Evaluacija na dostavljenim testnim podacima
            processed_data = []
            labels = []
            
            for sample in test_data:
                features = self.preprocess_traffic_data(sample["data"])
                is_attack = sample.get("is_attack", False)
                
                processed_data.append(features)
                labels.append(1 if is_attack else 0)
            
            if NUMPY_AVAILABLE:
                processed_data = np.array(processed_data)
                labels = np.array(labels)
            
            return self.agent.evaluate(processed_data, labels)
    
    def reset(self):
        """
        Resetira stanje detektora.
        """
        self.traffic_history = []
        self.attack_history = []
        self.last_attack_time = None
        self.last_attack_type = None
        self.attack_in_progress = False
        self.current_attack_severity = 0.0
        print("Stanje detektora resetirano.")
    
    def get_attack_history(self, limit=10):
        """
        Vraća povijest detektiranih napada.
        
        Args:
            limit: Maksimalni broj napada za vraćanje
            
        Returns:
            list: Povijest napada
        """
        return self.attack_history[-limit:] if self.attack_history else []
    
    def save_model(self, model_path=None):
        """
        Sprema trenutno stanje modela.
        
        Args:
            model_path: Putanja za spremanje (ako nije navedena, koristi se zadana putanja)
            
        Returns:
            bool: True ako je spremanje uspjelo, inače False
        """
        if not self.agent or not hasattr(self.agent, 'save'):
            return False
            
        if not model_path:
            model_path = str(DEFAULT_MODEL_PATH)
            
        try:
            self.agent.save(model_path)
            print(f"Model uspješno spremljen u: {model_path}")
            return True
        except Exception as e:
            print(f"Greška pri spremanju modela: {e}")
            return False
    
    def recommend_action(self, detection_result):
        """
        Preporučuje akciju na temelju rezultata detekcije.
        
        Args:
            detection_result: Rezultat detekcije
            
        Returns:
            dict: Preporučena akcija
        """
        if not detection_result.get("is_attack", False) and not detection_result.get("attack_in_progress", False):
            return {
                "action": "monitor",
                "description": "Nastavite nadzirati promet.",
                "severity": "low"
            }
        
        # Ako je napad u tijeku
        if detection_result.get("attack_in_progress", False):
            current_attack = detection_result.get("current_attack", {})
            severity = current_attack.get("severity", 0.0)
            attack_type = current_attack.get("type", "Unknown")
            
            if severity > 0.8:
                return {
                    "action": "block",
                    "description": f"Blokirajte izvorni promet. Detektiran ozbiljan {attack_type} napad.",
                    "severity": "critical",
                    "target": "source",
                    "duration": 3600  # 1 sat
                }
            elif severity > 0.6:
                return {
                    "action": "throttle",
                    "description": f"Ograničite propusnost za sumnjive izvore. Detektiran {attack_type} napad srednjeg intenziteta.",
                    "severity": "high",
                    "target": "specific_sources",
                    "duration": 1800  # 30 minuta
                }
            elif severity > 0.4:
                return {
                    "action": "analyze",
                    "description": f"Dubinska analiza prometa. Detektiran {attack_type} napad niskog intenziteta.",
                    "severity": "medium",
                    "target": "traffic_patterns",
                    "duration": 900  # 15 minuta
                }
            else:
                return {
                    "action": "monitor",
                    "description": f"Nastavite nadzirati promet. Moguć {attack_type} napad vrlo niskog intenziteta.",
                    "severity": "low",
                    "duration": 300  # 5 minuta
                }
        
        # Ako je detektiran novi napad
        confidence = detection_result.get("confidence", 0.0)
        if confidence > 0.8:
            return {
                "action": "throttle",
                "description": "Ograničite propusnost za sumnjive izvore.",
                "severity": "high",
                "duration": 1800  # 30 minuta
            }
        elif confidence > 0.6:
            return {
                "action": "analyze",
                "description": "Dubinska analiza prometa.",
                "severity": "medium",
                "duration": 900  # 15 minuta
            }
        else:
            return {
                "action": "monitor",
                "description": "Nastavite nadzirati promet uz povećanu pozornost.",
                "severity": "low",
                "duration": 300  # 5 minuta
            }


# Globalna instanca detektora
_detector_instance = None

def get_detector(online_learning=True):
    """
    Vraća globalnu instancu detektora.
    
    Args:
        online_learning: Zastavica za online učenje
        
    Returns:
        DDQNDetector: Instanca detektora
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = DDQNDetector(online_learning=online_learning)
    return _detector_instance