#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Detektor DDoS napada
Implementacija detektora DDoS napada koji koristi DDQN model
"""

import os
import sys
import json
import time
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
MODEL_DIR = Path(__file__).parent.parent.parent / "ml" / "models"
MODEL_DIR.mkdir(exist_ok=True)
DEFAULT_MODEL_PATH = MODEL_DIR / "ddqn_best_model.h5"
SIMPLIFIED_MODEL_PATH = MODEL_DIR / "ddqn_best_model_simplified.json"

class DDoSDetector:
    """
    Detektor DDoS napada koji koristi DDQN model za analizu mrežnog prometa
    i detekciju potencijalnih napada u stvarnom vremenu.
    """
    
    def __init__(self, model_path=None, window_size=5):
        """
        Inicijalizacija detektora.
        
        Args:
            model_path: Putanja do modela. Ako nije navedena, koristi se zadani model.
            window_size: Veličina vremenskog prozora za analizu
        """
        self.window_size = window_size
        self.model_path = model_path
        self.ddqn_agent = None
        self.traffic_history = []
        self.attack_history = []
        self.last_attack_time = None
        self.last_attack_type = None
        self.attack_in_progress = False
        self.current_attack_severity = 0.0
        
        # Inicijaliziraj dataset loader
        self.dataset_loader = DDQNDataLoader()
        
        # Učitaj model
        self._load_model()
    
    def _load_model(self):
        """
        Učitava DDQN model.
        """
        try:
            # Ako putanja nije navedena, koristi zadani model
            model_path = self.model_path
            if not model_path:
                model_path = str(DEFAULT_MODEL_PATH) if DEFAULT_MODEL_PATH.exists() else str(SIMPLIFIED_MODEL_PATH)
            
            # Inicijaliziraj DDQN agent
            self.ddqn_agent = DDQNAgent(state_size=8, action_size=2, window_size=self.window_size)
            
            # Učitaj model
            result = self.ddqn_agent.load(model_path)
            
            if result:
                print(f"DDoS detektor uspješno učitao model iz: {model_path}")
            else:
                print(f"Nije moguće učitati model iz {model_path}, inicijaliziran novi model.")
                
        except Exception as e:
            print(f"Greška pri učitavanju modela: {e}")
            print("Inicijaliziran novi model.")
            
            # Inicijaliziraj novi model ako učitavanje nije uspjelo
            self.ddqn_agent = DDQNAgent(state_size=8, action_size=2, window_size=self.window_size)
    
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
                entropy -= p * (math.log2(p) if 'math' in sys.modules else math_log2_fallback(p))
            
        # Normalizacija na raspon [0, 1]
        max_entropy = (math.log2(len(freq_dict)) if 'math' in sys.modules else math_log2_fallback(len(freq_dict))) if freq_dict else 0
        if max_entropy > 0:
            return entropy / max_entropy
        return 0.0
    
    def detect(self, traffic_data):
        """
        Detektira potencijalne DDoS napade u mrežnom prometu.
        
        Args:
            traffic_data: Podaci o trenutnom mrežnom prometu
            
        Returns:
            dict: Rezultati detekcije
        """
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
        
        # Detekcija napada pomoću DDQN modela
        if self.ddqn_agent:
            action, q_values = self.ddqn_agent.predict(state)
            
            # Računanje konfidencije
            confidence = q_values[action]
            
            # Provjera je li detektiran napad
            is_attack = action == 1
            
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
                        "severity": self._estimate_attack_severity(features[-1])
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
            
            # Izgradnja rezultata
            result = {
                "timestamp": now.isoformat(),
                "is_attack": is_attack,
                "confidence": confidence,
                "action": action,
                "q_values": q_values,
                "attack_in_progress": self.attack_in_progress,
                "current_attack": {
                    "type": self.last_attack_type,
                    "start_time": self.last_attack_time.isoformat() if self.last_attack_time else None,
                    "duration": (now - self.last_attack_time).total_seconds() if self.last_attack_time else 0,
                    "severity": self.current_attack_severity
                } if self.attack_in_progress else None,
                "recent_attacks": self.attack_history[-5:] if self.attack_history else []
            }
            
            return result
        else:
            # Ako model nije dostupan, vrati jednostavan rezultat
            return {
                "timestamp": datetime.now().isoformat(),
                "is_attack": False,
                "confidence": 0.0,
                "message": "Model nije dostupan za detekciju"
            }
    
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
                    "description": f"Blokirajte izvori promet. Detektiran ozbiljan {attack_type} napad.",
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
    
    def get_attack_history(self, limit=10):
        """
        Vraća povijest detektiranih napada.
        
        Args:
            limit: Maksimalni broj napada za vraćanje
            
        Returns:
            list: Povijest napada
        """
        return self.attack_history[-limit:] if self.attack_history else []
    
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
    
    def evaluate(self, test_data=None):
        """
        Evaluira detektor na testnim podacima.
        
        Args:
            test_data: Testni podaci ili None za korištenje dataset-a
            
        Returns:
            dict: Metrike evaluacije
        """
        if not self.ddqn_agent:
            return {"error": "Model nije dostupan za evaluaciju"}
        
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
            metrics = self.ddqn_agent.evaluate(X_test, y_test)
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
            
            return self.ddqn_agent.evaluate(processed_data, labels)


# Fallback funkcija za logaritam ako math modul nije dostupan
def math_log2_fallback(x):
    """
    Fallback implementacija logaritma (baza 2) ako math modul nije dostupan.
    
    Args:
        x: Vrijednost za logaritmiranje
        
    Returns:
        float: Logaritam baze 2
    """
    import math
    return math.log2(x)


# Globalna instanca detektora
_detector_instance = None

def get_detector():
    """
    Vraća globalnu instancu detektora.
    
    Returns:
        DDoSDetector: Instanca detektora
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = DDoSDetector()
    return _detector_instance