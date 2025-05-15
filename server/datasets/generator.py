#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Dataset Generator
Implementacija generiranja podataka prema metodologiji
"""

import os
import json
import random
import numpy as np
from datetime import datetime, timedelta
import math
from pathlib import Path

# Provjerimo je li NumPy dostupan
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: NumPy not available, using basic Python lists instead")

# Provjerimo je li Scapy dostupan za generiranje paketa
try:
    from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available, using simplified packet modeling")

# Provjerimo je li NetworkX dostupan za mrežnu topologiju
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    print("Warning: NetworkX not available, using simplified network topology")

# Struktura direktorija za pohranu podataka
DATASET_ROOT = Path(__file__).parent
NETWORK_DATA_DIR = DATASET_ROOT / "network"
ATTACK_DATA_DIR = DATASET_ROOT / "attack"
TRAINING_DATA_DIR = DATASET_ROOT / "training"

# Osigurajmo da direktoriji postoje
for dir_path in [NETWORK_DATA_DIR, ATTACK_DATA_DIR, TRAINING_DATA_DIR]:
    dir_path.mkdir(exist_ok=True)

class DatasetGenerator:
    """
    Generator podataka za trening i evaluaciju DDQN modela
    prema definiranoj metodologiji.
    """
    
    def __init__(self):
        self.protocol_distribution = {
            "HTTP": 0.40,    # 40% HTTP prometa
            "HTTPS": 0.30,   # 30% HTTPS prometa
            "DNS": 0.15,     # 15% DNS prometa
            "FTP": 0.10,     # 10% FTP prometa
            "VoIP": 0.05     # 5% VoIP prometa
        }
        
        # Parametri distribucije veličine paketa po protokolima
        self.packet_size_distributions = {
            "HTTP": {"type": "lognormal", "mu": 7.31, "sigma": 0.5, "min": 500, "max": 5000},
            "HTTPS": {"type": "lognormal", "mu": 7.82, "sigma": 0.6, "min": 800, "max": 8000},
            "DNS": {"type": "normal", "mu": 150, "sigma": 50, "min": 50, "max": 300},
            "FTP": {"type": "exponential", "lambda": 0.00005, "min": 1000, "max": 50000},
            "VoIP": {"type": "normal", "mu": 200, "sigma": 100, "min": 100, "max": 1000}
        }
        
        # Definicije napada
        self.attack_types = {
            "TCP_SYN_FLOOD": {
                "protocol": "TCP",
                "packet_rate_range": {
                    "low": (100, 1000),     # Nizak intenzitet: 100-1000 paketa/s
                    "medium": (1000, 5000), # Srednji intenzitet: 1000-5000 paketa/s
                    "high": (5000, 10000)   # Visok intenzitet: 5000-10000 paketa/s
                },
                "characteristics": {
                    "syn_flag": True,
                    "ack_flag": False,
                    "packet_size": 60,      # Tipična veličina SYN paketa
                    "random_source_ip": True
                }
            },
            "UDP_FLOOD": {
                "protocol": "UDP",
                "packet_rate_range": {
                    "low": (100, 1000),
                    "medium": (1000, 5000),
                    "high": (5000, 10000)
                },
                "characteristics": {
                    "packet_size_range": (50, 1000),  # UDP paketi različitih veličina
                    "random_source_ip": True,
                    "random_dest_port": True
                }
            },
            "ICMP_FLOOD": {
                "protocol": "ICMP",
                "packet_rate_range": {
                    "low": (100, 1000),
                    "medium": (1000, 5000),
                    "high": (5000, 10000)
                },
                "characteristics": {
                    "packet_size": 84,  # Tipična veličina ICMP Echo paketa
                    "random_source_ip": True
                }
            }
        }
        
        # Težine značajki za DDQN model
        self.feature_weights = np.array([
            0.18,  # source_entropy
            0.12,  # destination_entropy
            0.25,  # syn_ratio
            0.15,  # traffic_volume
            0.20,  # packet_rate
            0.05,  # unique_src_ips_count
            0.02,  # unique_dst_ips_count
            0.03   # protocol_imbalance
        ])
        
    def generate_packet_size(self, protocol):
        """
        Generira veličinu paketa prema odgovarajućoj distribuciji
        za određeni protokol.
        """
        dist_params = self.packet_size_distributions.get(protocol)
        if not dist_params:
            return 500  # Zadana veličina ako protokol nije definiran
            
        dist_type = dist_params["type"]
        
        if dist_type == "lognormal":
            if NUMPY_AVAILABLE:
                size = int(np.random.lognormal(dist_params["mu"], dist_params["sigma"]))
            else:
                # Aproksimacija lognormalne distribucije bez NumPy
                mu, sigma = dist_params["mu"], dist_params["sigma"]
                normal = random.gauss(mu, sigma)
                size = int(math.exp(normal))
                
        elif dist_type == "normal":
            if NUMPY_AVAILABLE:
                size = int(np.random.normal(dist_params["mu"], dist_params["sigma"]))
            else:
                size = int(random.gauss(dist_params["mu"], dist_params["sigma"]))
                
        elif dist_type == "exponential":
            if NUMPY_AVAILABLE:
                size = int(np.random.exponential(1/dist_params["lambda"]))
            else:
                size = int(random.expovariate(dist_params["lambda"]))
        else:
            size = 500  # Zadani povrat
            
        # Ograničenje prema min/max
        return max(dist_params["min"], min(size, dist_params["max"]))
        
    def generate_ip_address(self, internal=True):
        """
        Generira IP adresu - internu ili vanjsku.
        """
        if internal:
            # Interne IP adrese u privatnim rasponima
            prefix = random.choice(["10", "172", "192.168"])
            if prefix == "10":
                return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            elif prefix == "172":
                return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:  # 192.168
                return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            # Vanjske IP adrese (izbjegavamo privatne i rezervirane raspone)
            first_octet = random.choice([i for i in range(1, 223) if i not in [10, 127, 169, 172, 192, 198, 203]])
            return f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def calculate_shannon_entropy(self, values):
        """
        Izračun Shannon entropije za listu vrijednosti.
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
            entropy -= p * math.log2(p)
            
        # Normalizacija na raspon [0, 1]
        max_entropy = math.log2(len(freq_dict)) if freq_dict else 0
        if max_entropy > 0:
            return entropy / max_entropy
        return 0.0
        
    def generate_normal_traffic(self, duration_seconds=60, packet_rate=850):
        """
        Generira normalni mrežni promet prema zadanoj distribuciji protokola.
        
        Args:
            duration_seconds: Trajanje generiranja u sekundama
            packet_rate: Prosječna stopa paketa po sekundi
            
        Returns:
            List of packet data dictionaries
        """
        packets = []
        
        # Generiraj listu uređaja
        num_clients = random.randint(10, 30)
        num_servers = random.randint(5, 15)
        
        clients = [self.generate_ip_address(internal=True) for _ in range(num_clients)]
        servers = [self.generate_ip_address(internal=False) for _ in range(num_servers)]
        
        # Generiraj pakete za zadano razdoblje
        for second in range(duration_seconds):
            # Broj paketa u ovoj sekundi (s malim odstupanjem za realizam)
            current_packet_rate = int(random.gauss(packet_rate, packet_rate * 0.1))
            current_packet_rate = max(10, current_packet_rate)  # Minimalno 10 paketa/s
            
            for _ in range(current_packet_rate):
                # Odabir protokola prema distribuciji
                protocol = random.choices(
                    list(self.protocol_distribution.keys()), 
                    weights=list(self.protocol_distribution.values())
                )[0]
                
                # Generiranje izvorišne i odredišne IP adrese
                src_ip = random.choice(clients)
                dst_ip = random.choice(servers)
                
                # Generiranje veličine paketa
                packet_size = self.generate_packet_size(protocol)
                
                # Generiranje porta ovisno o protokolu
                if protocol == "HTTP":
                    dst_port = 80
                    src_port = random.randint(1024, 65535)
                elif protocol == "HTTPS":
                    dst_port = 443
                    src_port = random.randint(1024, 65535)
                elif protocol == "DNS":
                    dst_port = 53
                    src_port = random.randint(1024, 65535)
                elif protocol == "FTP":
                    dst_port = random.choice([20, 21])
                    src_port = random.randint(1024, 65535)
                elif protocol == "VoIP":
                    dst_port = random.choice([5060, 5061])
                    src_port = random.randint(1024, 65535)
                else:
                    dst_port = random.randint(1, 1023)
                    src_port = random.randint(1024, 65535)
                
                # Generiranje TCP zastavica (flags)
                if protocol in ["HTTP", "HTTPS", "FTP"]:
                    # Većina prometa ima zastavice ACK ili PSH-ACK jer su to uspostavljene veze
                    tcp_flags = random.choices(
                        ["S", "A", "PA", "FA", "R", "SA"],  # SYN, ACK, PSH-ACK, FIN-ACK, RST, SYN-ACK
                        weights=[0.05, 0.45, 0.40, 0.05, 0.02, 0.03]
                    )[0]
                else:
                    tcp_flags = ""
                
                # Stvaranje zapisa paketa
                timestamp = datetime.now() + timedelta(seconds=second)
                packet = {
                    "timestamp": timestamp.isoformat(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "tcp_flags": tcp_flags,
                    "packet_size": packet_size,
                    "is_attack": False
                }
                
                packets.append(packet)
        
        return packets
    
    def generate_attack_traffic(self, attack_type, intensity="medium", duration_seconds=60, 
                              target_ips=None, num_src_ips=None):
        """
        Generira promet napada prema zadanom tipu i intenzitetu.
        
        Args:
            attack_type: Tip napada (npr. "TCP_SYN_FLOOD")
            intensity: Intenzitet napada ("low", "medium", "high")
            duration_seconds: Trajanje napada u sekundama
            target_ips: Lista ciljanih IP adresa
            num_src_ips: Broj izvorišnih IP adresa za napad
            
        Returns:
            List of packet data dictionaries
        """
        packets = []
        
        # Provjera je li tip napada podržan
        if attack_type not in self.attack_types:
            raise ValueError(f"Nepodržani tip napada: {attack_type}")
        
        attack_params = self.attack_types[attack_type]
        
        # Odredi stopu paketa prema intenzitetu
        rate_range = attack_params["packet_rate_range"][intensity.lower()]
        packet_rate = random.randint(rate_range[0], rate_range[1])
        
        # Postavi ciljane IP adrese
        if not target_ips:
            num_targets = random.randint(1, 3)
            target_ips = [self.generate_ip_address(internal=True) for _ in range(num_targets)]
        
        # Postavi izvorišne IP adrese za napad
        if not num_src_ips:
            # Broj izvorišnih IP adresa ovisi o intenzitetu
            intensity_map = {"low": (5, 10), "medium": (10, 30), "high": (30, 50)}
            src_range = intensity_map[intensity.lower()]
            num_src_ips = random.randint(src_range[0], src_range[1])
        
        # Generiraj izvorišne IP adrese
        src_ips = [self.generate_ip_address(internal=False) for _ in range(num_src_ips)]
        
        protocol = attack_params["protocol"]
        
        # Generiraj pakete za zadano razdoblje
        for second in range(duration_seconds):
            # Trenutna stopa paketa (s manjim varijacijama)
            current_packet_rate = int(random.gauss(packet_rate, packet_rate * 0.05))
            current_packet_rate = max(10, current_packet_rate)
            
            for _ in range(current_packet_rate):
                # Odabir izvora i cilja
                src_ip = random.choice(src_ips)
                dst_ip = random.choice(target_ips)
                
                # Postavljanje portova i zastavica specifično za tip napada
                if protocol == "TCP":
                    src_port = random.randint(1024, 65535)
                    dst_port = random.choice([80, 443, 22, 21, 25])  # Uobičajeni portovi za TCP napade
                    
                    if attack_type == "TCP_SYN_FLOOD":
                        tcp_flags = "S"  # Samo SYN zastavica
                        packet_size = 60  # Tipična veličina SYN paketa
                    else:
                        tcp_flags = random.choice(["S", "A", "SA", "PA", "FA", "R"])
                        packet_size = random.randint(40, 1000)
                        
                elif protocol == "UDP":
                    src_port = random.randint(1024, 65535)
                    if attack_params["characteristics"].get("random_dest_port", False):
                        dst_port = random.randint(1, 65535)
                    else:
                        dst_port = random.choice([53, 123, 161, 1900])  # Uobičajeni UDP portovi
                    
                    packet_size = random.randint(
                        attack_params["characteristics"].get("packet_size_range", [50, 1000])[0],
                        attack_params["characteristics"].get("packet_size_range", [50, 1000])[1]
                    )
                    tcp_flags = ""
                    
                elif protocol == "ICMP":
                    src_port = 0
                    dst_port = 0
                    packet_size = attack_params["characteristics"].get("packet_size", 84)
                    tcp_flags = ""
                    
                else:
                    src_port = random.randint(1024, 65535)
                    dst_port = random.randint(1, 1023)
                    packet_size = random.randint(50, 1500)
                    tcp_flags = ""
                
                # Stvaranje zapisa paketa
                timestamp = datetime.now() + timedelta(seconds=second)
                packet = {
                    "timestamp": timestamp.isoformat(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "tcp_flags": tcp_flags,
                    "packet_size": packet_size,
                    "is_attack": True,
                    "attack_type": attack_type
                }
                
                packets.append(packet)
        
        return packets
    
    def generate_mixed_traffic(self, duration_seconds=600, attack_duration=120, 
                             attack_type="TCP_SYN_FLOOD", attack_intensity="medium",
                             attack_start_time=None):
        """
        Generira mješoviti promet s normalnim i napadačkim prometom.
        
        Args:
            duration_seconds: Ukupno trajanje generiranja u sekundama
            attack_duration: Trajanje napada u sekundama
            attack_type: Tip napada
            attack_intensity: Intenzitet napada
            attack_start_time: Vrijeme početka napada (ako None, nasumično se određuje)
            
        Returns:
            Dict with traffic data and metadata
        """
        # Ako nije zadan početak napada, nasumično ga odredimo
        if attack_start_time is None:
            # Napad počinje nakon prvih 10% vremena i završava barem 10% prije kraja
            min_start = int(duration_seconds * 0.1)
            max_start = int(duration_seconds * 0.9) - attack_duration
            
            if max_start <= min_start:
                attack_start_time = min_start
            else:
                attack_start_time = random.randint(min_start, max_start)
        
        # Generiraj normalni promet za cijelo razdoblje
        normal_packets = self.generate_normal_traffic(duration_seconds=duration_seconds)
        
        # Generiraj napadački promet samo za razdoblje napada
        target_ips = list(set([p["dst_ip"] for p in normal_packets[:1000] if random.random() < 0.1]))
        if not target_ips:
            target_ips = [self.generate_ip_address(internal=True)]
            
        attack_packets = self.generate_attack_traffic(
            attack_type=attack_type,
            intensity=attack_intensity,
            duration_seconds=attack_duration,
            target_ips=target_ips[:3]  # Ograničimo broj ciljeva na najviše 3
        )
        
        # Postavi vremenske oznake za napadačke pakete
        attack_start_dt = datetime.now() + timedelta(seconds=attack_start_time)
        for i, packet in enumerate(attack_packets):
            # Računamo relativno vrijeme unutar napada
            relative_time = i % attack_duration  # Ovo pretpostavlja da je približno 1 paket po sekundi
            packet_time = attack_start_dt + timedelta(seconds=relative_time)
            packet["timestamp"] = packet_time.isoformat()
        
        # Ukloni normalne pakete koji su u koliziji s napadačkim paketima
        # (jednostavnosti radi, uklonimo sve normalne pakete tijekom razdoblja napada)
        attack_end_time = attack_start_time + attack_duration
        filtered_normal_packets = []
        
        for packet in normal_packets:
            packet_time = datetime.fromisoformat(packet["timestamp"])
            packet_second = (packet_time - datetime.now()).total_seconds()
            
            # Zadrži paket ako nije u razdoblju napada ili s malom vjerojatnošću čak i ako jest
            if packet_second < attack_start_time or packet_second >= attack_end_time or random.random() < 0.2:
                filtered_normal_packets.append(packet)
        
        # Kombiniranje normalnog i napadačkog prometa
        all_packets = filtered_normal_packets + attack_packets
        
        # Sortiranje paketa po vremenu
        all_packets.sort(key=lambda x: x["timestamp"])
        
        # Stvaranje metapodataka
        metadata = {
            "total_duration": duration_seconds,
            "attack": {
                "type": attack_type,
                "intensity": attack_intensity,
                "start_time": attack_start_time,
                "duration": attack_duration,
                "target_ips": target_ips[:3]
            },
            "normal_packet_count": len(filtered_normal_packets),
            "attack_packet_count": len(attack_packets),
            "total_packet_count": len(all_packets)
        }
        
        return {"packets": all_packets, "metadata": metadata}
    
    def extract_features(self, packets, window_size=1):
        """
        Izvlači značajke iz paketa prema vremenskim prozorima.
        
        Args:
            packets: Lista paketa
            window_size: Veličina vremenskog prozora u sekundama
            
        Returns:
            Lista vektora značajki za svaki vremenski prozor
        """
        if not packets:
            return []
            
        # Pretvaranje svih timestamp-ova u datetime objekte
        for packet in packets:
            if isinstance(packet["timestamp"], str):
                packet["timestamp"] = datetime.fromisoformat(packet["timestamp"])
        
        # Određivanje početnog i krajnjeg vremena
        start_time = min(packet["timestamp"] for packet in packets)
        end_time = max(packet["timestamp"] for packet in packets)
        
        # Izračun broja vremenskih prozora
        total_seconds = int((end_time - start_time).total_seconds())
        num_windows = (total_seconds // window_size) + 1
        
        features_list = []
        
        for window_idx in range(num_windows):
            window_start = start_time + timedelta(seconds=window_idx * window_size)
            window_end = window_start + timedelta(seconds=window_size)
            
            # Filtriranje paketa u trenutnom vremenskom prozoru
            window_packets = [p for p in packets if window_start <= p["timestamp"] < window_end]
            
            if not window_packets:
                # Ako nema paketa u prozoru, koristimo nulti vektor
                features = np.zeros(8)
                features_list.append(features)
                continue
            
            # Izvlačenje značajki
            src_ips = [p["src_ip"] for p in window_packets]
            dst_ips = [p["dst_ip"] for p in window_packets]
            
            unique_src_ips = set(src_ips)
            unique_dst_ips = set(dst_ips)
            
            # 1. Shannon entropija izvorišnih IP adresa
            source_entropy = self.calculate_shannon_entropy(src_ips)
            
            # 2. Shannon entropija odredišnih IP adresa
            destination_entropy = self.calculate_shannon_entropy(dst_ips)
            
            # 3. Omjer SYN paketa
            syn_packets = [p for p in window_packets if p.get("tcp_flags") == "S"]
            syn_ratio = len(syn_packets) / len(window_packets) if window_packets else 0
            
            # 4. Ukupni volumen prometa (bajtova)
            traffic_volume = sum(p.get("packet_size", 0) for p in window_packets)
            
            # 5. Stopa paketa
            packet_rate = len(window_packets) / window_size
            
            # 6-7. Broj jedinstvenih izvorišnih i odredišnih IP adresa
            unique_src_count = len(unique_src_ips)
            unique_dst_count = len(unique_dst_ips)
            
            # 8. Mjera neravnoteže u distribuciji protokola
            protocols = [p.get("protocol", "UNKNOWN") for p in window_packets]
            protocol_imbalance = self.calculate_shannon_entropy(protocols)
            
            # Stvaranje vektora značajki
            features = np.array([
                source_entropy,
                destination_entropy,
                syn_ratio,
                traffic_volume,
                packet_rate,
                unique_src_count,
                unique_dst_count,
                protocol_imbalance
            ])
            
            # Normalizacija značajki (djelomična)
            # Volumetrijske značajke normaliziramo posebno
            # Entropije su već u rasponu [0,1]
            
            # Normalizacija traffic_volume (logaritamski zbog velikog raspona)
            if features[3] > 0:
                features[3] = math.log(features[3]) / 20  # Pretpostavljamo da je max oko 10^20
                features[3] = min(1.0, features[3])
            
            # Normalizacija packet_rate (logaritamski)
            if features[4] > 0:
                features[4] = math.log(features[4]) / 10  # Pretpostavljamo da je max oko 10^10
                features[4] = min(1.0, features[4])
            
            # Normalizacija broja jedinstvenih IP adresa
            if features[5] > 0:
                features[5] = min(1.0, features[5] / 100)  # Skaliranje do 100 jedinstvenih izvora
            
            if features[6] > 0:
                features[6] = min(1.0, features[6] / 50)   # Skaliranje do 50 jedinstvenih odredišta
            
            features_list.append(features)
        
        return features_list
    
    def apply_feature_weights(self, features_list):
        """
        Primjenjuje težine značajki za poboljšanje performansi učenja.
        
        Args:
            features_list: Lista vektora značajki
            
        Returns:
            Lista vektora značajki s primijenjenim težinama
        """
        if not NUMPY_AVAILABLE:
            # Ako NumPy nije dostupan, vraćamo originalne značajke
            return features_list
            
        weighted_features = []
        
        for features in features_list:
            # Skaliranje značajki prema važnosti
            weighted = features * self.feature_weights
            weighted_features.append(weighted)
            
        return weighted_features
    
    def save_dataset(self, dataset, file_path):
        """
        Sprema dataset u JSON format.
        
        Args:
            dataset: Dataset za spremanje
            file_path: Putanja za spremanje
        """
        # Konverzija numpy tipova u standardne Python tipove
        def convert_numpy_types(obj):
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, (np.int_, np.intc, np.intp, np.int8, np.int16, np.int32, np.int64, 
                              np.uint8, np.uint16, np.uint32, np.uint64)):
                return int(obj)
            elif isinstance(obj, (np.float_, np.float16, np.float32, np.float64)):
                return float(obj)
            elif isinstance(obj, (np.complex_, np.complex64, np.complex128)):
                return complex(obj)
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, (list, tuple)):
                return [convert_numpy_types(item) for item in obj]
            elif isinstance(obj, dict):
                return {key: convert_numpy_types(value) for key, value in obj.items()}
            else:
                return obj
        
        # Konverzija dataset-a
        clean_dataset = convert_numpy_types(dataset)
        
        # Spremanje u JSON
        with open(file_path, 'w') as f:
            json.dump(clean_dataset, f, indent=2)
    
    def load_dataset(self, file_path):
        """
        Učitava dataset iz JSON formata.
        
        Args:
            file_path: Putanja za učitavanje
            
        Returns:
            Učitani dataset
        """
        try:
            with open(file_path, 'r') as f:
                dataset = json.load(f)
                
            # Konverzija timestamp-ova iz string-a u datetime
            if "packets" in dataset:
                for packet in dataset["packets"]:
                    if "timestamp" in packet and isinstance(packet["timestamp"], str):
                        try:
                            packet["timestamp"] = datetime.fromisoformat(packet["timestamp"])
                        except ValueError:
                            # Ako konverzija ne uspije, ostavljamo string
                            pass
                
            return dataset
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Greška pri učitavanju dataset-a: {e}")
            return None
    
    def generate_training_dataset(self, num_episodes=1000, episode_duration=200, 
                                attack_probability=0.5):
        """
        Generira dataset za trening DDQN modela.
        
        Args:
            num_episodes: Broj epizoda za generiranje
            episode_duration: Trajanje svake epizode u sekundama
            attack_probability: Vjerojatnost da epizoda sadrži napad
            
        Returns:
            Path to saved dataset
        """
        all_episodes = []
        
        attack_types = list(self.attack_types.keys())
        intensity_levels = ["low", "medium", "high"]
        
        for episode_idx in range(num_episodes):
            # Odluka o uključivanju napada
            has_attack = random.random() < attack_probability
            
            if has_attack:
                attack_type = random.choice(attack_types)
                attack_intensity = random.choice(intensity_levels)
                
                # Nasumično trajanje napada (između 10% i 50% ukupnog trajanja epizode)
                attack_duration = random.randint(
                    int(episode_duration * 0.1),
                    int(episode_duration * 0.5)
                )
                
                # Generiraj mješoviti promet
                episode_data = self.generate_mixed_traffic(
                    duration_seconds=episode_duration,
                    attack_duration=attack_duration,
                    attack_type=attack_type,
                    attack_intensity=attack_intensity
                )
            else:
                # Generiraj samo normalni promet
                normal_packets = self.generate_normal_traffic(duration_seconds=episode_duration)
                episode_data = {
                    "packets": normal_packets,
                    "metadata": {
                        "total_duration": episode_duration,
                        "attack": None,
                        "normal_packet_count": len(normal_packets),
                        "attack_packet_count": 0,
                        "total_packet_count": len(normal_packets)
                    }
                }
            
            # Izvlačenje značajki
            features = self.extract_features(episode_data["packets"])
            weighted_features = self.apply_feature_weights(features)
            
            # Označavanje vremenskih prozora s napadom
            if has_attack:
                attack_start = episode_data["metadata"]["attack"]["start_time"]
                attack_end = attack_start + episode_data["metadata"]["attack"]["duration"]
                
                attack_labels = []
                for i in range(len(features)):
                    # Pretvori indeks prozora u stvarno vrijeme
                    window_time = i  # Pretpostavljamo da su prozori po 1 sekundu
                    
                    # Provjeri je li prozor tijekom napada
                    is_attack = attack_start <= window_time < attack_end
                    attack_labels.append(is_attack)
            else:
                attack_labels = [False] * len(features)
            
            # Dodavanje podataka epizode
            episode_dict = {
                "episode_id": episode_idx,
                "features": weighted_features,
                "attack_labels": attack_labels,
                "metadata": episode_data["metadata"]
            }
            
            all_episodes.append(episode_dict)
            
            # Prikaz napretka
            if (episode_idx + 1) % 10 == 0:
                print(f"Generirano {episode_idx + 1}/{num_episodes} epizoda")
        
        # Podjela na skupove za trening, validaciju i testiranje
        random.shuffle(all_episodes)
        train_size = int(0.7 * num_episodes)
        val_size = int(0.15 * num_episodes)
        
        train_episodes = all_episodes[:train_size]
        val_episodes = all_episodes[train_size:train_size+val_size]
        test_episodes = all_episodes[train_size+val_size:]
        
        # Stvaranje finalnog dataset-a
        dataset = {
            "train": train_episodes,
            "validation": val_episodes,
            "test": test_episodes,
            "metadata": {
                "num_episodes": num_episodes,
                "episode_duration": episode_duration,
                "attack_probability": attack_probability,
                "creation_date": datetime.now().isoformat(),
                "feature_names": [
                    "source_entropy",
                    "destination_entropy",
                    "syn_ratio",
                    "traffic_volume",
                    "packet_rate",
                    "unique_src_ips_count",
                    "unique_dst_ips_count",
                    "protocol_imbalance"
                ],
                "feature_weights": self.feature_weights.tolist()
            }
        }
        
        # Spremanje dataset-a
        dataset_path = TRAINING_DATA_DIR / f"ddqn_dataset_{num_episodes}ep_{datetime.now().strftime('%Y%m%d')}.json"
        self.save_dataset(dataset, dataset_path)
        
        print(f"Dataset generiran i spremljen na: {dataset_path}")
        return str(dataset_path)

    def generate_sample_dataset(self, save=True):
        """
        Generira mali uzorak dataset-a za testiranje i dokumentaciju.
        
        Args:
            save: Određuje hoće li se dataset spremiti
            
        Returns:
            Sample dataset or path to saved dataset
        """
        # Generiraj mali broj epizoda
        num_episodes = 5
        episode_duration = 30  # sekundi
        
        # Generiraj različite vrste napada
        attack_types = list(self.attack_types.keys())
        sample_episodes = []
        
        for i, attack_type in enumerate(attack_types[:3]):  # Koristimo prva 3 tipa napada
            # Generiraj epizodu s napadom
            episode_data = self.generate_mixed_traffic(
                duration_seconds=episode_duration,
                attack_duration=10,  # 10 sekundi napada
                attack_type=attack_type,
                attack_intensity="medium",
                attack_start_time=10  # Napad počinje nakon 10 sekundi
            )
            
            # Izvlačenje značajki
            features = self.extract_features(episode_data["packets"])
            weighted_features = self.apply_feature_weights(features)
            
            # Označavanje vremenskih prozora s napadom
            attack_start = episode_data["metadata"]["attack"]["start_time"]
            attack_end = attack_start + episode_data["metadata"]["attack"]["duration"]
            
            attack_labels = []
            for j in range(len(features)):
                # Pretvori indeks prozora u stvarno vrijeme
                window_time = j  # Pretpostavljamo da su prozori po 1 sekundu
                
                # Provjeri je li prozor tijekom napada
                is_attack = attack_start <= window_time < attack_end
                attack_labels.append(is_attack)
            
            # Dodavanje podataka epizode
            episode_dict = {
                "episode_id": i,
                "features": weighted_features,
                "attack_labels": attack_labels,
                "metadata": episode_data["metadata"]
            }
            
            sample_episodes.append(episode_dict)
        
        # Generiraj i epizode bez napada
        for i in range(2):  # 2 epizode bez napada
            normal_packets = self.generate_normal_traffic(duration_seconds=episode_duration)
            episode_data = {
                "packets": normal_packets,
                "metadata": {
                    "total_duration": episode_duration,
                    "attack": None,
                    "normal_packet_count": len(normal_packets),
                    "attack_packet_count": 0,
                    "total_packet_count": len(normal_packets)
                }
            }
            
            # Izvlačenje značajki
            features = self.extract_features(episode_data["packets"])
            weighted_features = self.apply_feature_weights(features)
            
            attack_labels = [False] * len(features)
            
            episode_dict = {
                "episode_id": i + 3,
                "features": weighted_features,
                "attack_labels": attack_labels,
                "metadata": episode_data["metadata"]
            }
            
            sample_episodes.append(episode_dict)
        
        # Stvaranje finalnog sample dataset-a
        sample_dataset = {
            "train": sample_episodes[:4],  # 4 epizode za trening
            "validation": sample_episodes[4:5],  # 1 epizoda za validaciju
            "test": [],  # Nema test epizoda
            "metadata": {
                "num_episodes": len(sample_episodes),
                "episode_duration": episode_duration,
                "attack_probability": 0.6,  # 3/5 epizoda ima napad
                "creation_date": datetime.now().isoformat(),
                "feature_names": [
                    "source_entropy",
                    "destination_entropy",
                    "syn_ratio",
                    "traffic_volume",
                    "packet_rate",
                    "unique_src_ips_count",
                    "unique_dst_ips_count",
                    "protocol_imbalance"
                ],
                "feature_weights": self.feature_weights.tolist(),
                "description": "Mali uzorak dataset-a za testiranje i dokumentaciju"
            }
        }
        
        if save:
            # Spremanje dataset-a
            dataset_path = TRAINING_DATA_DIR / f"ddqn_sample_dataset_{datetime.now().strftime('%Y%m%d')}.json"
            self.save_dataset(sample_dataset, dataset_path)
            
            print(f"Uzorak dataset-a generiran i spremljen na: {dataset_path}")
            return str(dataset_path)
        else:
            return sample_dataset


# Pomoćna funkcija za inicijalizaciju dataset-a
def init_sample_dataset():
    """Inicijalizira uzorak dataset-a za testiranje."""
    generator = DatasetGenerator()
    return generator.generate_sample_dataset()


# Ako se skripta izvršava direktno, generiraj uzorke
if __name__ == "__main__":
    print("Inicijalizacija generator podataka...")
    generator = DatasetGenerator()
    
    print("Generiranje uzorka dataset-a...")
    sample_dataset_path = generator.generate_sample_dataset()
    
    print(f"Generiranje dovršeno. Uzorak dataset-a spremljen na: {sample_dataset_path}")