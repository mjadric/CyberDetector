#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Test MongoDB agregacije
Skripta za testiranje spremanja paketa u MongoDB i njihove agregacije
"""

import os
import sys
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

# Dodavanje root direktorija u PYTHONPATH
current_dir = Path(__file__).parent
root_dir = current_dir.parent
sys.path.append(str(root_dir))

# Import naših modula
try:
    from server.database.data_aggregator import (
        store_packets_batch, 
        aggregate_traffic_data,
        store_aggregated_data,
        extract_features_for_ddqn,
        get_attack_statistics
    )
    from server.datasets.generator import DatasetGenerator
except ImportError as e:
    print(f"Greška pri importu: {e}")
    sys.exit(1)

def test_with_generator():
    """
    Testira spremanje i agregaciju podataka koristeći DatasetGenerator
    """
    print("Inicijaliziram generator podataka...")
    generator = DatasetGenerator()
    
    print("Generiram normalni promet...")
    normal_traffic = generator.generate_normal_traffic(duration_seconds=10)
    print(f"Broj normalnih paketa: {len(normal_traffic)}")
    
    print("Generiram napadački promet (TCP SYN Flood)...")
    attack_traffic = generator.generate_attack_traffic(
        attack_type="TCP_SYN_FLOOD",
        intensity="medium",
        duration_seconds=5
    )
    print(f"Broj napadačkih paketa: {len(attack_traffic)}")
    
    # Kombiniraj pakete
    all_packets = normal_traffic + attack_traffic
    all_packets.sort(key=lambda x: x["timestamp"] if isinstance(x["timestamp"], datetime) else 
                                  datetime.fromisoformat(x["timestamp"]))
    
    print(f"Ukupno paketa za spremanje: {len(all_packets)}")
    
    # Spremi pakete u MongoDB
    print("Spremam pakete u MongoDB...")
    success = store_packets_batch(all_packets)
    
    if success:
        print("Paketi uspješno spremljeni u MongoDB")
        
        # Agregiraj podatke
        print("Agregiram podatke...")
        start_time = datetime.fromisoformat(all_packets[0]["timestamp"]) if isinstance(all_packets[0]["timestamp"], str) else all_packets[0]["timestamp"]
        end_time = datetime.fromisoformat(all_packets[-1]["timestamp"]) if isinstance(all_packets[-1]["timestamp"], str) else all_packets[-1]["timestamp"]
        
        # Dodaj malo margine za end_time
        end_time = end_time + timedelta(seconds=1)
        
        aggregated_data = aggregate_traffic_data(
            time_window_seconds=1,
            start_time=start_time,
            end_time=end_time
        )
        
        print(f"Generirano {len(aggregated_data)} agregiranih podatkovnih točaka")
        
        # Spremi agregirane podatke
        if aggregated_data:
            print("Spremam agregirane podatke...")
            success = store_aggregated_data(aggregated_data)
            
            if success:
                print("Agregirani podaci uspješno spremljeni u MongoDB")
                
                # Izvuci značajke za DDQN
                print("Izvlačim značajke za DDQN...")
                features, labels = extract_features_for_ddqn(window_size=5)
                
                if features is not None:
                    print(f"Izdvojeno {len(features)} vektora značajki za DDQN")
                    print(f"Oblik značajki: {features.shape if hasattr(features, 'shape') else len(features[0]) if features else 0}")
                    
                    # Statistika napada
                    print("Dohvaćam statistiku napada...")
                    stats = get_attack_statistics(start_time=start_time, end_time=end_time)
                    
                    print("Statistika napada:")
                    for key, value in stats.items():
                        print(f"  {key}: {value}")
                        
                    print("\nTestiranje uspješno završeno!")
                    return True
                else:
                    print("Greška pri izvlačenju značajki za DDQN")
            else:
                print("Greška pri spremanju agregiranih podataka")
        else:
            print("Nema generiranih agregiranih podataka")
    else:
        print("Greška pri spremanju paketa u MongoDB")
    
    return False

if __name__ == "__main__":
    print("Testiram MongoDB agregaciju s generatorom podataka...")
    test_with_generator()