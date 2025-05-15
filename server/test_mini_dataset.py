#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generira mali dataset za DDQN model
"""

import sys
import os
from pathlib import Path

# Dodajemo root direktorij u PYTHONPATH
current_dir = Path(__file__).parent
root_dir = current_dir.parent
sys.path.append(str(root_dir))

try:
    from server.datasets.generator import DatasetGenerator
    
    print("Inicijaliziram generator podataka...")
    generator = DatasetGenerator()
    
    print("Generiram mini-dataset (2 epizode)...")
    mini_dataset = {
        "train": [],
        "validation": [],
        "test": [],
        "metadata": {
            "num_episodes": 2,
            "episode_duration": 10,
            "attack_probability": 0.5,
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
            "feature_weights": generator.feature_weights.tolist() if hasattr(generator, 'feature_weights') else []
        }
    }
    
    # Epizoda 1: s napadom
    print("Generiranje epizode 1 (s TCP SYN Flood napadom)...")
    episode1_data = generator.generate_mixed_traffic(
        duration_seconds=10,
        attack_duration=5,
        attack_type="TCP_SYN_FLOOD",
        attack_intensity="medium",
        attack_start_time=3
    )
    
    # Izvlačenje značajki
    episode1_features = generator.extract_features(episode1_data["packets"])
    
    # Stvaranje oznaka (labels)
    episode1_labels = []
    for i in range(len(episode1_features)):
        time_point = i  # Pretpostavljamo 1 sekunda po značajki
        is_attack = episode1_data["metadata"]["attack"]["start_time"] <= time_point < (episode1_data["metadata"]["attack"]["start_time"] + episode1_data["metadata"]["attack"]["duration"])
        episode1_labels.append(is_attack)
    
    # Dodavanje epizode u train dataset
    mini_dataset["train"].append({
        "episode_id": 1,
        "features": episode1_features,
        "attack_labels": episode1_labels,
        "metadata": episode1_data["metadata"]
    })
    
    # Epizoda 2: bez napada
    print("Generiranje epizode 2 (bez napada)...")
    normal_packets = generator.generate_normal_traffic(duration_seconds=10)
    episode2_data = {
        "packets": normal_packets,
        "metadata": {
            "total_duration": 10,
            "attack": None,
            "normal_packet_count": len(normal_packets),
            "attack_packet_count": 0,
            "total_packet_count": len(normal_packets)
        }
    }
    
    # Izvlačenje značajki
    episode2_features = generator.extract_features(episode2_data["packets"])
    
    # Stvaranje oznaka (sve False jer nema napada)
    episode2_labels = [False] * len(episode2_features)
    
    # Dodavanje epizode u validation dataset
    mini_dataset["validation"].append({
        "episode_id": 2,
        "features": episode2_features,
        "attack_labels": episode2_labels,
        "metadata": episode2_data["metadata"]
    })
    
    # Spremanje mini-dataset-a
    dataset_dir = Path("server/datasets/training")
    dataset_dir.mkdir(exist_ok=True, parents=True)
    dataset_path = dataset_dir / "ddqn_mini_dataset.json"
    
    print(f"Spremanje mini-dataset-a u: {dataset_path}")
    generator.save_dataset(mini_dataset, dataset_path)
    
    print(f"Mini-dataset uspješno generiran i spremljen u: {dataset_path}")
    print(f"Broj značajki po epizodi: {len(mini_dataset['train'][0]['features'])}")
    
except Exception as e:
    print(f"Greška pri generiranju mini-dataset-a: {e}")
    import traceback
    traceback.print_exc()