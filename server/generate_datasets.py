#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Dataset Generator Script
Skripta za generiranje dataset-a prema metodologiji
"""

import os
import sys
import time
from pathlib import Path

# Dodavanje root direktorija u PYTHONPATH
current_dir = Path(__file__).parent
root_dir = current_dir.parent
sys.path.append(str(root_dir))

# Import generatora dataset-a
try:
    from server.datasets.generator import DatasetGenerator
except ImportError as e:
    print(f"Greška pri importu DatasetGenerator: {e}")
    sys.exit(1)

def generate_sample_dataset():
    """
    Generira mali demo dataset za testiranje
    """
    print("Generiram uzorak dataset-a za testiranje...")
    generator = DatasetGenerator()
    dataset_path = generator.generate_sample_dataset()
    print(f"Uzorak dataset-a generiran i spremljen na: {dataset_path}")
    return dataset_path

def generate_full_dataset(num_episodes=100, attack_probability=0.5):
    """
    Generira potpuni dataset za trening, validaciju i testiranje
    
    Args:
        num_episodes: Broj epizoda za dataset
        attack_probability: Vjerojatnost da epizoda sadrži napad (0.0-1.0)
    """
    print(f"Generiram puni dataset ({num_episodes} epizoda)...")
    print(f"Vjerojatnost napada: {attack_probability*100:.0f}%")
    
    start_time = time.time()
    generator = DatasetGenerator()
    dataset_path = generator.generate_training_dataset(
        num_episodes=num_episodes,
        episode_duration=200,
        attack_probability=attack_probability
    )
    
    elapsed_time = time.time() - start_time
    print(f"Dataset generiran za {elapsed_time:.1f} sekundi")
    print(f"Dataset spremljen na: {dataset_path}")
    return dataset_path

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generator dataset-a za DDoS Defender")
    parser.add_argument("--full", action="store_true", help="Generiraj puni dataset umjesto uzorka")
    parser.add_argument("--episodes", type=int, default=100, help="Broj epizoda za puni dataset")
    parser.add_argument("--attack-prob", type=float, default=0.5, help="Vjerojatnost napada (0.0-1.0)")
    
    args = parser.parse_args()
    
    if args.full:
        generate_full_dataset(args.episodes, args.attack_prob)
    else:
        generate_sample_dataset()