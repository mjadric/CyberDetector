#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Dataset loader module
"""

from pathlib import Path
import os
import sys
import json

# Enabling imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Struktura direktorija za pohranu podataka
DATASET_ROOT = Path(__file__).parent
NETWORK_DATA_DIR = DATASET_ROOT / "network"
ATTACK_DATA_DIR = DATASET_ROOT / "attack"
TRAINING_DATA_DIR = DATASET_ROOT / "training"

# Osigurajmo da direktoriji postoje
for dir_path in [NETWORK_DATA_DIR, ATTACK_DATA_DIR, TRAINING_DATA_DIR]:
    dir_path.mkdir(exist_ok=True)

def get_available_datasets():
    """
    Vraća popis dostupnih dataset-a za trening i evaluaciju.
    
    Returns:
        Dict s popisom dataset-a po kategorijama
    """
    datasets = {
        "network": [],
        "attack": [],
        "training": []
    }
    
    # Pronalazak JSON dataset-a u direktorijima
    for dataset_type, dir_path in [
        ("network", NETWORK_DATA_DIR),
        ("attack", ATTACK_DATA_DIR),
        ("training", TRAINING_DATA_DIR)
    ]:
        try:
            for file in dir_path.glob("*.json"):
                datasets[dataset_type].append({
                    "filename": file.name,
                    "path": str(file),
                    "size_bytes": file.stat().st_size,
                    "modified": file.stat().st_mtime
                })
        except Exception as e:
            print(f"Greška pri čitanju {dataset_type} dataset-a: {e}")
    
    return datasets

def load_dataset(path):
    """
    Učitava dataset iz JSON datoteke.
    
    Args:
        path: Putanja do dataset-a
        
    Returns:
        Dict s učitanim dataset-om
    """
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Greška pri učitavanju dataset-a {path}: {e}")
        return None

def initialize_datasets():
    """
    Inicijalizira demo dataset-e ako ne postoje.
    
    Returns:
        True ako je inicijalizacija uspješna
    """
    try:
        from .generator import DatasetGenerator
        
        # Provjeri postoje li već dataset-i
        existing_datasets = get_available_datasets()
        total_datasets = sum(len(ds) for ds in existing_datasets.values())
        
        if total_datasets == 0:
            print("Inicijaliziram demo dataset-e...")
            generator = DatasetGenerator()
            generator.generate_sample_dataset()
            return True
        else:
            print(f"Postojeći dataset-i pronađeni ({total_datasets}).")
            return True
            
    except ImportError as e:
        print(f"Greška pri inicijalizaciji dataset-a: {e}")
        return False