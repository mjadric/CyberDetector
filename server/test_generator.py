#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test za generator podataka
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
    
    print("Generiram normalni promet...")
    normal_traffic = generator.generate_normal_traffic(duration_seconds=5)
    print(f"Broj normalnih paketa: {len(normal_traffic)}")
    
    print("Generiram napadački promet (TCP SYN Flood)...")
    attack_traffic = generator.generate_attack_traffic(
        attack_type="TCP_SYN_FLOOD",
        intensity="medium",
        duration_seconds=5
    )
    print(f"Broj napadačkih paketa: {len(attack_traffic)}")
    
    print("Testiranje uspješno!")
    
except Exception as e:
    print(f"Greška pri testiranju: {e}")
    import traceback
    traceback.print_exc()