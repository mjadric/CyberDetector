#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Data Aggregator
Funkcije za agregaciju podataka iz MongoDB baze i pripremu za analizu
"""

import os
import sys
import json
import math
from datetime import datetime, timedelta
import logging
from pathlib import Path

# MongoDB import
try:
    from pymongo import MongoClient, ASCENDING, DESCENDING
    from bson.objectid import ObjectId
    import pymongo
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False
    print("Warning: MongoDB support not available in data aggregator")

# Provjera je li NumPy dostupan
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: NumPy not available, using basic Python lists instead")

# Logger
logger = logging.getLogger("mongodb_aggregator")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Uvozimo funkciju za konekciju iz connection modula
from .connection import get_mongodb_connection

def store_packet(packet_data):
    """
    Sprema pojedinačni mrežni paket u MongoDB.
    
    Args:
        packet_data: Podaci o paketu
        
    Returns:
        bool: True ako je spremanje uspjelo, inače False
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return False
    
    try:
        # Konverzija timestamp-a iz string-a u datetime objekt
        if "timestamp" in packet_data and isinstance(packet_data["timestamp"], str):
            try:
                packet_data["timestamp"] = datetime.fromisoformat(packet_data["timestamp"])
            except ValueError:
                # Ako konverzija ne uspije, koristimo trenutno vrijeme
                packet_data["timestamp"] = datetime.now()
        
        # Spremi podatke u kolekciju
        result = db.network_traffic.insert_one(packet_data)
        
        return True
    except Exception as e:
        logger.error(f"Failed to store packet data: {e}")
        return False

def store_packets_batch(packets_data):
    """
    Sprema više mrežnih paketa odjednom u MongoDB.
    
    Args:
        packets_data: Lista podataka o paketima
        
    Returns:
        bool: True ako je spremanje uspjelo, inače False
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return False
    
    try:
        # Konverzija timestamp-a iz string-a u datetime objekt
        for packet in packets_data:
            if "timestamp" in packet and isinstance(packet["timestamp"], str):
                try:
                    packet["timestamp"] = datetime.fromisoformat(packet["timestamp"])
                except ValueError:
                    # Ako konverzija ne uspije, koristimo trenutno vrijeme
                    packet["timestamp"] = datetime.now()
        
        # Spremi podatke u kolekciju
        if packets_data:
            result = db.network_traffic.insert_many(packets_data)
            logger.info(f"Inserted {len(result.inserted_ids)} packets into MongoDB")
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to store packets data: {e}")
        return False

def _calculate_entropy(values):
    """
    Izračunava Shannon entropiju za listu vrijednosti.
    
    Args:
        values: Lista vrijednosti
        
    Returns:
        float: Entropija [0, 1]
    """
    if not values:
        return 0.0
        
    # Računamo frekvencije
    freq_dict = {}
    for val in values:
        if val is not None:
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

def aggregate_traffic_data(time_window_seconds=1, start_time=None, end_time=None):
    """
    Agregira podatke o mrežnom prometu iz MongoDB baze u vremenske prozore.
    
    Args:
        time_window_seconds: Veličina vremenskog prozora u sekundama
        start_time: Početno vrijeme (None za sve podatke)
        end_time: Završno vrijeme (None za sve podatke)
        
    Returns:
        list: Lista agregiranih podataka po vremenskim prozorima
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return []
    
    try:
        # Pripremi filter za vremenski raspon
        time_filter = {}
        if start_time:
            time_filter["$gte"] = start_time if isinstance(start_time, datetime) else datetime.fromisoformat(start_time)
        if end_time:
            time_filter["$lte"] = end_time if isinstance(end_time, datetime) else datetime.fromisoformat(end_time)
        
        # Postavi filter za upit
        query_filter = {}
        if time_filter:
            query_filter["timestamp"] = time_filter
        
        # Dohvat svih paketa koji zadovoljavaju filter
        packets = list(db.network_traffic.find(query_filter).sort("timestamp", ASCENDING))
        
        if not packets:
            return []
        
        # Grupiranje paketa po vremenskim prozorima
        time_windows = {}
        
        for packet in packets:
            # Računanje indeksa vremenskog prozora
            timestamp = packet["timestamp"]
            window_index = int(timestamp.timestamp() / time_window_seconds)
            
            # Dodavanje paketa u odgovarajući vremenski prozor
            if window_index not in time_windows:
                time_windows[window_index] = []
            time_windows[window_index].append(packet)
        
        # Stvaranje agregiranih podataka za svaki vremenski prozor
        aggregated_data = []
        
        for window_index, window_packets in sorted(time_windows.items()):
            # Stvaranje vremenskog prozora
            window_start = datetime.fromtimestamp(window_index * time_window_seconds)
            
            # Izvlačenje značajki
            source_ips = [p.get("src_ip") for p in window_packets]
            destination_ips = [p.get("dst_ip") for p in window_packets]
            
            unique_src_ips = set(ip for ip in source_ips if ip)
            unique_dst_ips = set(ip for ip in destination_ips if ip)
            
            # Računanje značajki
            protocol_counts = {}
            syn_count = 0
            total_packet_size = 0
            
            for packet in window_packets:
                protocol = packet.get("protocol", "unknown")
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
                
                # SYN paketi
                if packet.get("tcp_flags") == "S":
                    syn_count += 1
                
                # Veličina paketa
                packet_size = packet.get("packet_size", 0)
                total_packet_size += packet_size
            
            # Normalizacija značajki
            total_packets = len(window_packets)
            
            # Shannon entropija izvorišnih IP adresa
            source_entropy = _calculate_entropy(source_ips)
            
            # Shannon entropija odredišnih IP adresa
            destination_entropy = _calculate_entropy(destination_ips)
            
            # Omjer SYN paketa
            syn_ratio = syn_count / total_packets if total_packets > 0 else 0
            
            # Normalizacija prometa (logaritamska)
            traffic_volume = min(1.0, math.log(total_packet_size + 1) / 20) if total_packet_size > 0 else 0
            
            # Stopa paketa (paketi po sekundi)
            packet_rate = total_packets / time_window_seconds if time_window_seconds > 0 else 0
            packet_rate_normalized = min(1.0, packet_rate / 5000)  # Normalizacija na max 5000 paketa/s
            
            # Broj jedinstvenih izvorišnih i odredišnih IP adresa
            unique_src_count = len(unique_src_ips)
            unique_dst_count = len(unique_dst_ips)
            
            unique_src_normalized = min(1.0, unique_src_count / 100) if unique_src_count > 0 else 0
            unique_dst_normalized = min(1.0, unique_dst_count / 50) if unique_dst_count > 0 else 0
            
            # Mjera neravnoteže u distribuciji protokola
            protocol_imbalance = _calculate_entropy(list(protocol_counts.keys()))
            
            # Provjera je li neki paket označen kao napad
            is_attack = any(p.get("is_attack", False) for p in window_packets)
            attack_type = next((p.get("attack_type") for p in window_packets if p.get("is_attack", False) and "attack_type" in p), None)
            
            # TCP/UDP/ICMP omjeri
            tcp_count = sum(1 for p in window_packets if p.get("protocol") == "TCP")
            udp_count = sum(1 for p in window_packets if p.get("protocol") == "UDP")
            icmp_count = sum(1 for p in window_packets if p.get("protocol") == "ICMP")
            
            tcp_ratio = tcp_count / total_packets if total_packets > 0 else 0
            udp_ratio = udp_count / total_packets if total_packets > 0 else 0
            icmp_ratio = icmp_count / total_packets if total_packets > 0 else 0
            
            # Stvaranje agregiranog podatka
            aggregated_entry = {
                "timestamp": window_start,
                "interval": f"{time_window_seconds}s",
                "packet_count": total_packets,
                "byte_count": total_packet_size,
                "metrics": {
                    "packet_count": total_packets,
                    "byte_count": total_packet_size,
                    "unique_source_ips": unique_src_count,
                    "unique_dest_ips": unique_dst_count,
                    "tcp_ratio": tcp_ratio,
                    "udp_ratio": udp_ratio,
                    "icmp_ratio": icmp_ratio,
                    "entropy_src_ip": source_entropy,
                    "entropy_dest_ip": destination_entropy,
                    "syn_ratio": syn_ratio
                },
                "features": [
                    source_entropy,
                    destination_entropy,
                    syn_ratio,
                    traffic_volume,
                    packet_rate_normalized,
                    unique_src_normalized,
                    unique_dst_normalized,
                    protocol_imbalance
                ],
                "packets": total_packets,
                "is_attack": is_attack,
                "attack_type": attack_type
            }
            
            aggregated_data.append(aggregated_entry)
        
        return aggregated_data
    except Exception as e:
        logger.error(f"Failed to aggregate traffic data: {e}")
        return []

def store_aggregated_data(aggregated_data):
    """
    Sprema agregirane podatke u MongoDB.
    
    Args:
        aggregated_data: Lista agregiranih podataka
        
    Returns:
        bool: True ako je spremanje uspjelo, inače False
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return False
    
    try:
        # Spremi podatke u kolekciju
        if aggregated_data:
            result = db.time_series_data.insert_many(aggregated_data)
            logger.info(f"Inserted {len(result.inserted_ids)} aggregated data points into MongoDB")
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to store aggregated data: {e}")
        return False

def get_recent_aggregated_data(limit=100):
    """
    Dohvaća nedavne agregirane podatke iz MongoDB baze.
    
    Args:
        limit: Maksimalni broj podataka za dohvat
        
    Returns:
        list: Lista agregiranih podataka
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return []
    
    try:
        # Dohvat nedavnih podataka
        data = list(db.time_series_data.find().sort("timestamp", DESCENDING).limit(limit))
        
        # Konverzija ObjectId-a u string za JSON serijalizaciju
        for item in data:
            if "_id" in item:
                item["_id"] = str(item["_id"])
        
        return data
    except Exception as e:
        logger.error(f"Failed to get recent aggregated data: {e}")
        return []

def extract_features_for_ddqn(window_size=10):
    """
    Izvlači značajke za DDQN model iz agregiranih podataka.
    
    Args:
        window_size: Veličina vremenskog prozora za DDQN input
        
    Returns:
        tuple: (features, labels) ili (None, None) ako nema podataka
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return None, None
    
    try:
        # Dohvat agregiranih podataka
        data = list(db.time_series_data.find().sort("timestamp", ASCENDING))
        
        if not data:
            return None, None
        
        # Priprema značajki i oznaka
        features = []
        labels = []
        
        for i in range(len(data) - window_size + 1):
            # Izvlačenje vremenskog prozora
            window = data[i:i+window_size]
            
            # Izvlačenje značajki iz prozora
            window_features = [item["features"] for item in window]
            
            # Priprema značajki
            if NUMPY_AVAILABLE:
                # Reshape u (window_size, num_features)
                features_array = np.array(window_features)
                # Flatten u (window_size * num_features,)
                features_flat = features_array.flatten()
                features.append(features_flat)
            else:
                # Flatten bez NumPy
                features_flat = [f for sublist in window_features for f in sublist]
                features.append(features_flat)
            
            # Oznaka je is_attack zadnjeg elementa u prozoru
            labels.append(1 if window[-1]["is_attack"] else 0)
        
        # Konverzija u NumPy array ako je dostupan
        if NUMPY_AVAILABLE:
            features = np.array(features)
            labels = np.array(labels)
        
        return features, labels
    except Exception as e:
        logger.error(f"Failed to extract features for DDQN: {e}")
        return None, None

def get_attack_statistics(start_time=None, end_time=None):
    """
    Dohvaća statistiku napada iz agregiranih podataka.
    
    Args:
        start_time: Početno vrijeme (None za sve podatke)
        end_time: Završno vrijeme (None za sve podatke)
        
    Returns:
        dict: Statistika napada
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return {}
    
    try:
        # Pripremi filter za vremenski raspon
        time_filter = {}
        if start_time:
            time_filter["$gte"] = start_time if isinstance(start_time, datetime) else datetime.fromisoformat(start_time)
        if end_time:
            time_filter["$lte"] = end_time if isinstance(end_time, datetime) else datetime.fromisoformat(end_time)
        
        # Postavi filter za upit
        query_filter = {"is_attack": True}
        if time_filter:
            query_filter["timestamp"] = time_filter
        
        # Dohvat podataka o napadima
        attack_data = list(db.time_series_data.find(query_filter))
        
        if not attack_data:
            return {
                "total_attacks": 0,
                "attack_types": {},
                "total_attack_packets": 0,
                "total_attack_bytes": 0,
                "attack_ratio": 0.0
            }
        
        # Računanje statistike
        attack_types = {}
        total_attack_packets = 0
        total_attack_bytes = 0
        
        for item in attack_data:
            attack_type = item.get("attack_type", "Unknown")
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            total_attack_packets += item.get("packet_count", 0)
            total_attack_bytes += item.get("byte_count", 0)
        
        # Dohvat ukupnih paketa za računanje omjera
        query_filter_all = {}
        if time_filter:
            query_filter_all["timestamp"] = time_filter
            
        total_windows = db.time_series_data.count_documents(query_filter_all)
        total_packets = sum(item.get("packet_count", 0) for item in db.time_series_data.find(query_filter_all))
        total_bytes = sum(item.get("byte_count", 0) for item in db.time_series_data.find(query_filter_all))
        
        # Računanje omjera napada
        attack_window_ratio = len(attack_data) / total_windows if total_windows > 0 else 0
        attack_packet_ratio = total_attack_packets / total_packets if total_packets > 0 else 0
        attack_byte_ratio = total_attack_bytes / total_bytes if total_bytes > 0 else 0
        
        return {
            "total_attacks": len(attack_data),
            "attack_types": attack_types,
            "total_attack_packets": total_attack_packets,
            "total_attack_bytes": total_attack_bytes,
            "attack_window_ratio": attack_window_ratio,
            "attack_packet_ratio": attack_packet_ratio,
            "attack_byte_ratio": attack_byte_ratio,
            "total_windows": total_windows,
            "total_packets": total_packets,
            "total_bytes": total_bytes
        }
    except Exception as e:
        logger.error(f"Failed to get attack statistics: {e}")
        return {}