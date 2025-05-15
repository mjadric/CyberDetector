#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Attack Events Module
Funkcije za rad s događajima napada u MongoDB bazi
"""

import os
import sys
import logging
from datetime import datetime, timedelta

# Uvozimo funkciju za konekciju iz connection modula
from .connection import get_mongodb_connection

# Logger
logger = logging.getLogger("mongodb_attack_events")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def store_attack_event(attack_data):
    """
    Sprema podatke o detektiranom napadu u MongoDB.
    
    Args:
        attack_data: Rječnik s podacima o napadu
            {
                "start_time": datetime,
                "end_time": datetime ili None (za napade koji još traju),
                "attack_type": string (TCP_SYN_FLOOD, UDP_FLOOD, itd.),
                "severity": int (1-5),
                "source_ips": list[string],
                "target_ips": list[string],
                "packet_count": int,
                "byte_count": int,
                "detection_features": dict,
                "mitigation_actions": list[string] ili [],
                "details": dict (dodatne informacije ovisno o tipu napada)
            }
            
    Returns:
        str: ID spremljenog zapisa ili None ako spremanje nije uspjelo
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return None
    
    try:
        # Dodaj vrijeme detekcije ako nije već prisutno
        if "detection_time" not in attack_data:
            attack_data["detection_time"] = datetime.now()
            
        # Validacija obaveznih polja
        required_fields = ["start_time", "attack_type", "severity", "source_ips", "target_ips"]
        for field in required_fields:
            if field not in attack_data:
                logger.error(f"Missing required field: {field}")
                return None
                
        # Spremi podatke u kolekciju
        result = db.attack_events.insert_one(attack_data)
        event_id = str(result.inserted_id)
        
        logger.info(f"Attack event stored with ID: {event_id}")
        
        # Stvori alert ako je ozbiljnost visoka
        if attack_data.get("severity", 0) >= 3:
            alert_data = {
                "timestamp": datetime.now(),
                "type": "ATTACK_DETECTED",
                "message": f"Detected {attack_data['attack_type']} attack from {len(attack_data['source_ips'])} source(s)",
                "severity": attack_data.get("severity", 3),
                "source": "DDoS Defender",
                "details": {
                    "attack_id": event_id,
                    "attack_type": attack_data.get("attack_type"),
                    "targets": attack_data.get("target_ips", [])[:5],  # Prvih 5 meta
                    "source_count": len(attack_data.get("source_ips", [])),
                    "packet_count": attack_data.get("packet_count", 0),
                    "byte_count": attack_data.get("byte_count", 0)
                }
            }
            
            db.alerts.insert_one(alert_data)
            logger.info(f"Created alert for attack event {event_id}")
        
        return event_id
    except Exception as e:
        logger.error(f"Failed to store attack event: {e}")
        return None

def update_attack_event(event_id, update_data):
    """
    Ažurira postojeći zapis o napadu.
    
    Args:
        event_id: ID zapisa o napadu
        update_data: Rječnik s podacima za ažuriranje
            
    Returns:
        bool: True ako je ažuriranje uspjelo, inače False
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return False
    
    try:
        from bson.objectid import ObjectId
        
        # Ažuriraj zapis
        result = db.attack_events.update_one(
            {"_id": ObjectId(event_id)},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            logger.warning(f"Attack event with ID {event_id} not found")
            return False
            
        if result.modified_count > 0:
            logger.info(f"Attack event {event_id} updated successfully")
            return True
        else:
            logger.info(f"Attack event {event_id} not modified (no changes)")
            return True
    except Exception as e:
        logger.error(f"Failed to update attack event: {e}")
        return False

def get_attack_events(start_time=None, end_time=None, attack_type=None, limit=100):
    """
    Dohvaća zapise o napadima iz MongoDB baze.
    
    Args:
        start_time: Početno vrijeme (None za sve podatke)
        end_time: Završno vrijeme (None za sve podatke)
        attack_type: Tip napada (None za sve tipove)
        limit: Maksimalni broj zapisa za dohvat
        
    Returns:
        list: Lista zapisa o napadima
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return []
    
    try:
        # Pripremi filter za upit
        query_filter = {}
        
        # Filter po vremenu
        if start_time or end_time:
            time_filter = {}
            if start_time:
                time_filter["$gte"] = start_time if isinstance(start_time, datetime) else datetime.fromisoformat(start_time)
            if end_time:
                time_filter["$lte"] = end_time if isinstance(end_time, datetime) else datetime.fromisoformat(end_time)
            query_filter["start_time"] = time_filter
        
        # Filter po tipu napada
        if attack_type:
            query_filter["attack_type"] = attack_type
        
        # Dohvat podataka
        from pymongo import DESCENDING
        
        events = list(db.attack_events.find(query_filter).sort("start_time", DESCENDING).limit(limit))
        
        # Konverzija ObjectId-a u string za JSON serijalizaciju
        for event in events:
            if "_id" in event:
                event["_id"] = str(event["_id"])
        
        return events
    except Exception as e:
        logger.error(f"Failed to get attack events: {e}")
        return []

def calculate_attack_statistics(start_time=None, end_time=None):
    """
    Izračunava statistiku napada iz zapisanih događaja.
    
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
        # Pripremi filter za upit
        query_filter = {}
        
        # Filter po vremenu
        if start_time or end_time:
            time_filter = {}
            if start_time:
                time_filter["$gte"] = start_time if isinstance(start_time, datetime) else datetime.fromisoformat(start_time)
            if end_time:
                time_filter["$lte"] = end_time if isinstance(end_time, datetime) else datetime.fromisoformat(end_time)
            query_filter["start_time"] = time_filter
        
        # Dohvat podataka
        events = list(db.attack_events.find(query_filter))
        
        if not events:
            return {
                "total_attacks": 0,
                "attack_types": {},
                "severity_distribution": {},
                "total_packets": 0,
                "total_bytes": 0,
                "unique_sources": 0,
                "unique_targets": 0
            }
        
        # Računanje statistike
        attack_types = {}
        severity_distribution = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        
        total_packets = 0
        total_bytes = 0
        
        all_sources = set()
        all_targets = set()
        
        for event in events:
            # Tip napada
            attack_type = event.get("attack_type", "Unknown")
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Ozbiljnost
            severity = event.get("severity", 1)
            if severity < 1: severity = 1
            if severity > 5: severity = 5
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
            
            # Brojevi paketa i bajtova
            total_packets += event.get("packet_count", 0)
            total_bytes += event.get("byte_count", 0)
            
            # Jedinstveni izvori i mete
            sources = event.get("source_ips", [])
            targets = event.get("target_ips", [])
            
            for src in sources:
                all_sources.add(src)
                
            for tgt in targets:
                all_targets.add(tgt)
        
        return {
            "total_attacks": len(events),
            "attack_types": attack_types,
            "severity_distribution": severity_distribution,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "unique_sources": len(all_sources),
            "unique_targets": len(all_targets),
            "mitigated_count": sum(1 for e in events if e.get("mitigation_actions"))
        }
    except Exception as e:
        logger.error(f"Failed to calculate attack statistics: {e}")
        return {}