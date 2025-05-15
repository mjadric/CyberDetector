#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Alerts Module
Funkcije za rad s upozorenjima u MongoDB bazi
"""

import os
import sys
import logging
from datetime import datetime, timedelta

# Uvozimo funkciju za konekciju iz connection modula
from .connection import get_mongodb_connection

# Logger
logger = logging.getLogger("mongodb_alerts")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def store_alert(alert_data):
    """
    Sprema upozorenje u MongoDB.
    
    Args:
        alert_data: Rječnik s podacima o upozorenju
            {
                "timestamp": datetime,
                "type": string (ATTACK_DETECTED, SYN_FLOOD, ENTROPY_ANOMALY, itd.),
                "message": string,
                "severity": int (1-5),
                "source": string (komponenta koja je generirala upozorenje),
                "details": dict (dodatne informacije ovisno o tipu upozorenja)
            }
            
    Returns:
        str: ID spremljenog upozorenja ili None ako spremanje nije uspjelo
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return None
    
    try:
        # Dodaj vrijeme ako nije već prisutno
        if "timestamp" not in alert_data:
            alert_data["timestamp"] = datetime.now()
            
        # Validacija obaveznih polja
        required_fields = ["type", "message", "severity"]
        for field in required_fields:
            if field not in alert_data:
                logger.error(f"Missing required field: {field}")
                return None
                
        # Provjera ispravnosti polja severity
        if "severity" in alert_data:
            severity = alert_data["severity"]
            if not isinstance(severity, int) or severity < 1 or severity > 5:
                alert_data["severity"] = max(1, min(5, int(severity) if isinstance(severity, (int, float)) else 3))
        
        # Spremi podatke u kolekciju
        result = db.alerts.insert_one(alert_data)
        alert_id = str(result.inserted_id)
        
        logger.info(f"Alert stored with ID: {alert_id}")
        return alert_id
    except Exception as e:
        logger.error(f"Failed to store alert: {e}")
        return None

def update_alert(alert_id, update_data):
    """
    Ažurira postojeće upozorenje.
    
    Args:
        alert_id: ID upozorenja
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
        result = db.alerts.update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            logger.warning(f"Alert with ID {alert_id} not found")
            return False
            
        return result.modified_count > 0
    except Exception as e:
        logger.error(f"Failed to update alert: {e}")
        return False

def get_alerts(start_time=None, end_time=None, alert_type=None, severity=None, limit=100):
    """
    Dohvaća upozorenja iz MongoDB baze.
    
    Args:
        start_time: Početno vrijeme (None za sve podatke)
        end_time: Završno vrijeme (None za sve podatke)
        alert_type: Tip upozorenja (None za sve tipove)
        severity: Minimalna ozbiljnost (1-5, None za sve)
        limit: Maksimalni broj upozorenja za dohvat
        
    Returns:
        list: Lista upozorenja
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
            query_filter["timestamp"] = time_filter
        
        # Filter po tipu upozorenja
        if alert_type:
            query_filter["type"] = alert_type
            
        # Filter po ozbiljnosti
        if severity:
            try:
                min_severity = int(severity)
                query_filter["severity"] = {"$gte": min_severity}
            except (ValueError, TypeError):
                pass
        
        # Dohvat podataka
        from pymongo import DESCENDING
        
        alerts = list(db.alerts.find(query_filter).sort("timestamp", DESCENDING).limit(limit))
        
        # Konverzija ObjectId-a u string za JSON serijalizaciju
        for alert in alerts:
            if "_id" in alert:
                alert["_id"] = str(alert["_id"])
        
        return alerts
    except Exception as e:
        logger.error(f"Failed to get alerts: {e}")
        return []

def mark_alert_as_read(alert_id):
    """
    Označava upozorenje kao pročitano.
    
    Args:
        alert_id: ID upozorenja
            
    Returns:
        bool: True ako je ažuriranje uspjelo, inače False
    """
    return update_alert(alert_id, {"read": True, "read_time": datetime.now()})

def mark_alert_as_resolved(alert_id, resolution_notes=None):
    """
    Označava upozorenje kao riješeno.
    
    Args:
        alert_id: ID upozorenja
        resolution_notes: Bilješke o rješenju (opciono)
            
    Returns:
        bool: True ako je ažuriranje uspjelo, inače False
    """
    update_data = {
        "resolved": True, 
        "resolution_time": datetime.now()
    }
    
    if resolution_notes:
        update_data["resolution_notes"] = resolution_notes
        
    return update_alert(alert_id, update_data)

def get_alert_statistics(start_time=None, end_time=None):
    """
    Izračunava statistiku upozorenja.
    
    Args:
        start_time: Početno vrijeme (None za sve podatke)
        end_time: Završno vrijeme (None za sve podatke)
        
    Returns:
        dict: Statistika upozorenja
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
            query_filter["timestamp"] = time_filter
        
        # Dohvat podataka
        alerts = list(db.alerts.find(query_filter))
        
        if not alerts:
            return {
                "total_alerts": 0,
                "alert_types": {},
                "severity_distribution": {},
                "resolved_count": 0,
                "unresolved_count": 0,
                "read_count": 0,
                "unread_count": 0
            }
        
        # Računanje statistike
        alert_types = {}
        severity_distribution = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        
        resolved_count = 0
        unresolved_count = 0
        read_count = 0
        unread_count = 0
        
        for alert in alerts:
            # Tip upozorenja
            alert_type = alert.get("type", "Unknown")
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
            
            # Ozbiljnost
            severity = alert.get("severity", 1)
            if severity < 1: severity = 1
            if severity > 5: severity = 5
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
            
            # Riješenost i pročitanost
            if alert.get("resolved", False):
                resolved_count += 1
            else:
                unresolved_count += 1
                
            if alert.get("read", False):
                read_count += 1
            else:
                unread_count += 1
        
        return {
            "total_alerts": len(alerts),
            "alert_types": alert_types,
            "severity_distribution": severity_distribution,
            "resolved_count": resolved_count,
            "unresolved_count": unresolved_count,
            "read_count": read_count,
            "unread_count": unread_count
        }
    except Exception as e:
        logger.error(f"Failed to calculate alert statistics: {e}")
        return {}