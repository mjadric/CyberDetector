#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - MongoDB Connection Module
Centralno mjesto za upravljanje konekcijom s MongoDB bazom
"""

import os
import time
from datetime import datetime
import logging

# MongoDB import
try:
    from pymongo import MongoClient, ASCENDING, DESCENDING
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False
    print("Warning: MongoDB support not available in connection module")

# Logger
logger = logging.getLogger("mongodb_connection")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Globalni objekti konekcije
_mongo_client = None
_mongo_db = None

def get_mongodb_connection():
    """
    Vraća konekciju na MongoDB bazu podataka. Koristi singleton pattern
    za dijeljenje konekcije.
    
    Returns:
        tuple: (client, db) ili (None, None) ako konekcija nije uspjela
    """
    global _mongo_client, _mongo_db
    
    # Ako već imamo konekciju, vrati je
    if _mongo_client is not None and _mongo_db is not None:
        try:
            # Provjeri je li konekcija još uvijek aktivna
            _mongo_client.admin.command('ping')
            return _mongo_client, _mongo_db
        except Exception:
            # Ako konekcija nije aktivna, zatvori je i stvori novu
            try:
                _mongo_client.close()
            except:
                pass
            _mongo_client = None
            _mongo_db = None
    
    if not MONGO_AVAILABLE:
        logger.warning("MongoDB support not available")
        return None, None
    
    try:
        # Dohvati MongoDB URI iz environment varijable ili koristi lokalni default
        mongo_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/")
        
        # Provjeri sadrži li URI već ime baze
        if "?" in mongo_uri and "/" in mongo_uri.split("?")[0]:
            uri_parts = mongo_uri.split("?")
            db_name = uri_parts[0].split("/")[-1]
            if not db_name:
                mongo_uri = f"{uri_parts[0]}ddos_defender"
                if len(uri_parts) > 1:
                    mongo_uri += f"?{uri_parts[1]}"
        elif "/" in mongo_uri:
            if mongo_uri.endswith("/"):
                mongo_uri += "ddos_defender"
            else:
                uri_parts = mongo_uri.split("/")
                if not uri_parts[-1] or "." in uri_parts[-1]:
                    mongo_uri += "/ddos_defender"
        
        # Maskiraj korisničko ime i lozinku u URI za logove
        display_uri = mongo_uri
        if "@" in display_uri:
            display_uri = display_uri.split("@")[1]
        
        logger.info(f"Connecting to MongoDB at: {display_uri}")
        
        # Stvaranje konekcije s kratkim timeout-om
        _mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        
        # Dohvat baze podataka
        if "?" in mongo_uri and "/" in mongo_uri.split("?")[0]:
            db_name = mongo_uri.split("?")[0].split("/")[-1]
            if not db_name:
                db_name = "ddos_defender"
        elif "/" in mongo_uri:
            uri_parts = mongo_uri.split("/")
            db_name = uri_parts[-1] if uri_parts[-1] and "." not in uri_parts[-1] else "ddos_defender"
        else:
            db_name = "ddos_defender"
            
        _mongo_db = _mongo_client[db_name]
        
        # Provjera konekcije
        _mongo_client.admin.command('ping')
        logger.info(f"MongoDB connection successful to {db_name}")
        
        # Provjeri i stvori kolekcije i indekse
        _ensure_collections()
        
        return _mongo_client, _mongo_db
    except ConnectionFailure as e:
        logger.error(f"MongoDB connection failed: {e}")
        if _mongo_client:
            try:
                _mongo_client.close()
            except:
                pass
        _mongo_client = None
        _mongo_db = None
        return None, None
    except ServerSelectionTimeoutError as e:
        logger.error(f"MongoDB server selection timeout: {e}")
        if _mongo_client:
            try:
                _mongo_client.close()
            except:
                pass
        _mongo_client = None
        _mongo_db = None
        return None, None
    except Exception as e:
        logger.error(f"MongoDB connection failed with unexpected error: {e}")
        if _mongo_client:
            try:
                _mongo_client.close()
            except:
                pass
        _mongo_client = None
        _mongo_db = None
        return None, None

def _ensure_collections():
    """
    Osigurava da postoje potrebne kolekcije i indeksi u MongoDB bazi
    """
    global _mongo_db
    if _mongo_db is None:
        return
            
    collections = [
        "network_traffic",    # Pojedinačni mrežni paketi
        "attack_events",      # Detekcije napada
        "alerts",             # Sistemska upozorenja
        "packet_samples",     # Uzorci paketa za trening
        "time_series_data",   # Agregirani vremenski podaci
        "dataset_metadata",   # Metapodaci dataset-a
        "training_episodes",  # Epizode za trening
        "validation_episodes", # Epizode za validaciju
        "test_episodes"       # Epizode za testiranje
    ]
    
    existing_collections = _mongo_db.list_collection_names()
    
    for collection in collections:
        if collection not in existing_collections:
            # Stvaranje kolekcije
            _mongo_db.create_collection(collection)
            logger.info(f"Created MongoDB collection: {collection}")
            
            # Dodavanje indeksa
            if collection == "network_traffic":
                _mongo_db[collection].create_index([("timestamp", ASCENDING)])
                _mongo_db[collection].create_index([("src_ip", ASCENDING)])
                _mongo_db[collection].create_index([("dst_ip", ASCENDING)])
                _mongo_db[collection].create_index([("is_attack", ASCENDING)])
                logger.info(f"Created indexes for collection: {collection}")
            
            elif collection == "attack_events":
                _mongo_db[collection].create_index([("start_time", ASCENDING)])
                _mongo_db[collection].create_index([("attack_type", ASCENDING)])
                logger.info(f"Created indexes for collection: {collection}")
                
            elif collection == "alerts":
                _mongo_db[collection].create_index([("timestamp", ASCENDING)])
                _mongo_db[collection].create_index([("severity", ASCENDING)])
                logger.info(f"Created indexes for collection: {collection}")
                
            elif collection == "time_series_data":
                _mongo_db[collection].create_index([("timestamp", ASCENDING)])
                _mongo_db[collection].create_index([("is_attack", ASCENDING)])
                logger.info(f"Created indexes for collection: {collection}")
                
            elif collection in ["training_episodes", "validation_episodes", "test_episodes"]:
                _mongo_db[collection].create_index([("episode_id", ASCENDING)])
                logger.info(f"Created indexes for collection: {collection}")

def close_mongodb_connection():
    """
    Zatvara globalnu konekciju na MongoDB
    """
    global _mongo_client, _mongo_db
    if _mongo_client is not None:
        try:
            _mongo_client.close()
            logger.info("MongoDB connection closed")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")
        finally:
            _mongo_client = None
            _mongo_db = None