#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Datasets Module
Funkcije za rad s dataset-ima u MongoDB bazi
"""

import os
import sys
import logging
import json
from datetime import datetime, timedelta

# Uvozimo funkciju za konekciju iz connection modula
from .connection import get_mongodb_connection

# Logger
logger = logging.getLogger("mongodb_datasets")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def store_dataset_metadata(metadata):
    """
    Sprema metapodatke o dataset-u u MongoDB.
    
    Args:
        metadata: Rječnik s metapodacima o dataset-u
            {
                "name": string,
                "description": string,
                "created_at": datetime,
                "source": string,
                "total_samples": int,
                "attack_samples": int,
                "normal_samples": int,
                "feature_description": dict,
                "dataset_type": string (training, validation, test),
                "additional_info": dict (dodatne informacije o dataset-u)
            }
            
    Returns:
        str: ID spremljenih metapodataka ili None ako spremanje nije uspjelo
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return None
    
    try:
        # Dodaj vrijeme stvaranja ako nije već prisutno
        if "created_at" not in metadata:
            metadata["created_at"] = datetime.now()
            
        # Validacija obaveznih polja
        required_fields = ["name", "description"]
        for field in required_fields:
            if field not in metadata:
                logger.error(f"Missing required field: {field}")
                return None
        
        # Spremi podatke u kolekciju
        result = db.dataset_metadata.insert_one(metadata)
        metadata_id = str(result.inserted_id)
        
        logger.info(f"Dataset metadata stored with ID: {metadata_id}")
        return metadata_id
    except Exception as e:
        logger.error(f"Failed to store dataset metadata: {e}")
        return None

def store_training_episode(episode_data):
    """
    Sprema podatke o epizodi treninga u MongoDB.
    
    Args:
        episode_data: Rječnik s podacima o epizodi treninga
            {
                "episode_id": string,
                "timestamp": datetime,
                "duration_seconds": float,
                "traffic_type": string (normal, mixed, attack),
                "attack_type": string (ako je prisutan napad) ili None,
                "packets": lista paketa,
                "features": lista značajki po vremenskim prozorima,
                "is_attack": bool (sadrži li epizoda napad),
                "additional_info": dict (dodatne informacije o epizodi)
            }
            
    Returns:
        str: ID spremljene epizode ili None ako spremanje nije uspjelo
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return None
    
    try:
        # Dodaj vrijeme ako nije već prisutno
        if "timestamp" not in episode_data:
            episode_data["timestamp"] = datetime.now()
            
        # Validacija obaveznih polja
        required_fields = ["episode_id", "traffic_type", "features"]
        for field in required_fields:
            if field not in episode_data:
                logger.error(f"Missing required field: {field}")
                return None
        
        # Spremi podatke u kolekciju
        # Ako epizoda već postoji, prepiši je
        from bson.objectid import ObjectId
        
        # Provjeri postoji li već epizoda s istim ID-em
        existing_episode = db.training_episodes.find_one({"episode_id": episode_data["episode_id"]})
        
        if existing_episode:
            # Ažuriraj postojeću epizodu
            result = db.training_episodes.update_one(
                {"_id": existing_episode["_id"]},
                {"$set": episode_data}
            )
            episode_id = str(existing_episode["_id"])
            logger.info(f"Training episode updated with ID: {episode_id}")
        else:
            # Stvori novu epizodu
            result = db.training_episodes.insert_one(episode_data)
            episode_id = str(result.inserted_id)
            logger.info(f"Training episode stored with ID: {episode_id}")
        
        return episode_id
    except Exception as e:
        logger.error(f"Failed to store training episode: {e}")
        return None

def store_test_episode(episode_data):
    """
    Sprema podatke o epizodi testiranja u MongoDB.
    
    Args:
        episode_data: Rječnik s podacima o epizodi testiranja
            (ista struktura kao za epizodu treninga)
            
    Returns:
        str: ID spremljene epizode ili None ako spremanje nije uspjelo
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return None
    
    try:
        # Dodaj vrijeme ako nije već prisutno
        if "timestamp" not in episode_data:
            episode_data["timestamp"] = datetime.now()
            
        # Validacija obaveznih polja
        required_fields = ["episode_id", "traffic_type", "features"]
        for field in required_fields:
            if field not in episode_data:
                logger.error(f"Missing required field: {field}")
                return None
        
        # Spremi podatke u kolekciju
        # Ako epizoda već postoji, prepiši je
        from bson.objectid import ObjectId
        
        # Provjeri postoji li već epizoda s istim ID-em
        existing_episode = db.test_episodes.find_one({"episode_id": episode_data["episode_id"]})
        
        if existing_episode:
            # Ažuriraj postojeću epizodu
            result = db.test_episodes.update_one(
                {"_id": existing_episode["_id"]},
                {"$set": episode_data}
            )
            episode_id = str(existing_episode["_id"])
            logger.info(f"Test episode updated with ID: {episode_id}")
        else:
            # Stvori novu epizodu
            result = db.test_episodes.insert_one(episode_data)
            episode_id = str(result.inserted_id)
            logger.info(f"Test episode stored with ID: {episode_id}")
        
        return episode_id
    except Exception as e:
        logger.error(f"Failed to store test episode: {e}")
        return None

def get_training_episodes(limit=100, with_attack_only=False, attack_type=None):
    """
    Dohvaća epizode treninga iz MongoDB baze.
    
    Args:
        limit: Maksimalni broj epizoda za dohvat
        with_attack_only: Dohvati samo epizode s napadima
        attack_type: Dohvati samo epizode s određenim tipom napada
        
    Returns:
        list: Lista epizoda treninga
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return []
    
    try:
        # Pripremi filter za upit
        query_filter = {}
        
        # Filter za napade
        if with_attack_only:
            query_filter["is_attack"] = True
            
        # Filter za tip napada
        if attack_type:
            query_filter["attack_type"] = attack_type
        
        # Dohvat podataka
        from pymongo import DESCENDING
        
        # Ne dohvaćaj cijele pakete jer mogu biti veliki
        projection = {"packets": 0}
        
        episodes = list(db.training_episodes.find(query_filter, projection).sort("timestamp", DESCENDING).limit(limit))
        
        # Konverzija ObjectId-a u string za JSON serijalizaciju
        for episode in episodes:
            if "_id" in episode:
                episode["_id"] = str(episode["_id"])
        
        return episodes
    except Exception as e:
        logger.error(f"Failed to get training episodes: {e}")
        return []

def get_test_episodes(limit=100, with_attack_only=False, attack_type=None):
    """
    Dohvaća epizode testiranja iz MongoDB baze.
    
    Args:
        limit: Maksimalni broj epizoda za dohvat
        with_attack_only: Dohvati samo epizode s napadima
        attack_type: Dohvati samo epizode s određenim tipom napada
        
    Returns:
        list: Lista epizoda testiranja
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return []
    
    try:
        # Pripremi filter za upit
        query_filter = {}
        
        # Filter za napade
        if with_attack_only:
            query_filter["is_attack"] = True
            
        # Filter za tip napada
        if attack_type:
            query_filter["attack_type"] = attack_type
        
        # Dohvat podataka
        from pymongo import DESCENDING
        
        # Ne dohvaćaj cijele pakete jer mogu biti veliki
        projection = {"packets": 0}
        
        episodes = list(db.test_episodes.find(query_filter, projection).sort("timestamp", DESCENDING).limit(limit))
        
        # Konverzija ObjectId-a u string za JSON serijalizaciju
        for episode in episodes:
            if "_id" in episode:
                episode["_id"] = str(episode["_id"])
        
        return episodes
    except Exception as e:
        logger.error(f"Failed to get test episodes: {e}")
        return []

def get_dataset_statistics():
    """
    Dohvaća statistiku dataset-a iz MongoDB baze.
    
    Returns:
        dict: Statistika dataset-a
    """
    client, db = get_mongodb_connection()
    if client is None or db is None:
        return {}
    
    try:
        # Brojevi epizoda
        training_count = db.training_episodes.count_documents({})
        test_count = db.test_episodes.count_documents({})
        
        # Brojevi epizoda s napadima
        training_attack_count = db.training_episodes.count_documents({"is_attack": True})
        test_attack_count = db.test_episodes.count_documents({"is_attack": True})
        
        # Distribucija po tipovima napada
        training_attack_types = {}
        test_attack_types = {}
        
        # Agregacija za trening
        if training_count > 0:
            pipeline = [
                {"$match": {"is_attack": True}},
                {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}
            ]
            
            attack_type_counts = list(db.training_episodes.aggregate(pipeline))
            for item in attack_type_counts:
                attack_type = item["_id"] or "Unknown"
                training_attack_types[attack_type] = item["count"]
        
        # Agregacija za test
        if test_count > 0:
            pipeline = [
                {"$match": {"is_attack": True}},
                {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}
            ]
            
            attack_type_counts = list(db.test_episodes.aggregate(pipeline))
            for item in attack_type_counts:
                attack_type = item["_id"] or "Unknown"
                test_attack_types[attack_type] = item["count"]
        
        return {
            "training_count": training_count,
            "test_count": test_count,
            "training_attack_count": training_attack_count,
            "test_attack_count": test_attack_count,
            "training_normal_count": training_count - training_attack_count,
            "test_normal_count": test_count - test_attack_count,
            "training_attack_ratio": training_attack_count / training_count if training_count > 0 else 0,
            "test_attack_ratio": test_attack_count / test_count if test_count > 0 else 0,
            "training_attack_types": training_attack_types,
            "test_attack_types": test_attack_types
        }
    except Exception as e:
        logger.error(f"Failed to get dataset statistics: {e}")
        return {}