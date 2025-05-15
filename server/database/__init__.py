"""
Database Module za DDoS Defender
Centralno mjesto za upravljanje bazama podataka
"""

# MongoDB moduli
from .mongodb import (
    # Osnovne funkcije za konekciju
    get_mongodb_connection,
    close_mongodb_connection,
    
    # Funkcije za rad s podacima prometa
    store_packet,
    store_packets_batch,
    aggregate_traffic_data,
    store_aggregated_data,
    get_recent_aggregated_data,
    extract_features_for_ddqn,
    get_attack_statistics,
    
    # Funkcije za rad s događajima napada
    store_attack_event,
    update_attack_event,
    get_attack_events,
    calculate_attack_statistics,
    
    # Funkcije za rad s upozorenjima
    store_alert,
    update_alert,
    get_alerts,
    mark_alert_as_read,
    mark_alert_as_resolved,
    get_alert_statistics,
    
    # Funkcije za rad s dataset-ima
    store_dataset_metadata,
    store_training_episode,
    store_test_episode,
    get_training_episodes,
    get_test_episodes,
    get_dataset_statistics
)

# PostgreSQL moduli će se dodati kasnije

# Neo4j moduli će se dodati kasnije

# Funkcija za provjeru statusa baza podataka
def check_database_status():
    """
    Provjerava status konekcija na baze podataka
    
    Returns:
        dict: Status konekcija na baze podataka
    """
    status = {
        "mongodb": False,
        "postgresql": False,
        "neo4j": False
    }
    
    # Provjeri MongoDB konekciju
    client, db = get_mongodb_connection()
    if client is not None and db is not None:
        try:
            # Provjeri konekciju
            client.admin.command('ping')
            status["mongodb"] = True
        except:
            pass
            
    # Ovdje će kasnije biti provjere za PostgreSQL i Neo4j
            
    return status