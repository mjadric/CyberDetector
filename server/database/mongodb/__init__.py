"""
MongoDB Module za DDoS Defender
Modul za rad s MongoDB bazom podataka
"""

# Osnovne funkcije za konekciju
from .connection import get_mongodb_connection, close_mongodb_connection

# Uvoz funkcija za rad s podacima prometa
from .data_aggregator import (
    store_packet,
    store_packets_batch,
    aggregate_traffic_data,
    store_aggregated_data,
    get_recent_aggregated_data,
    extract_features_for_ddqn,
    get_attack_statistics
)

# Uvoz funkcija za rad s događajima napada
from .attack_events import (
    store_attack_event,
    update_attack_event,
    get_attack_events,
    calculate_attack_statistics
)

# Uvoz funkcija za rad s upozorenjima
from .alerts import (
    store_alert,
    update_alert,
    get_alerts,
    mark_alert_as_read,
    mark_alert_as_resolved,
    get_alert_statistics
)

# Uvoz funkcija za rad s dataset-ima
from .datasets import (
    store_dataset_metadata,
    store_training_episode,
    store_test_episode,
    get_training_episodes,
    get_test_episodes,
    get_dataset_statistics
)