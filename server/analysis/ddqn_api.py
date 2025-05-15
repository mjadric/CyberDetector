#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDQN API integration module for DDoS detection and mitigation.
This module connects the DDQN implementation with MongoDB data sources.
"""

import os
import sys
import json
import time
import random
from datetime import datetime, timedelta
import numpy as np
from pymongo import MongoClient
from collections import deque

# Import DDQN implementation
from .ddqn import DDQNAgent, normalize_state, get_reward, create_mitigation_action

# MongoDB connection settings
MONGO_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017')
DB_NAME = 'ddos_defender'
TRAFFIC_COLLECTION = 'network_traffic'
ALERTS_COLLECTION = 'alerts'
ATTACK_EVENTS_COLLECTION = 'attack_events'

# DDQN Agent global instance
agent = None
model_path = os.path.join(os.path.dirname(__file__), "ddqn_weights.h5")

def get_mongo_connection():
    """
    Establish MongoDB connection
    
    Returns:
        tuple: (client, db) MongoDB client and database objects
    """
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        # Test connection
        client.server_info()
        return client, db
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        return None, None

def init_ddqn_agent():
    """
    Initialize DDQN agent and load weights if available
    
    Returns:
        DDQNAgent: Initialized DDQN agent
    """
    global agent
    if agent is None:
        # Create agent with parameters matching our feature vector
        agent = DDQNAgent(state_size=8, action_size=4)
        
        # Load saved weights if they exist
        if os.path.exists(model_path):
            try:
                agent.load(model_path)
                print(f"Loaded DDQN model from {model_path}")
            except Exception as e:
                print(f"Error loading DDQN model: {e}")
    
    return agent

def extract_features_from_traffic(traffic_data):
    """
    Extract features from traffic data for DDQN input
    
    Args:
        traffic_data (dict): Traffic data document from MongoDB
        
    Returns:
        list: Feature vector for DDQN input
    """
    # Default zero values
    features = [0.0] * 8
    
    try:
        # Source IP entropy (from Shannon entropy calculation)
        features[0] = traffic_data.get('source_entropy', 0.0)
        
        # Destination IP entropy
        features[1] = traffic_data.get('destination_entropy', 0.0)
        
        # SYN packet ratio
        features[2] = traffic_data.get('syn_ratio', 0.0)
        
        # Traffic volume (packets per second)
        features[3] = traffic_data.get('traffic_volume', 0.0)
        
        # Packet rate
        features[4] = traffic_data.get('packet_rate', 0.0)
        
        # Unique source IPs count
        features[5] = traffic_data.get('unique_src_ips', 0.0)
        
        # Unique destination IPs count
        features[6] = traffic_data.get('unique_dst_ips', 0.0)
        
        # Protocol distribution imbalance
        features[7] = traffic_data.get('protocol_distribution', 0.0)
        
        # Normalize features
        return normalize_state(features)
    except Exception as e:
        print(f"Error extracting features: {e}")
        return normalize_state(features)

def get_training_data(batch_size=100):
    """
    Get training data from MongoDB
    
    Args:
        batch_size (int): Number of samples to retrieve
        
    Returns:
        list: List of (state, is_attack) tuples for training
    """
    client, db = get_mongo_connection()
    if not client or not db:
        # Generate some synthetic data if MongoDB is unavailable
        return [(normalize_state([random.random() for _ in range(8)]), bool(random.getrandbits(1))) 
                for _ in range(batch_size)]
    
    try:
        # Get traffic data
        traffic_collection = db[TRAFFIC_COLLECTION]
        attack_collection = db[ATTACK_EVENTS_COLLECTION]
        
        # Get traffic samples
        traffic_samples = list(traffic_collection.find().sort('timestamp', -1).limit(batch_size))
        
        # Get attack timestamps
        attack_timestamps = {attack['start_time']: attack['end_time'] 
                             for attack in attack_collection.find()}
        
        # Create training data
        training_data = []
        for traffic in traffic_samples:
            features = extract_features_from_traffic(traffic)
            
            # Check if this traffic timestamp falls within an attack period
            timestamp = traffic.get('timestamp', datetime.now())
            is_attack = any(start <= timestamp <= end 
                           for start, end in attack_timestamps.items())
            
            training_data.append((features, is_attack))
        
        client.close()
        return training_data
    
    except Exception as e:
        print(f"Error getting training data: {e}")
        if client:
            client.close()
        # Return synthetic data as fallback
        return [(normalize_state([random.random() for _ in range(8)]), bool(random.getrandbits(1))) 
                for _ in range(batch_size)]

def train_ddqn_model(episodes=10, batch_size=32, save_model=True):
    """
    Train the DDQN model with data from MongoDB
    
    Args:
        episodes (int): Number of training episodes
        batch_size (int): Batch size for DDQN replay
        save_model (bool): Whether to save the model after training
        
    Returns:
        dict: Training results
    """
    agent = init_ddqn_agent()
    
    # Get training data
    training_data = get_training_data(batch_size=max(episodes * 10, 100))
    if not training_data:
        return {"error": "No training data available"}
    
    total_rewards = 0
    losses = []
    
    # Training loop
    for episode in range(episodes):
        # Reset episode state
        episode_reward = 0
        
        # Create a sequence of state transitions from the training data
        for i in range(len(training_data) - 1):
            state, is_attack = training_data[i]
            next_state, next_is_attack = training_data[i + 1]
            
            # Get action from DDQN agent
            action = agent.act(state)
            
            # Calculate reward based on action and attack status
            reward = get_reward(state, action, next_state, is_attack)
            episode_reward += reward
            
            # Remember the experience
            done = (i == len(training_data) - 2)  # Last step in episode
            agent.remember(state, action, reward, next_state, done)
            
            # Train the model
            if len(agent.memory) > batch_size:
                loss = agent.replay(batch_size)
                losses.append(loss)
        
        total_rewards += episode_reward
        print(f"Episode {episode+1}/{episodes}, Reward: {episode_reward:.2f}, "
              f"Epsilon: {agent.epsilon:.4f}")
    
    # Save the trained model
    if save_model:
        agent.save(model_path)
    
    # Return training results
    return {
        "success": True,
        "episodes": episodes,
        "total_reward": float(total_rewards),
        "final_epsilon": float(agent.epsilon),
        "avg_loss": float(np.mean(losses)) if losses else 0,
        "model_saved": save_model
    }

def predict_ddqn_action(state=None):
    """
    Predict action using DDQN agent
    
    Args:
        state (list, optional): State vector. If None, gets latest data from MongoDB.
        
    Returns:
        dict: Prediction results with action details
    """
    agent = init_ddqn_agent()
    
    # If state is not provided, get latest traffic data from MongoDB
    if state is None:
        client, db = get_mongo_connection()
        if client and db:
            try:
                traffic_collection = db[TRAFFIC_COLLECTION]
                latest_traffic = traffic_collection.find_one(sort=[('timestamp', -1)])
                if latest_traffic:
                    state = extract_features_from_traffic(latest_traffic)
                client.close()
            except Exception as e:
                print(f"Error getting latest traffic data: {e}")
                if client:
                    client.close()
    
    # Use default state if none could be obtained
    if state is None:
        state = normalize_state([0.5] * 8)
    
    # Get prediction from DDQN agent
    action = agent.act(state)
    
    # Create human-readable mitigation action
    mitigation = create_mitigation_action(action)
    
    # Return prediction results
    return {
        "success": True,
        "state": state.tolist() if isinstance(state, np.ndarray) else state,
        "action": int(action),
        "mitigation": mitigation,
        "confidence": float(1.0 - agent.epsilon),
        "timestamp": datetime.now().isoformat()
    }

def save_alert_to_mongodb(alert_data):
    """
    Save alert to MongoDB
    
    Args:
        alert_data (dict): Alert data to save
        
    Returns:
        bool: Whether the save was successful
    """
    client, db = get_mongo_connection()
    if not client or not db:
        return False
    
    try:
        alerts_collection = db[ALERTS_COLLECTION]
        
        # Add timestamp if not present
        if 'timestamp' not in alert_data:
            alert_data['timestamp'] = datetime.now()
        
        # Insert alert
        result = alerts_collection.insert_one(alert_data)
        
        client.close()
        return result.acknowledged
    except Exception as e:
        print(f"Error saving alert to MongoDB: {e}")
        if client:
            client.close()
        return False

# Initialize agent when module is loaded
init_ddqn_agent()