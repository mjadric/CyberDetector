"""
DDQN API integration module for DDoS detection and mitigation.
This module connects the DDQN implementation with MongoDB data sources.
Supports hybrid training with both real and synthetic data.
"""

import os
import random
import time
import json
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add the parent directory to sys.path
parent_dir = str(Path(__file__).resolve().parent.parent)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# Try to import MongoDB
try:
    from pymongo import MongoClient
    MONGO_AVAILABLE = True
    print("MongoDB support is available in DDQN API")
except ImportError:
    MONGO_AVAILABLE = False
    print("Warning: MongoDB not available in DDQN API module")

from analysis.ddqn import DDQNAgent, normalize_state, create_mitigation_action

# Try to import NumPy
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: NumPy not available in DDQN API module")

def get_mongo_connection():
    """
    Establish MongoDB connection
    
    Returns:
        tuple: (client, db) MongoDB client and database objects
    """
    if not MONGO_AVAILABLE:
        print("MongoDB client not available")
        return None, None
        
    try:
        mongo_uri = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017')
        client = MongoClient(mongo_uri)
        db = client.get_database('ddos_defender')
        return client, db
    except Exception as e:
        print(f"Error connecting to MongoDB in DDQN API: {e}")
        return None, None

def init_ddqn_agent():
    """
    Initialize DDQN agent and load weights if available
    
    Returns:
        DDQNAgent: Initialized DDQN agent
    """
    try:
        # Define model parameters
        state_size = 8  # Number of network traffic features we're tracking
        action_size = 4  # Number of actions the agent can take
        
        # Initialize the DDQN agent
        agent = DDQNAgent(
            state_size=state_size,
            action_size=action_size,
            memory_size=10000,
            gamma=0.95,
            epsilon=0.1,  # Lower epsilon for production use
            epsilon_min=0.01,
            epsilon_decay=0.995,
            learning_rate=0.001
        )
        
        # Try to load existing model weights
        model_path = os.path.join(parent_dir, 'models', 'ddqn_model.h5')
        if os.path.exists(model_path):
            try:
                agent.load(model_path)
                print("Loaded existing DDQN model weights")
            except Exception as load_error:
                print(f"Error loading model weights: {load_error}")
        
        return agent
    except Exception as e:
        print(f"Error initializing DDQN agent: {e}")
        return None

def extract_features_from_traffic(traffic_data):
    """
    Extract features from traffic data for DDQN input
    
    Args:
        traffic_data (dict): Traffic data document from MongoDB
        
    Returns:
        list: Feature vector for DDQN input
    """
    try:
        # Extract the features we need
        features = [
            traffic_data.get('source_entropy', 0.5),
            traffic_data.get('destination_entropy', 0.5),
            traffic_data.get('syn_ratio', 0.5),
            traffic_data.get('traffic_volume', 0.5),
            traffic_data.get('packet_rate', 0.5),
            traffic_data.get('unique_src_ips', 0.5),
            traffic_data.get('unique_dst_ips', 0.5),
            traffic_data.get('protocol_distribution', 0.5)
        ]
        
        # Normalize the features
        return normalize_state(features)
    except Exception as e:
        print(f"Error extracting features: {e}")
        return [0.5] * 8  # Return default features on error

def generate_synthetic_normal_traffic():
    """
    Generate synthetic normal traffic data
    
    Returns:
        dict: Synthetic normal traffic data
    """
    return {
        "source_entropy": random.uniform(0.4, 0.6),
        "destination_entropy": random.uniform(0.4, 0.6),
        "syn_ratio": random.uniform(0.2, 0.4),
        "traffic_volume": random.uniform(0.3, 0.7),
        "packet_rate": random.uniform(0.3, 0.6),
        "unique_src_ips": random.uniform(0.5, 0.7),
        "unique_dst_ips": random.uniform(0.4, 0.6),
        "protocol_distribution": random.uniform(0.4, 0.6),
        "is_attack": False,
        "synthetic": True
    }

def generate_synthetic_attack_traffic():
    """
    Generate synthetic attack traffic data
    
    Returns:
        dict: Synthetic attack traffic data
    """
    # Choose randomly between different attack types
    attack_type = random.choice([
        "SYN Flood", "UDP Flood", "ICMP Flood", "HTTP Flood", 
        "DNS Amplification", "NTP Amplification"
    ])
    
    # Generate different feature patterns based on attack type
    if attack_type == "SYN Flood":
        return {
            "source_entropy": random.uniform(0.7, 0.9),
            "destination_entropy": random.uniform(0.1, 0.3),
            "syn_ratio": random.uniform(0.8, 0.95),
            "traffic_volume": random.uniform(0.7, 0.9),
            "packet_rate": random.uniform(0.8, 0.95),
            "unique_src_ips": random.uniform(0.7, 0.9),
            "unique_dst_ips": random.uniform(0.1, 0.3),
            "protocol_distribution": random.uniform(0.7, 0.9),
            "is_attack": True,
            "attack_type": attack_type,
            "synthetic": True
        }
    elif attack_type == "UDP Flood":
        return {
            "source_entropy": random.uniform(0.7, 0.9),
            "destination_entropy": random.uniform(0.1, 0.3),
            "syn_ratio": random.uniform(0.1, 0.3),
            "traffic_volume": random.uniform(0.8, 0.95),
            "packet_rate": random.uniform(0.8, 0.95),
            "unique_src_ips": random.uniform(0.5, 0.8),
            "unique_dst_ips": random.uniform(0.1, 0.3),
            "protocol_distribution": random.uniform(0.7, 0.9),
            "is_attack": True,
            "attack_type": attack_type,
            "synthetic": True
        }
    else:
        # Generic pattern for other attack types
        return {
            "source_entropy": random.uniform(0.7, 0.9),
            "destination_entropy": random.uniform(0.1, 0.3),
            "syn_ratio": random.uniform(0.5, 0.8),
            "traffic_volume": random.uniform(0.8, 1.0),
            "packet_rate": random.uniform(0.8, 1.0),
            "unique_src_ips": random.uniform(0.1, 0.5),
            "unique_dst_ips": random.uniform(0.1, 0.3),
            "protocol_distribution": random.uniform(0.7, 0.9),
            "is_attack": True,
            "attack_type": attack_type,
            "synthetic": True
        }

def get_training_data(batch_size=100, synthetic_ratio=0.5):
    """
    Get training data from MongoDB with option for hybrid approach
    
    Args:
        batch_size (int): Number of samples to retrieve
        synthetic_ratio (float): Ratio of synthetic data to include (0.0-1.0)
        
    Returns:
        list: List of (state, is_attack) tuples for training
    """
    try:
        # Determine how many real vs synthetic samples to use
        real_samples = int(batch_size * (1 - synthetic_ratio))
        synthetic_samples = batch_size - real_samples
        
        # Initialize empty lists for data
        real_data = []
        synthetic_data = []
        
        # Try to get real data from MongoDB if available
        if real_samples > 0 and MONGO_AVAILABLE:
            client, db = get_mongo_connection()
            if client and db:
                try:
                    # Get a mix of normal and attack traffic
                    normal_traffic = list(db.network_traffic.aggregate([
                        {"$match": {"is_attack": False}},
                        {"$sample": {"size": real_samples // 2}}
                    ]))
                    
                    attack_traffic = list(db.network_traffic.aggregate([
                        {"$match": {"is_attack": True}},
                        {"$sample": {"size": real_samples // 2}}
                    ]))
                    
                    # Combine real data
                    real_data = normal_traffic + attack_traffic
                    
                    client.close()
                except Exception as mongo_error:
                    print(f"Error fetching training data from MongoDB: {mongo_error}")
        
        # Calculate how many synthetic samples we still need
        synthetic_needed = batch_size - len(real_data)
        
        # Generate synthetic data as needed
        if synthetic_needed > 0:
            # Split evenly between normal and attack patterns
            for _ in range(synthetic_needed // 2):
                synthetic_data.append(generate_synthetic_normal_traffic())
                
            for _ in range(synthetic_needed - (synthetic_needed // 2)):
                synthetic_data.append(generate_synthetic_attack_traffic())
        
        # Combine and shuffle all data
        combined_data = real_data + synthetic_data
        random.shuffle(combined_data)
        
        # Convert to training data format (state, is_attack)
        training_data = []
        for traffic in combined_data:
            state = extract_features_from_traffic(traffic)
            is_attack = traffic.get('is_attack', False)
            training_data.append((state, is_attack))
        
        print(f"Generated training batch: {len(real_data)} real samples, {len(synthetic_data)} synthetic samples")
        return training_data
        
    except Exception as e:
        print(f"Error getting training data: {e}")
        # Return fully synthetic data as a fallback
        return [(normalize_state([random.random() for _ in range(8)]), 
                random.choice([True, False, False, False])) 
                for _ in range(batch_size)]

def train_ddqn_model(episodes=10, batch_size=32, save_model=True, synthetic_ratio=0.5):
    """
    Train the DDQN model with hybrid approach (real + synthetic data)
    
    Args:
        episodes (int): Number of training episodes
        batch_size (int): Batch size for DDQN replay
        save_model (bool): Whether to save the model after training
        synthetic_ratio (float): Ratio of synthetic data to use (0.0-1.0)
        
    Returns:
        dict: Training results
    """
    try:
        agent = init_ddqn_agent()
        if not agent:
            return {"success": False, "error": "Failed to initialize DDQN agent"}
        
        training_results = {
            "episodes": episodes,
            "losses": [],
            "rewards": [],
            "actions": [],
            "synthetic_ratio": synthetic_ratio
        }
        
        print(f"Starting hybrid DDQN training with {episodes} episodes, {synthetic_ratio*100}% synthetic data")
        
        for episode in range(episodes):
            episode_rewards = []
            episode_losses = []
            episode_actions = []
            
            # Get training data for this episode - mix of real and synthetic
            training_data = get_training_data(batch_size, synthetic_ratio)
            
            for state, is_attack in training_data:
                # Get the agent's action
                action = agent.act(state)
                
                # Advanced reward function that considers confidence and action type
                # True positive: correctly detecting attack
                if action > 0 and is_attack:
                    # Higher reward for stronger action when attack is present
                    # Scale from 0.5 to 1.0 based on action intensity
                    reward = 0.5 + (action / 6.0)
                # True negative: correctly taking no action on normal traffic
                elif action == 0 and not is_attack:
                    reward = 1.0
                # False positive: taking action when no attack (worse than false negative)
                elif action > 0 and not is_attack:
                    # Penalty scales with how aggressive the action is
                    reward = -0.5 - (action / 6.0)
                # False negative: not detecting actual attack
                else:  # action == 0 and is_attack
                    reward = -0.7
                
                # Next state is the same for now (can be improved for sequential learning)
                next_state = state
                
                # Store the experience in the agent's memory
                agent.remember(state, action, reward, next_state, False)
                
                # Train the agent
                if len(agent.memory) > batch_size:
                    loss = agent.replay(batch_size)
                    episode_losses.append(loss)
                
                episode_rewards.append(reward)
                episode_actions.append(action)
            
            # Update the target model periodically
            agent.update_target_model()
            
            # Record results for this episode
            avg_loss = sum(episode_losses) / len(episode_losses) if episode_losses else 0
            avg_reward = sum(episode_rewards) / len(episode_rewards) if episode_rewards else 0
            
            training_results["losses"].append(avg_loss)
            training_results["rewards"].append(avg_reward)
            training_results["actions"].append(episode_actions)
            
            print(f"Episode {episode+1}/{episodes}, Avg Loss: {avg_loss:.4f}, Avg Reward: {avg_reward:.4f}")
        
        # Save the model if requested
        if save_model:
            model_dir = os.path.join(parent_dir, 'models')
            os.makedirs(model_dir, exist_ok=True)
            model_path = os.path.join(model_dir, 'ddqn_model.h5')
            agent.save(model_path)
            print(f"Saved trained model to {model_path}")
        
        return {
            "success": True,
            "results": training_results,
            "message": f"Successfully trained DDQN model with {episodes} episodes using hybrid approach"
        }
        
    except Exception as e:
        print(f"Error in DDQN training: {e}")
        return {"success": False, "error": str(e)}

def predict_ddqn_action(state=None):
    """
    Predict action using DDQN agent
    
    Args:
        state (list, optional): State vector. If None, gets latest data from MongoDB.
        
    Returns:
        dict: Prediction results with action details
    """
    try:
        agent = init_ddqn_agent()
        if not agent:
            return {"success": False, "error": "Failed to initialize DDQN agent"}
        
        if state is None:
            # Get the latest traffic data from MongoDB if available
            if MONGO_AVAILABLE:
                client, db = get_mongo_connection()
                if client and db:
                    try:
                        # Get the most recent traffic data
                        latest_traffic = db.network_traffic.find_one(
                            sort=[("timestamp", -1)]
                        )
                        
                        if latest_traffic:
                            state = extract_features_from_traffic(latest_traffic)
                            print("Using latest traffic data from MongoDB for prediction")
                        else:
                            state = [random.random() for _ in range(8)]
                            print("No traffic data found in MongoDB, using random state")
                        
                        client.close()
                    except Exception as mongo_error:
                        print(f"Error getting latest traffic from MongoDB: {mongo_error}")
                        state = [random.random() for _ in range(8)]
                else:
                    print("MongoDB connection failed, using random state")
                    state = [random.random() for _ in range(8)]
            else:
                print("MongoDB not available, using random state")
                state = [random.random() for _ in range(8)]
        
        # Normalize state
        normalized_state = normalize_state(state)
        
        # Get action from the agent
        action_index = agent.act(normalized_state)
        
        # Convert action to human-readable format
        mitigation_action = create_mitigation_action(action_index)
        
        # Calculate the confidence level using Q-values if available
        if hasattr(agent, 'policy_model') and hasattr(agent.policy_model, 'predict'):
            try:
                q_values = agent.policy_model.predict(
                    normalized_state.reshape(1, -1), verbose=0)[0]
                confidence = float(q_values[action_index] / max(1.0, abs(q_values.max())))
                q_values_list = q_values.tolist() if hasattr(q_values, "tolist") else q_values
            except Exception as predict_error:
                print(f"Error predicting Q-values: {predict_error}")
                confidence = 0.5
                q_values_list = [0.0] * agent.action_size
        else:
            # Fallback if model prediction is not available
            confidence = 0.5
            q_values_list = [0.0] * agent.action_size
        
        # Calculate threat score using weighted features
        feature_weights = [
            0.18,  # source_entropy
            0.12,  # destination_entropy
            0.25,  # syn_ratio
            0.15,  # traffic_volume
            0.20,  # packet_rate
            0.05,  # unique_src_ips
            0.02,  # unique_dst_ips
            0.03   # protocol_distribution
        ]
        
        weighted_state = [normalized_state[i] * feature_weights[i] for i in range(len(normalized_state))]
        threat_score = sum(weighted_state)
        
        return {
            "success": True,
            "action_index": int(action_index),
            "action": mitigation_action,
            "confidence": confidence,
            "threat_score": threat_score,
            "raw_state": state,
            "normalized_state": normalized_state.tolist() if hasattr(normalized_state, "tolist") else normalized_state,
            "q_values": q_values_list,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        print(f"Error in DDQN prediction: {e}")
        return {"success": False, "error": str(e)}

def save_alert_to_mongodb(alert_data):
    """
    Save alert to MongoDB
    
    Args:
        alert_data (dict): Alert data to save
        
    Returns:
        bool: Whether the save was successful
    """
    if not MONGO_AVAILABLE:
        print("MongoDB not available, cannot save alert")
        return False
        
    try:
        client, db = get_mongo_connection()
        if not client or not db:
            return False
        
        # Add timestamp if not present
        if "timestamp" not in alert_data:
            alert_data["timestamp"] = datetime.now()
        
        # Insert the alert
        result = db.alerts.insert_one(alert_data)
        
        # Log successful save
        print(f"Saved alert to MongoDB with ID {result.inserted_id}")
        
        client.close()
        return bool(result.inserted_id)
    except Exception as e:
        print(f"Error saving alert to MongoDB: {e}")
        return False