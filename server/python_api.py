#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Python backend API server for DDoS detection and mitigation
Integrates basic functionality with DDQN for advanced detection and mitigation
"""

import os
import json
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, request
from flask_cors import CORS

# Try to import numpy, but have fallback if it doesn't work
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: NumPy not available, using basic Python lists instead")

# Set flags for available functionality
TF_AVAILABLE = False
DDQN_AVAILABLE = False

# We'll skip TensorFlow imports for now due to compatibility issues
# This will make the API use simpler algorithms instead

# Try to import MongoDB
try:
    from pymongo import MongoClient
    MONGO_AVAILABLE = True
    print("MongoDB support is available")
except ImportError:
    MONGO_AVAILABLE = False
    print("Warning: MongoDB support not available")

print("Using basic algorithms for DDoS detection instead of TensorFlow-based DDQN")

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Helper functions with no dependencies
def normalize_state_simple(state):
    """Normalize state without NumPy"""
    max_val = max(abs(x) for x in state) if state else 1
    if max_val == 0:
        max_val = 1
    return [x / max_val for x in state]

def normalize_state(state):
    """Normalize state with NumPy if available"""
    if NUMPY_AVAILABLE:
        import numpy as np
        if not isinstance(state, np.ndarray):
            state = np.array(state)
        return state / np.max(np.abs(state)) if np.max(np.abs(state)) > 0 else state
    else:
        return normalize_state_simple(state)

def create_mitigation_action(action_index, intensity=None):
    """Create mitigation action details"""
    actions = [
        "No action needed",
        "Rate limiting",
        "Traffic filtering",
        "Connection blocking"
    ]
    action_name = actions[min(action_index, len(actions)-1)]
    return {
        "action": action_name,
        "intensity": intensity or random.uniform(0.5, 1.0),
        "description": f"Apply {action_name} to mitigate potential attack"
    }

# Mock data generators for development purposes
def generate_mock_network_topology():
    """Generate a hierarchical network topology based on the research methodology"""
    
    # Create hierarchical network topology following the documented structure:
    # - Core Layer: 1-5 central routers
    # - Distribution Layer: 3-10 switches
    # - Access Layer: 3-10 servers and 9-20 hosts
    
    # Setup core layer (routers)
    routers = [
        {"id": f"router{i+1}", "name": f"R{i+1}", "type": "router", 
         "layer": "core", "status": "active", "load": 45 + (i*10), 
         "x": 100 + (i*150), "y": 50} 
        for i in range(2)  # Using 2 core routers
    ]
    
    # Setup distribution layer (switches)
    switches = [
        {"id": f"switch{i+1}", "name": f"SW{i+1}", "type": "switch", 
         "layer": "distribution", "status": "active", "load": 30 + (i*5),
         "x": 50 + (i*100), "y": 150} 
        for i in range(4)  # Using 4 switches
    ]
    
    # Setup access layer (servers)
    server_names = ["Web", "DB", "Auth"]
    servers = [
        {"id": f"server{i+1}", "name": f"{server_names[i]}", "type": "server", 
         "layer": "access", "status": "active", "load": 60 + (i*7),
         "vulnerabilities": ["CVE-2023-1234"] if i == 1 else [],
         "x": 50 + (i*100), "y": 250} 
        for i in range(3)
    ]
    
    # Setup hosts (client machines)
    hosts = [
        {"id": f"host{i+1}", "name": f"C{i+1}", "type": "host", 
         "layer": "access", "status": "active" if i != 2 else "compromised",
         "x": 100 + (i*100), "y": 350} 
        for i in range(3)  # Using 3 hosts for simplicity in visualization
    ]
    
    # Define the network links following hierarchy: router -> switch -> server/host
    links = [
        # Router to router connections
        {"source": "router1", "target": "router2", "weight": 10, "status": "normal", "traffic": 45},
        
        # Router to switch connections
        {"source": "router1", "target": "switch1", "weight": 8, "status": "normal", "traffic": 38},
        {"source": "router1", "target": "switch2", "weight": 8, "status": "normal", "traffic": 42},
        {"source": "router2", "target": "switch3", "weight": 8, "status": "normal", "traffic": 35},
        {"source": "router2", "target": "switch4", "weight": 8, "status": "congested", "traffic": 82},
        
        # Switch to server connections
        {"source": "switch1", "target": "server1", "weight": 5, "status": "normal", "traffic": 30},
        {"source": "switch2", "target": "server2", "weight": 5, "status": "normal", "traffic": 55},
        {"source": "switch3", "target": "server3", "weight": 5, "status": "normal", "traffic": 25},
        
        # Switch to host connections
        {"source": "switch1", "target": "host1", "weight": 3, "status": "normal", "traffic": 15},
        {"source": "switch2", "target": "host2", "weight": 3, "status": "normal", "traffic": 18},
        {"source": "switch3", "target": "host3", "weight": 3, "status": "attacked", "traffic": 78}
    ]
    
    # Add additional cross-connections for redundancy and realistic topology
    additional_links = [
        {"source": "switch1", "target": "switch2", "weight": 5, "status": "normal", "traffic": 12},
        {"source": "switch3", "target": "switch4", "weight": 5, "status": "normal", "traffic": 14},
        {"source": "switch2", "target": "server3", "weight": 5, "status": "normal", "traffic": 8}
    ]
    links.extend(additional_links)
    
    # Combine all nodes
    nodes = routers + switches + servers + hosts
    
    return {
        "nodes": nodes,
        "links": links
    }

def generate_mock_vulnerability_analysis():
    """Generate mock vulnerability analysis data based on the methodology documentation"""
    return {
        # Graph theory centrality metrics
        "centrality": [
            {"name": "Degree Centrality", "value": 0.85, "description": "Measures the number of direct connections a node has"},
            {"name": "Betweenness Centrality", "value": 0.67, "description": "Measures how often a node lies on shortest paths between other nodes"},
            {"name": "Closeness Centrality", "value": 0.76, "description": "Measures how close a node is to all other nodes"}
        ],
        
        # Critical nodes based on centrality and vulnerability
        "critical_nodes": [
            {"id": "router1", "risk_score": 0.85, "vulnerabilities": [], "reason": "High centrality as core router"},
            {"id": "server2", "risk_score": 0.78, "vulnerabilities": ["CVE-2023-1234"], "reason": "Database server with known vulnerability"},
            {"id": "host3", "risk_score": 0.65, "vulnerabilities": [], "reason": "Compromised client machine"}
        ],
        
        # Attack paths analysis
        "attack_paths": [
            {
                "path": ["host3", "switch3", "router2", "router1", "switch1", "server1"], 
                "risk": "high",
                "explanation": "Critical path from compromised host to web server",
                "impact_score": 0.85
            },
            {
                "path": ["host3", "switch3", "server3"], 
                "risk": "medium",
                "explanation": "Path from compromised host to authentication server",
                "impact_score": 0.72
            },
            {
                "path": ["host3", "switch3", "switch2", "server2"], 
                "risk": "critical",
                "explanation": "Path from compromised host to vulnerable database",
                "impact_score": 0.92
            }
        ],
        
        # Community detection results
        "communities": [
            {"id": 1, "nodes": ["router1", "router2"], "description": "Core network layer"},
            {"id": 2, "nodes": ["switch1", "switch2", "server1", "server2", "host1", "host2"], "description": "Primary service cluster"},
            {"id": 3, "nodes": ["switch3", "switch4", "server3", "host3"], "description": "Secondary service cluster with compromised node"}
        ],
        
        # Overall vulnerability metrics
        "network_vulnerability_score": 0.68,
        "remediation_recommendations": [
            {"target": "server2", "action": "Patch CVE-2023-1234", "priority": "high"},
            {"target": "host3", "action": "Isolate and scan compromised machine", "priority": "critical"},
            {"target": "router1-router2", "action": "Implement redundant connection", "priority": "medium"}
        ]
    }

def generate_mock_traffic_paths():
    """Generate mock traffic paths data based on the network topology and methodology"""
    return [
        {
            "id": 1,
            "pathId": "P-001",
            "source": "host1",
            "source_ip": "192.168.1.101",
            "destination": "server1",
            "destination_ip": "10.0.0.5",
            "protocol": "HTTP",
            "port": 80,
            "hopCount": 3,
            "path": ["host1", "switch1", "router1", "server1"],
            "status": "normal",
            "traffic_volume": 2450,
            "packets_per_second": 32,
            "latency": 15,
            "bandwidth_usage": 0.35
        },
        {
            "id": 2,
            "pathId": "P-002",
            "source": "host2",
            "source_ip": "192.168.1.102",
            "destination": "server2",
            "destination_ip": "10.0.0.6",
            "protocol": "HTTPS",
            "port": 443,
            "hopCount": 4,
            "path": ["host2", "switch2", "router1", "router2", "server2"],
            "status": "normal",
            "traffic_volume": 5620,
            "packets_per_second": 47,
            "latency": 22,
            "bandwidth_usage": 0.58
        },
        {
            "id": 3,
            "pathId": "P-003",
            "source": "host3",
            "source_ip": "192.168.1.103",
            "destination": "server2",
            "destination_ip": "10.0.0.6",
            "protocol": "HTTPS",
            "port": 443,
            "hopCount": 4,
            "path": ["host3", "switch3", "router2", "server2"],
            "status": "suspicious",
            "traffic_volume": 8950,
            "packets_per_second": 124,
            "latency": 45,
            "bandwidth_usage": 0.74,
            "security_flags": ["abnormal_volume", "unusual_pattern"]
        },
        {
            "id": 4,
            "pathId": "P-004",
            "source": "host3",
            "source_ip": "192.168.1.103",
            "destination": "server1",
            "destination_ip": "10.0.0.5",
            "protocol": "HTTP",
            "port": 80,
            "hopCount": 5,
            "path": ["host3", "switch3", "router2", "router1", "switch1", "server1"],
            "status": "attack",
            "traffic_volume": 12500,
            "packets_per_second": 350,
            "latency": 78,
            "bandwidth_usage": 0.92,
            "security_flags": ["attack_signature_match", "syn_flood_pattern", "rate_limited"]
        },
        {
            "id": 5,
            "pathId": "P-005",
            "source": "host1",
            "source_ip": "192.168.1.101",
            "destination": "server3",
            "destination_ip": "10.0.0.7",
            "protocol": "LDAP",
            "port": 389,
            "hopCount": 4,
            "path": ["host1", "switch1", "switch2", "server3"],
            "status": "normal",
            "traffic_volume": 980,
            "packets_per_second": 12,
            "latency": 18,
            "bandwidth_usage": 0.22
        }
    ]

def generate_mock_analysis_data():
    """Generate comprehensive analysis data for API response"""
    # Get the current time
    now = datetime.now()
    
    # Generate time labels for the last 24 hours
    hour_labels = [(now - timedelta(hours=i)).strftime("%H:00") for i in range(24)]
    hour_labels.reverse()  # Make chronological
    
    return {
        "traffic_summary": {
            "total_packets": random.randint(100000, 500000),
            "packet_rate": random.randint(500, 2000),
            "unique_ips": random.randint(50, 200),
            "attack_confidence": random.uniform(0, 1)
        },
        "protocol_distribution": [
            {"protocol": "TCP", "percentage": 60},
            {"protocol": "UDP", "percentage": 25},
            {"protocol": "ICMP", "percentage": 10},
            {"protocol": "Other", "percentage": 5}
        ],
        "traffic_patterns": {
            "labels": hour_labels,
            "values": [random.randint(50, 200) for _ in range(24)]
        },
        "entropy_data": {
            "labels": hour_labels,
            "values": [random.uniform(0.1, 0.9) for _ in range(24)]
        },
        "feature_importance": {
            "labels": ["SYN Ratio", "Packet Rate", "Entropy", "Source IP Diversity", "TTL Variance"],
            "values": [0.35, 0.25, 0.2, 0.15, 0.05]
        },
        "attack_classification": [
            {"attackType": "TCP SYN Flood", "confidence": 0.85, "count": random.randint(10, 50)},
            {"attackType": "UDP Flood", "confidence": 0.65, "count": random.randint(5, 30)},
            {"attackType": "ICMP Flood", "confidence": 0.45, "count": random.randint(2, 20)},
            {"attackType": "HTTP Flood", "confidence": 0.75, "count": random.randint(8, 40)}
        ]
    }

# API routes
@app.route('/api/python/status', methods=['GET'])
def get_status():
    """Return the status of the Python API server"""
    return jsonify({
        "status": "online",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "features": {
            "numpy": NUMPY_AVAILABLE,
            "flask": True
        }
    })

@app.route('/api/python/analysis', methods=['GET'])
def get_analysis():
    """Return comprehensive analysis data"""
    try:
        analysis_data = generate_mock_analysis_data()
        return jsonify(analysis_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/python/topology', methods=['GET'])
def get_topology():
    """Return network topology data"""
    try:
        topology = generate_mock_network_topology()
        return jsonify(topology)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/python/vulnerability', methods=['GET'])
def get_vulnerability():
    """Return vulnerability analysis data"""
    try:
        vulnerability = generate_mock_vulnerability_analysis()
        return jsonify(vulnerability)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/python/traffic-paths', methods=['GET'])
def get_traffic_paths():
    """Return traffic paths data"""
    try:
        paths = generate_mock_traffic_paths()
        return jsonify(paths)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/python/train', methods=['POST'])
def train_model():
    """Train the DDQN model with a hybrid approach"""
    try:
        data = request.json or {}
        episodes = data.get('episodes', 10)
        batch_size = data.get('batch_size', 32)
        synthetic_ratio = data.get('synthetic_ratio', 0.5)
        
        # Import the training function from ddqn_api
        try:
            from analysis.ddqn_api import train_ddqn_model
            result = train_ddqn_model(
                episodes=episodes,
                batch_size=batch_size,
                save_model=True,
                synthetic_ratio=synthetic_ratio
            )
            return jsonify(result)
        except ImportError as e:
            # If the import fails, use the basic approach
            print(f"Error importing DDQN API: {e}")
            return jsonify({
                "success": False,
                "message": "DDQN module not available, consider using the algorithmic approach instead"
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/python/mitigate', methods=['POST'])
def mitigate_attack():
    """Take mitigation action against an attack"""
    try:
        data = request.json or {}
        state = data.get('state', [0.5] * 8)  # Default state if none provided
        normalized_state = normalize_state(state)
        
        # Calculate threat score based on state features
        # These are algorithmic weights for different network features
        feature_weights = [
            0.18,  # source_entropy
            0.12,  # destination_entropy
            0.25,  # syn_ratio
            0.15,  # traffic_volume
            0.20,  # packet_rate
            0.05,  # unique_src_ips_count
            0.02,  # unique_dst_ips_count
            0.03   # protocol_distribution
        ]
        
        # Calculate weighted score
        weighted_state = [normalized_state[i] * feature_weights[i] for i in range(len(normalized_state))]
        threat_score = sum(weighted_state)
        
        # Decision logic for action selection
        if threat_score > 0.7:
            action = 2  # Block IP
        elif threat_score > 0.5:
            action = 1  # Rate limit
        elif threat_score > 0.3:
            action = 3  # Filter
        else:
            action = 0  # Monitor
            
        # Create human-readable mitigation action details
        mitigation = create_mitigation_action(action)
        
        # Calculate confidence based on how close to thresholds
        confidence = min(max((threat_score - 0.3) / 0.7, 0.1), 0.95)
        
        # Create alert in MongoDB if we're detecting an attack
        if action > 0:
            # Only try to use MongoDB if it's available
            if MONGO_AVAILABLE:
                try:
                    # Using the MongoDB client directly
                    client = MongoClient(os.environ.get('MONGODB_URI', 'mongodb://localhost:27017'))
                    db = client.get_database('ddos_defender')
                    alerts_collection = db.get_collection('alerts')
                    
                    # Save alert data
                    alert_data = {
                        "timestamp": datetime.now(),
                        "type": "Algorithmic Detection",
                        "severity": "High" if action > 1 else "Medium",
                        "message": f"Detected potential attack, action: {mitigation['name']}",
                        "source_ips": data.get("source_ips", []),
                        "confidence": confidence,
                        "threat_score": threat_score
                    }
                    alerts_collection.insert_one(alert_data)
                    client.close()
                except Exception as mongo_error:
                    print(f"Error saving alert to MongoDB: {mongo_error}")
            else:
                print("MongoDB not available, skipping alert creation")
        
        # Return mitigation result
        return jsonify({
            "success": True,
            "action": action,
            "mitigation": mitigation,
            "state": normalized_state if isinstance(normalized_state, list) else normalized_state.tolist(),
            "confidence": confidence,
            "threat_score": threat_score,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

class NetworkTrafficSimulator:
    """
    Sophisticated network traffic simulator for generating realistic traffic patterns
    and attack scenarios for testing detection algorithms.
    """
    
    def __init__(self):
        self.traffic_patterns = {
            "normal": {
                "source_entropy": (0.4, 0.6),      # Lower entropy - fewer source IPs
                "destination_entropy": (0.4, 0.6),  # Lower entropy - consistent destinations
                "syn_ratio": (0.1, 0.3),           # Normal SYN ratio
                "traffic_volume": (0.3, 0.7),      # Moderate traffic volume
                "packet_rate": (0.3, 0.6),         # Moderate packet rate
                "unique_src_ips": (0.3, 0.6),      # Moderate number of source IPs
                "unique_dst_ips": (0.4, 0.7),      # Moderate number of destination IPs
                "protocol_distribution": {
                    "TCP": (0.5, 0.7),
                    "UDP": (0.2, 0.3),
                    "ICMP": (0.05, 0.1),
                    "HTTP": (0.1, 0.2),
                    "HTTPS": (0.05, 0.1)
                }
            },
            "syn_flood": {
                "source_entropy": (0.7, 0.9),      # Higher entropy - many random source IPs
                "destination_entropy": (0.1, 0.3),  # Lower entropy - targeted destinations
                "syn_ratio": (0.7, 0.9),           # Very high SYN ratio
                "traffic_volume": (0.7, 0.9),      # High traffic volume
                "packet_rate": (0.8, 0.95),        # Very high packet rate
                "unique_src_ips": (0.7, 0.9),      # Many source IPs (spoofed)
                "unique_dst_ips": (0.1, 0.3),      # Few destination IPs (targets)
                "protocol_distribution": {
                    "TCP": (0.8, 0.95),
                    "UDP": (0.05, 0.1),
                    "ICMP": (0.0, 0.05),
                    "HTTP": (0.0, 0.05),
                    "HTTPS": (0.0, 0.05)
                }
            },
            "udp_flood": {
                "source_entropy": (0.7, 0.9),      # Higher entropy - many source IPs
                "destination_entropy": (0.1, 0.3),  # Lower entropy - targeted destinations
                "syn_ratio": (0.1, 0.2),           # Low SYN ratio (UDP doesn't use SYN)
                "traffic_volume": (0.8, 0.95),     # Very high traffic volume
                "packet_rate": (0.8, 0.95),        # Very high packet rate
                "unique_src_ips": (0.6, 0.8),      # Many source IPs (spoofed)
                "unique_dst_ips": (0.1, 0.3),      # Few destination IPs (targets)
                "protocol_distribution": {
                    "TCP": (0.0, 0.1),
                    "UDP": (0.8, 0.95),
                    "ICMP": (0.0, 0.05),
                    "HTTP": (0.0, 0.05),
                    "HTTPS": (0.0, 0.05)
                }
            },
            "http_flood": {
                "source_entropy": (0.5, 0.7),      # Moderate source entropy
                "destination_entropy": (0.1, 0.3),  # Lower entropy - targeted web servers
                "syn_ratio": (0.3, 0.5),           # Moderate SYN ratio (HTTP uses TCP)
                "traffic_volume": (0.6, 0.9),      # High traffic volume
                "packet_rate": (0.6, 0.8),         # High packet rate
                "unique_src_ips": (0.4, 0.7),      # Moderate number of source IPs
                "unique_dst_ips": (0.1, 0.3),      # Few destination IPs (web servers)
                "protocol_distribution": {
                    "TCP": (0.2, 0.4),
                    "UDP": (0.0, 0.1),
                    "ICMP": (0.0, 0.05),
                    "HTTP": (0.5, 0.7),
                    "HTTPS": (0.1, 0.2)
                }
            },
            "slowloris": {
                "source_entropy": (0.3, 0.5),      # Lower entropy - fewer sources
                "destination_entropy": (0.1, 0.2),  # Very targeted - specific web servers
                "syn_ratio": (0.2, 0.4),           # Moderate SYN ratio
                "traffic_volume": (0.2, 0.4),      # Lower traffic volume
                "packet_rate": (0.2, 0.4),         # Lower packet rate (slow!)
                "unique_src_ips": (0.2, 0.4),      # Fewer source IPs
                "unique_dst_ips": (0.1, 0.2),      # Very few destination IPs
                "protocol_distribution": {
                    "TCP": (0.3, 0.5),
                    "UDP": (0.0, 0.1),
                    "ICMP": (0.0, 0.05),
                    "HTTP": (0.4, 0.6),
                    "HTTPS": (0.1, 0.2)
                }
            },
            "dns_amplification": {
                "source_entropy": (0.2, 0.4),      # Lower entropy - spoofed source IPs
                "destination_entropy": (0.1, 0.3),  # Lower entropy - targeted victims
                "syn_ratio": (0.1, 0.2),           # Low SYN ratio (UDP doesn't use SYN)
                "traffic_volume": (0.7, 0.9),      # High traffic volume
                "packet_rate": (0.6, 0.8),         # High packet rate
                "unique_src_ips": (0.1, 0.3),      # Few source IPs (DNS servers)
                "unique_dst_ips": (0.1, 0.2),      # Very few destination IPs (victims)
                "protocol_distribution": {
                    "TCP": (0.0, 0.1),
                    "UDP": (0.8, 0.95),
                    "ICMP": (0.0, 0.05),
                    "HTTP": (0.0, 0.05),
                    "HTTPS": (0.0, 0.05)
                }
            }
        }
    
    def generate_traffic_state(self, traffic_type="normal", intensity=0.5):
        """
        Generate network traffic state based on specified pattern type and intensity
        
        Args:
            traffic_type (str): Type of traffic pattern (normal, syn_flood, etc.)
            intensity (float): Intensity factor (0.0-1.0) to adjust pattern strength
            
        Returns:
            dict: Traffic state parameters
        """
        # Default to normal traffic if type not found
        if traffic_type not in self.traffic_patterns:
            traffic_type = "normal"
            
        pattern = self.traffic_patterns[traffic_type]
        
        # Generate state with values adjusted by intensity
        state = {}
        for key, (min_val, max_val) in pattern.items():
            if key != "protocol_distribution":
                # Scale based on intensity
                if traffic_type == "normal":
                    # For normal traffic, intensity doesn't amplify
                    state[key] = random.uniform(min_val, max_val)
                else:
                    # For attack traffic, higher intensity means values closer to max
                    range_size = max_val - min_val
                    adjusted_min = min_val + (range_size * (1 - intensity) * 0.5)
                    adjusted_max = max_val - (range_size * (1 - intensity) * 0.5)
                    state[key] = random.uniform(adjusted_min, adjusted_max)
        
        # Generate protocol distribution
        protocols = {}
        for protocol, (min_val, max_val) in pattern["protocol_distribution"].items():
            if traffic_type == "normal":
                protocols[protocol] = random.uniform(min_val, max_val)
            else:
                range_size = max_val - min_val
                adjusted_min = min_val + (range_size * (1 - intensity) * 0.5)
                adjusted_max = max_val - (range_size * (1 - intensity) * 0.5)
                protocols[protocol] = random.uniform(adjusted_min, adjusted_max)
        
        # Normalize protocol distribution to sum to 1.0
        total = sum(protocols.values())
        if total > 0:
            for protocol in protocols:
                protocols[protocol] /= total
                
        state["protocol_distribution"] = protocols
        state["traffic_type"] = traffic_type
        state["intensity"] = intensity
        state["timestamp"] = datetime.now().isoformat()
        
        return state
    
    def generate_traffic_features(self, traffic_type="normal", intensity=0.5):
        """
        Generate feature vector for DDQN input based on traffic type
        
        Args:
            traffic_type (str): Type of traffic pattern
            intensity (float): Intensity factor
            
        Returns:
            list: Feature vector for DDQN input
        """
        state = self.generate_traffic_state(traffic_type, intensity)
        
        # Extract the 8 features used by DDQN in order
        features = [
            state.get("source_entropy", 0.5),
            state.get("destination_entropy", 0.5),
            state.get("syn_ratio", 0.5),
            state.get("traffic_volume", 0.5),
            state.get("packet_rate", 0.5),
            state.get("unique_src_ips", 0.5),
            state.get("unique_dst_ips", 0.5),
            # Calculate a single value for protocol distribution imbalance
            sum(abs(v - 0.2) for v in state.get("protocol_distribution", {}).values()) / 5.0
        ]
        
        return features
    
    def generate_training_data(self, num_samples=100, attack_ratio=0.5):
        """
        Generate mixed training data with normal and attack traffic
        
        Args:
            num_samples (int): Number of samples to generate
            attack_ratio (float): Ratio of attack samples (0.0-1.0)
            
        Returns:
            list: List of (features, is_attack) tuples
        """
        samples = []
        
        # Calculate number of attack samples
        num_attack = int(num_samples * attack_ratio)
        num_normal = num_samples - num_attack
        
        # Generate normal traffic samples
        for _ in range(num_normal):
            features = self.generate_traffic_features("normal", random.uniform(0.3, 0.7))
            samples.append((features, False))
        
        # Generate attack traffic samples (different types)
        attack_types = list(self.traffic_patterns.keys())
        attack_types.remove("normal")
        
        for _ in range(num_attack):
            attack_type = random.choice(attack_types)
            intensity = random.uniform(0.6, 1.0)  # Higher intensity for attacks
            features = self.generate_traffic_features(attack_type, intensity)
            samples.append((features, True))
        
        # Shuffle the samples
        random.shuffle(samples)
        
        return samples
    
    def simulate_attack_traffic(self, attack_type="syn_flood", duration=60, intensity=0.8):
        """
        Simulate attack traffic and save to MongoDB if available
        
        Args:
            attack_type (str): Type of attack to simulate
            duration (int): Duration in seconds
            intensity (float): Attack intensity (0.0-1.0)
            
        Returns:
            dict: Simulation details and results
        """
        # Generate attack state
        attack_state = self.generate_traffic_state(attack_type, intensity)
        attack_features = self.generate_traffic_features(attack_type, intensity)
        
        # Save to MongoDB if available
        if MONGO_AVAILABLE:
            try:
                client = MongoClient(os.environ.get('MONGODB_URI', 'mongodb://localhost:27017'))
                db = client.get_database('ddos_defender')
                traffic_collection = db.get_collection('network_traffic')
                
                # Create traffic document
                traffic_doc = {
                    "timestamp": datetime.now(),
                    "source_entropy": attack_state["source_entropy"],
                    "destination_entropy": attack_state["destination_entropy"],
                    "syn_ratio": attack_state["syn_ratio"],
                    "traffic_volume": attack_state["traffic_volume"],
                    "packet_rate": attack_state["packet_rate"],
                    "unique_src_ips": attack_state["unique_src_ips"],
                    "unique_dst_ips": attack_state["unique_dst_ips"],
                    "protocol_distribution": attack_state["protocol_distribution"],
                    "traffic_type": attack_type,
                    "is_attack": True,
                    "intensity": intensity,
                    "duration": duration,
                    "simulated": True
                }
                
                # Insert into MongoDB
                traffic_collection.insert_one(traffic_doc)
                
                client.close()
                mongodb_saved = True
            except Exception as mongo_error:
                print(f"Error saving simulated traffic to MongoDB: {mongo_error}")
                mongodb_saved = False
        else:
            mongodb_saved = False
        
        return {
            "success": True,
            "attack_type": attack_type,
            "features": attack_features,
            "state": attack_state,
            "duration": duration,
            "intensity": intensity,
            "mongodb_saved": mongodb_saved,
            "message": f"Simulated {attack_type} attack with intensity {intensity} for {duration} seconds"
        }


# Initialize the simulator
traffic_simulator = NetworkTrafficSimulator()

@app.route('/api/python/simulate', methods=['POST'])
def simulate_attack():
    """Simulate a DDoS attack for testing"""
    try:
        data = request.json or {}
        attack_type = data.get('attack_type', 'syn_flood')
        duration = data.get('duration', 60)
        intensity = data.get('intensity', 0.8)
        
        # Use the sophisticated simulator to generate attack traffic
        simulation_result = traffic_simulator.simulate_attack_traffic(
            attack_type=attack_type,
            duration=duration,
            intensity=intensity
        )
        
        return jsonify(simulation_result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def start_server(port=5001, debug=True):
    """Start the Flask server"""
    app.run(host='0.0.0.0', port=port, debug=debug)

if __name__ == '__main__':
    start_server()