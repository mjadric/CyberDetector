#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Python backend API server for DDoS detection and mitigation
Basic implementation without TensorFlow dependencies for better compatibility
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
    """Generate a mock network topology for development and testing"""
    return {
        "nodes": [
            {"id": "router1", "name": "R1", "type": "router", "x": 50, "y": 50},
            {"id": "router2", "name": "R2", "type": "router", "x": 200, "y": 50},
            {"id": "server1", "name": "S1", "type": "server", "x": 50, "y": 150},
            {"id": "server2", "name": "S2", "type": "server", "x": 200, "y": 150},
            {"id": "client1", "name": "C1", "type": "client", "x": 125, "y": 250}
        ],
        "links": [
            {"source": "router1", "target": "router2"},
            {"source": "router1", "target": "server1"},
            {"source": "router2", "target": "server2"},
            {"source": "router1", "target": "client1"},
            {"source": "router2", "target": "client1"}
        ]
    }

def generate_mock_vulnerability_analysis():
    """Generate mock vulnerability analysis data"""
    return {
        "centrality": [
            {"name": "Degree Centrality", "value": 0.85},
            {"name": "Betweenness Centrality", "value": 0.67},
            {"name": "Closeness Centrality", "value": 0.76}
        ],
        "critical_nodes": ["router1", "server1"],
        "attack_paths": [
            {"path": ["client1", "router1", "server1"], "risk": "high"},
            {"path": ["client1", "router2", "server2"], "risk": "medium"}
        ]
    }

def generate_mock_traffic_paths():
    """Generate mock traffic paths data"""
    return [
        {
            "id": 1,
            "pathId": "P-001",
            "source": "192.168.1.100",
            "destination": "10.0.0.5",
            "hopCount": 3,
            "status": "normal"
        },
        {
            "id": 2,
            "pathId": "P-002",
            "source": "192.168.1.45",
            "destination": "10.0.0.10",
            "hopCount": 4,
            "status": "attack"
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

@app.route('/api/python/mitigate', methods=['POST'])
def mitigate_attack():
    """Take mitigation action against an attack"""
    try:
        data = request.json or {}
        state = data.get('state', [0.5] * 8)  # Default state if none provided
        normalized_state = normalize_state(state)
        
        # Use a simple algorithm to decide action
        features_above_threshold = sum(1 for f in normalized_state if f > 0.6)
        action = min(features_above_threshold, 3)  # 0-3 range for actions
        
        # Create human-readable mitigation action details
        mitigation = create_mitigation_action(action)
        
        return jsonify({
            "success": True,
            "action": action,
            "mitigation": mitigation,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/python/simulate', methods=['POST'])
def simulate_attack():
    """Simulate a DDoS attack for testing"""
    try:
        data = request.json or {}
        attack_type = data.get('attack_type', 'tcp_syn_flood')
        duration = data.get('duration', 60)  # seconds
        intensity = data.get('intensity', 0.7)  # 0-1 scale
        
        # Return a success message with parameters
        return jsonify({
            "success": True,
            "simulation_id": f"sim-{int(time.time())}",
            "attack_type": attack_type,
            "duration": duration,
            "intensity": intensity,
            "start_time": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def start_server(port=5001, debug=True):
    """Start the Flask server"""
    app.run(host='0.0.0.0', port=port, debug=debug)

if __name__ == '__main__':
    start_server()