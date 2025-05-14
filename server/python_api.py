#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Python backend API server for DDoS detection and mitigation
This module provides a Flask API server that interfaces with the TensorFlow-based DDQN
implementation and network analysis components.
"""

import os
import json
import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
import time
from datetime import datetime, timedelta
import random
from pathlib import Path

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Add server directory to Python path to allow importing analysis modules
analysis_dir = os.path.join(os.path.dirname(__file__), "analysis")
print(f"Adding analysis directory to path: {analysis_dir}")
sys.path.append(analysis_dir)

# Create normalize_state function if module import fails
def normalize_state(state):
    """Default normalize_state function when imports fail"""
    if not isinstance(state, np.ndarray):
        state = np.array(state)
    return state / np.max(np.abs(state)) if np.max(np.abs(state)) > 0 else state

# Create create_mitigation_action function if module import fails
def create_mitigation_action(action_index, intensity=None):
    """Default create_mitigation_action function when imports fail"""
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

# Define base classes (will be overridden if imports succeed)
class DDQNAgent:
    """Placeholder DDQN Agent when module import fails"""
    def __init__(self, *args, **kwargs):
        print("Using placeholder DDQNAgent")
    
    def act(self, state):
        return random.randint(0, 3)  # Return random action between 0-3

class TrafficAnalyzer:
    """Placeholder Traffic Analyzer when module import fails"""
    def __init__(self, *args, **kwargs):
        print("Using placeholder TrafficAnalyzer")
    
    def generate_analysis_data(self):
        return {
            "traffic_patterns": {"timestamps": [], "values": []},
            "anomalies": [],
            "error": "Real analysis modules not available"
        }
    
    def generate_feature_importance(self):
        return {
            "labels": ["Feature 1", "Feature 2", "Feature 3"],
            "values": [0.7, 0.2, 0.1]
        }

class NetworkTopologyAnalyzer:
    """Placeholder Network Topology Analyzer when module import fails"""
    def __init__(self):
        print("Using placeholder NetworkTopologyAnalyzer")
    
    def get_topology(self):
        return {"nodes": [], "links": []}
    
    def generate_default_topology(self):
        """Generate a default topology for testing"""
        return self.get_topology()
    
    def get_vulnerability_analysis(self):
        """Return placeholder vulnerability analysis"""
        return {
            "centrality": [],
            "critical_nodes": [],
            "attack_paths": []
        }
    
    def generate_traffic_paths(self):
        """Return placeholder traffic paths"""
        return []

# Try to import real modules (will override base classes if successful)
try:
    # Using relative imports for better module resolution
    from .analysis.ddqn import DDQNAgent, normalize_state, create_mitigation_action
    from .analysis.traffic_analyzer import TrafficAnalyzer
    from .analysis.network_topology import NetworkTopologyAnalyzer
    print("Successfully imported analysis modules")
except ImportError as e:
    try:
        # Try direct imports as fallback
        from analysis.ddqn import DDQNAgent, normalize_state, create_mitigation_action
        from analysis.traffic_analyzer import TrafficAnalyzer
        from analysis.network_topology import NetworkTopologyAnalyzer
        print("Successfully imported analysis modules via direct import")
    except ImportError as e2:
        print(f"Warning: Could not import analysis modules: {e2}")
        # We'll use the placeholder classes defined above

# Initialize analysis components
analyzer = TrafficAnalyzer()
topology_analyzer = NetworkTopologyAnalyzer()

try:
    # Generate default network topology if it doesn't exist
    topology_analyzer.generate_default_topology()
    print("Generated default network topology")
except Exception as e:
    print(f"Warning: Could not generate default network topology: {e}")

@app.route('/api/python/status', methods=['GET'])
def get_status():
    """Return the status of the Python API server"""
    return jsonify({
        "status": "online",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "ddqn": DDQNAgent is not None,
            "traffic_analyzer": TrafficAnalyzer is not None,
            "topology_analyzer": NetworkTopologyAnalyzer is not None
        }
    })

@app.route('/api/python/analysis', methods=['GET'])
def get_analysis():
    """Return comprehensive analysis data"""
    try:
        analysis_data = analyzer.generate_analysis_data()
        return jsonify(analysis_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/python/topology', methods=['GET'])
def get_topology():
    """Return network topology data"""
    try:
        topology = topology_analyzer.get_topology()
        return jsonify(topology)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/python/vulnerability', methods=['GET'])
def get_vulnerability():
    """Return vulnerability analysis data"""
    try:
        vulnerability = topology_analyzer.get_vulnerability_analysis()
        return jsonify(vulnerability)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/python/traffic-paths', methods=['GET'])
def get_traffic_paths():
    """Return traffic paths data"""
    try:
        paths = topology_analyzer.generate_traffic_paths()
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
        
        # Use the DDQN agent to determine the best action
        agent = DDQNAgent()
        action = agent.act(normalized_state)
        
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
        
        # In real implementation, this would create a simulated attack
        # For now, just return a success message with parameters
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