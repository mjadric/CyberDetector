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
sys.path.append(os.path.join(os.path.dirname(__file__), "analysis"))

# Import analysis modules (with error handling)
try:
    from analysis.ddqn import DDQNAgent, normalize_state, create_mitigation_action
    from analysis.traffic_analyzer import TrafficAnalyzer
    from analysis.network_topology import NetworkTopologyAnalyzer
    print("Successfully imported analysis modules")
except ImportError as e:
    print(f"Warning: Could not import analysis modules: {e}")
    # Create placeholder classes for development
    class DDQNAgent:
        def __init__(self, *args, **kwargs):
            print("Using placeholder DDQNAgent")
        
        def act(self, state):
            return 0
    
    class TrafficAnalyzer:
        def __init__(self, *args, **kwargs):
            print("Using placeholder TrafficAnalyzer")
        
        def generate_analysis_data(self):
            return {"error": "Analysis modules not available"}
    
    class NetworkTopologyAnalyzer:
        def __init__(self):
            print("Using placeholder NetworkTopologyAnalyzer")
        
        def get_topology(self):
            return {"nodes": [], "links": []}

# Initialize analysis components
analyzer = TrafficAnalyzer()
topology_analyzer = NetworkTopologyAnalyzer()

try:
    # Generate default network topology if it doesn't exist
    topology_analyzer.generate_default_topology()
    print("Generated default network topology")
except:
    print("Warning: Could not generate default network topology")

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
        data = request.json
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
        data = request.json
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