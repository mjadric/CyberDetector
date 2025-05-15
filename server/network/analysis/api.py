#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - API sučelje za detekciju DDoS napada
"""

import os
import sys
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

# Enabling imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Provjeri postoji li flask
try:
    from flask import Blueprint, jsonify, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("Warning: Flask is not available. API will not be functional.")

# Import iz naših modula
try:
    from network.analysis.ddos_detector import DDoSDetector, get_detector
except ImportError as e:
    print(f"Error importing detector module: {e}")

# Putanja za dataset
DATASET_ROOT = Path(__file__).parent.parent.parent / "datasets"

# Stvaranje Blueprint-a za API
if FLASK_AVAILABLE:
    analysis_api = Blueprint('analysis_api', __name__)
else:
    analysis_api = None

# Globalni detektor
detector = get_detector() if 'get_detector' in locals() else None

# API rute
if FLASK_AVAILABLE:
    @analysis_api.route('/status', methods=['GET'])
    def get_status():
        """Vraća status detektora"""
        global detector
        
        if detector is None:
            try:
                detector = get_detector()
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Error initializing detector: {str(e)}"
                }), 500
        
        return jsonify({
            "status": "ready",
            "timestamp": datetime.now().isoformat(),
            "attack_history_count": len(detector.attack_history) if detector else 0,
            "attack_in_progress": detector.attack_in_progress if detector else False
        })
    
    @analysis_api.route('/detect', methods=['POST'])
    def detect_attack():
        """Detektira napad na temelju dostavljenih podataka o prometu"""
        global detector
        
        if detector is None:
            try:
                detector = get_detector()
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Error initializing detector: {str(e)}"
                }), 500
        
        # Dohvati podatke o prometu iz zahtjeva
        try:
            traffic_data = request.json.get('traffic_data', [])
            
            if not traffic_data:
                return jsonify({
                    "status": "error",
                    "message": "No traffic data provided"
                }), 400
                
            # Detektiraj napad
            detection_result = detector.detect(traffic_data)
            
            # Dodaj preporučenu akciju
            action = detector.recommend_action(detection_result)
            detection_result["recommended_action"] = action
            
            return jsonify({
                "status": "success",
                "detection": detection_result
            })
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Error during detection: {str(e)}"
            }), 500
    
    @analysis_api.route('/attack-history', methods=['GET'])
    def get_attack_history():
        """Vraća povijest detektiranih napada"""
        global detector
        
        if detector is None:
            try:
                detector = get_detector()
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Error initializing detector: {str(e)}"
                }), 500
        
        # Dohvati limit iz parametara
        limit = request.args.get('limit', default=10, type=int)
        
        # Dohvati povijest napada
        attack_history = detector.get_attack_history(limit=limit)
        
        return jsonify({
            "status": "success",
            "attack_history": attack_history,
            "count": len(attack_history)
        })
    
    @analysis_api.route('/reset', methods=['POST'])
    def reset_detector():
        """Resetira stanje detektora"""
        global detector
        
        if detector is None:
            try:
                detector = get_detector()
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Error initializing detector: {str(e)}"
                }), 500
        
        # Resetiraj detektor
        detector.reset()
        
        return jsonify({
            "status": "success",
            "message": "Detector state has been reset"
        })
    
    @analysis_api.route('/evaluate', methods=['GET'])
    def evaluate_detector():
        """Evaluira detektor na testnim podacima"""
        global detector
        
        if detector is None:
            try:
                detector = get_detector()
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Error initializing detector: {str(e)}"
                }), 500
        
        # Evaluiraj na testnim podacima
        evaluation_results = detector.evaluate()
        
        if "error" in evaluation_results:
            return jsonify({
                "status": "error",
                "message": evaluation_results["error"]
            }), 500
        
        return jsonify({
            "status": "success",
            "evaluation": evaluation_results
        })
    
    @analysis_api.route('/simulate', methods=['POST'])
    def simulate_attack():
        """Simulira napad za testiranje detektora"""
        try:
            from datasets.generator import DatasetGenerator
            
            # Dohvati parametre iz zahtjeva
            params = request.json or {}
            attack_type = params.get('attack_type', 'TCP_SYN_FLOOD')
            intensity = params.get('intensity', 'medium')
            duration = params.get('duration', 30)
            
            # Inicijaliziraj generator
            generator = DatasetGenerator()
            
            # Generiraj promet za napad
            attack_traffic = generator.generate_attack_traffic(
                attack_type=attack_type,
                intensity=intensity,
                duration_seconds=duration
            )
            
            # Generiraj mali uzorak normalnog prometa za usporedbu
            normal_traffic = generator.generate_normal_traffic(duration_seconds=10)
            
            # Detektiraj napad na generiranom prometu ako je detektor dostupan
            detection_results = None
            if detector:
                # Za normalni promet
                normal_detection = detector.detect(normal_traffic[:100])  # Prvih 100 paketa
                
                # Za napadački promet
                attack_detection = detector.detect(attack_traffic[:100])  # Prvih 100 paketa
                
                detection_results = {
                    "normal": normal_detection,
                    "attack": attack_detection
                }
            
            return jsonify({
                "status": "success",
                "simulation": {
                    "attack_type": attack_type,
                    "intensity": intensity,
                    "duration": duration,
                    "normal_traffic_size": len(normal_traffic),
                    "attack_traffic_size": len(attack_traffic)
                },
                "detection_results": detection_results
            })
            
        except ImportError:
            return jsonify({
                "status": "error",
                "message": "Dataset generator not available"
            }), 500
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Error simulating attack: {str(e)}"
            }), 500


# Inicijalizacijska funkcija koja se poziva iz glavnog Flask aplikacije
def init_analysis_api(app):
    """
    Inicijalizira API za detekciju DDoS napada.
    
    Args:
        app: Flask aplikacija
    """
    if FLASK_AVAILABLE and analysis_api:
        app.register_blueprint(analysis_api, url_prefix='/api/analysis')
        
        # Inicijaliziraj detektor
        global detector
        try:
            detector = get_detector()
            print("DDoS detector initialized successfully")
        except Exception as e:
            print(f"Error initializing DDoS detector: {e}")
    else:
        print("Flask is not available, analysis API not registered")
    

# Ako se skripta izvršava direktno, pokreni testni server
if __name__ == "__main__":
    from flask import Flask
    
    app = Flask(__name__)
    init_analysis_api(app)
    
    print("Starting test server for analysis API...")
    app.run(debug=True, port=5555)