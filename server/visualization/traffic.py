"""
Traffic Visualization for DDoS Defender

This module provides network traffic visualization components.
"""
import os
import datetime
from pymongo import MongoClient

def get_mongodb_connection():
    """Get MongoDB connection from environment variables"""
    mongodb_uri = os.environ.get('MONGODB_URI')
    if not mongodb_uri:
        raise ValueError("MONGODB_URI environment variable not set")
    return MongoClient(mongodb_uri)

def generate_traffic_data(hours=24):
    """
    Generate traffic data for visualization
    
    Args:
        hours (int): Time range in hours to analyze
        
    Returns:
        dict: Traffic data with labels, normal traffic and attack traffic
    """
    try:
        # Connect to MongoDB
        client = get_mongodb_connection()
        db = client.ddos_defender
        
        # Get time series aggregated data
        time_series = db.time_series_data.find({
            'timestamp': {'$gte': datetime.datetime.now() - datetime.timedelta(hours=hours)}
        }).sort('timestamp', 1)
        
        time_series_list = list(time_series)
        
        # If we have data, format it for the chart
        if time_series_list:
            # Process data for chart
            labels = []
            normal_data = []
            attack_data = []
            
            for doc in time_series_list:
                # Format timestamp for label
                ts = doc['timestamp']
                label = f"{ts.hour:02d}:{ts.minute:02d}"
                labels.append(label)
                
                # Get traffic volumes
                normal_data.append(doc.get('normal_traffic_volume', 0))
                attack_data.append(doc.get('attack_traffic_volume', 0))
            
            return {
                'labels': labels,
                'normalData': normal_data,
                'attackData': attack_data
            }
        
        # If no data, generate time labels for the last 24 hours
        current_time = datetime.datetime.now()
        labels = []
        for i in range(hours):
            time_point = current_time - datetime.timedelta(hours=hours-i-1)
            labels.append(f"{time_point.hour:02d}:00")
        
        # Return empty dataset with time labels
        return {
            'labels': labels,
            'normalData': [0] * hours,
            'attackData': [0] * hours
        }
        
    except Exception as e:
        print(f"Error generating traffic data: {e}")
        
        # Return minimal empty dataset
        return {
            'labels': ['00:00'],
            'normalData': [0],
            'attackData': [0]
        }
    
def generate_real_time_traffic():
    """
    Generate real-time traffic data for the last minute
    
    Returns:
        dict: Real-time traffic statistics
    """
    try:
        # Connect to MongoDB
        client = get_mongodb_connection()
        db = client.ddos_defender
        
        # Get the last minute's traffic
        one_minute_ago = datetime.datetime.now() - datetime.timedelta(minutes=1)
        traffic = db.network_traffic.find({
            'timestamp': {'$gte': one_minute_ago}
        })
        
        traffic_list = list(traffic)
        
        # Calculate real-time statistics
        if traffic_list:
            packet_count = len(traffic_list)
            anomaly_count = sum(1 for doc in traffic_list if doc.get('is_anomaly', False))
            
            protocols = {}
            for doc in traffic_list:
                protocol = doc.get('protocol', 'unknown')
                protocols[protocol] = protocols.get(protocol, 0) + 1
            
            # Get dominant protocol
            dominant_protocol = max(protocols.items(), key=lambda x: x[1])[0] if protocols else 'none'
            
            return {
                'packetRate': packet_count,
                'anomalyRate': anomaly_count,
                'packetRatePerSecond': packet_count / 60,
                'dominantProtocol': dominant_protocol
            }
        
        # If no data, return zeros
        return {
            'packetRate': 0,
            'anomalyRate': 0,
            'packetRatePerSecond': 0,
            'dominantProtocol': 'none'
        }
        
    except Exception as e:
        print(f"Error generating real-time traffic data: {e}")
        return {
            'packetRate': 0,
            'anomalyRate': 0,
            'packetRatePerSecond': 0,
            'dominantProtocol': 'none'
        }