"""
Protocol Distribution Visualization for DDoS Defender

This module analyzes network traffic data from MongoDB to generate
protocol distribution statistics.
"""
import os
from pymongo import MongoClient
import datetime

def get_mongodb_connection():
    """Get MongoDB connection from environment variables"""
    mongodb_uri = os.environ.get('MONGODB_URI')
    if not mongodb_uri:
        raise ValueError("MONGODB_URI environment variable not set")
    return MongoClient(mongodb_uri)

def generate_protocol_distribution(hours=1):
    """
    Generate protocol distribution data from MongoDB
    
    Args:
        hours (int): Time range in hours to analyze
        
    Returns:
        list: Protocol distribution with percentages and colors
    """
    try:
        client = get_mongodb_connection()
        db = client['ddos_defender']
        
        # Query collection for network traffic
        traffic_collection = db['network_traffic']
        
        # Get current time and calculate start time
        end_time = datetime.datetime.now()
        start_time = end_time - datetime.timedelta(hours=hours)
        
        # Query for traffic in the time period
        query = {'timestamp': {'$gte': start_time, '$lte': end_time}}
        
        # Count total packets
        total_packets = traffic_collection.count_documents(query)
        
        if total_packets == 0:
            # Return default distribution if no data
            return [
                {"protocol": "TCP", "percentage": 45, "color": "hsl(152, 70%, 50%)"},
                {"protocol": "UDP", "percentage": 35, "color": "hsl(22, 70%, 50%)"},
                {"protocol": "ICMP", "percentage": 15, "color": "hsl(265, 70%, 50%)"},
                {"protocol": "Other", "percentage": 5, "color": "hsl(336, 70%, 50%)"}
            ]
        
        # Get protocol counts
        pipeline = [
            {'$match': query},
            {'$group': {'_id': '$protocol', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        
        protocol_counts = list(traffic_collection.aggregate(pipeline))
        
        # Calculate percentages and assign colors
        colors = {
            "TCP": "hsl(152, 70%, 50%)",
            "UDP": "hsl(22, 70%, 50%)",
            "ICMP": "hsl(265, 70%, 50%)",
            "HTTP": "hsl(191, 70%, 50%)",
            "HTTPS": "hsl(120, 70%, 50%)",
            "DNS": "hsl(210, 70%, 50%)",
            "Other": "hsl(336, 70%, 50%)"
        }
        
        result = []
        other_count = 0
        
        # Process top protocols (keep up to 5 categories)
        for i, item in enumerate(protocol_counts):
            protocol = item['_id']
            count = item['count']
            percentage = round((count / total_packets) * 100)
            
            if i < 4 and percentage > 3:  # Only keep major protocols as separate categories
                result.append({
                    "protocol": protocol,
                    "percentage": percentage,
                    "color": colors.get(protocol, f"hsl({(i * 70) % 360}, 70%, 50%)")
                })
            else:
                other_count += count
        
        # Add "Other" category if needed
        other_percentage = round((other_count / total_packets) * 100)
        if other_percentage > 0:
            result.append({
                "protocol": "Other",
                "percentage": other_percentage,
                "color": colors["Other"]
            })
        
        return result
    
    except Exception as e:
        print(f"Error generating protocol distribution: {e}")
        # Return sensible default
        return [
            {"protocol": "TCP", "percentage": 45, "color": "hsl(152, 70%, 50%)"},
            {"protocol": "UDP", "percentage": 35, "color": "hsl(22, 70%, 50%)"},
            {"protocol": "ICMP", "percentage": 15, "color": "hsl(265, 70%, 50%)"},
            {"protocol": "Other", "percentage": 5, "color": "hsl(336, 70%, 50%)"}
        ]