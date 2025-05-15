"""
Network Visualization for DDoS Defender

This module provides network topology and traffic path visualizations.
"""
import os
import networkx as nx
import datetime
from pymongo import MongoClient

def get_mongodb_connection():
    """Get MongoDB connection from environment variables"""
    mongodb_uri = os.environ.get('MONGODB_URI')
    if not mongodb_uri:
        raise ValueError("MONGODB_URI environment variable not set")
    return MongoClient(mongodb_uri)

def generate_network_topology():
    """
    Generate network topology visualization data
    
    Returns:
        dict: Network topology data with nodes and links
    """
    try:
        client = get_mongodb_connection()
        db = client['ddos_defender']
        
        # Check if we have network topology collections
        if 'network_nodes' in db.list_collection_names() and 'network_links' in db.list_collection_names():
            nodes_collection = db['network_nodes']
            links_collection = db['network_links']
            
            # Get nodes and links
            nodes = list(nodes_collection.find())
            links = list(links_collection.find())
            
            # Format nodes
            formatted_nodes = []
            for node in nodes:
                formatted_nodes.append({
                    'id': str(node.get('_id')),
                    'name': node.get('name'),
                    'type': node.get('type', 'device'),
                    'nodeId': node.get('node_id', str(node.get('_id'))),
                    'x': node.get('x', 0),
                    'y': node.get('y', 0),
                    'status': node.get('status', 'active')
                })
            
            # Format links
            formatted_links = []
            for link in links:
                formatted_links.append({
                    'id': str(link.get('_id')),
                    'source': link.get('source'),
                    'target': link.get('target'),
                    'value': link.get('value', 1),
                    'status': link.get('status', 'active')
                })
            
            # Create network data
            return {
                'nodes': formatted_nodes,
                'links': formatted_links
            }
            
        # If no collections, generate simulated topology
        return generate_simulated_topology()
    
    except Exception as e:
        print(f"Error generating network topology: {e}")
        return generate_simulated_topology()

def generate_traffic_paths():
    """
    Generate traffic paths visualization data
    
    Returns:
        list: Traffic paths with source, target and metrics
    """
    try:
        client = get_mongodb_connection()
        db = client['ddos_defender']
        
        # Check if we have traffic paths collection
        if 'traffic_paths' in db.list_collection_names():
            paths_collection = db['traffic_paths']
            
            # Get current time and calculate start time
            end_time = datetime.datetime.now()
            start_time = end_time - datetime.timedelta(hours=1)
            
            # Query for recent paths
            query = {'timestamp': {'$gte': start_time, '$lte': end_time}}
            
            # Get paths
            paths = list(paths_collection.find(query).sort('packet_count', -1).limit(20))
            
            # Format paths
            formatted_paths = []
            for path in paths:
                formatted_paths.append({
                    'id': str(path.get('_id')),
                    'source': path.get('source'),
                    'target': path.get('target'),
                    'protocol': path.get('protocol', 'TCP'),
                    'packetCount': path.get('packet_count', 0),
                    'byteCount': path.get('byte_count', 0),
                    'isAttack': path.get('is_attack', False)
                })
            
            return formatted_paths if formatted_paths else generate_simulated_paths()
            
        # If no collection, generate simulated paths
        return generate_simulated_paths()
    
    except Exception as e:
        print(f"Error generating traffic paths: {e}")
        return generate_simulated_paths()

def generate_simulated_topology():
    """Generate simulated network topology with realistic structure"""
    # Create a network graph
    G = nx.random_tree(10)
    
    # Node types
    node_types = ['router', 'switch', 'server', 'client', 'firewall']
    
    # Generate nodes
    nodes = []
    for i, (node, degree) in enumerate(G.degree()):
        node_type = node_types[min(degree, len(node_types)-1)]
        x = i * 100 % 800
        y = (i // 8) * 100
        
        nodes.append({
            'id': f"node{node}",
            'name': f"{node_type.capitalize()} {node+1}",
            'type': node_type,
            'nodeId': f"node{node}",
            'x': x,
            'y': y,
            'status': 'active'
        })
    
    # Generate links
    links = []
    for i, (source, target) in enumerate(G.edges()):
        links.append({
            'id': f"link{i}",
            'source': f"node{source}",
            'target': f"node{target}",
            'value': 1,
            'status': 'active'
        })
    
    return {
        'nodes': nodes,
        'links': links
    }

def generate_simulated_paths():
    """Generate simulated traffic paths with realistic values"""
    # Create some simulated paths
    paths = []
    for i in range(10):
        source = f"192.168.{i//4 + 1}.{(i%4)*10 + 1}"
        target = f"10.0.{i//3 + 1}.{(i%3)*20 + 10}"
        protocol = "TCP" if i % 3 == 0 else "UDP" if i % 3 == 1 else "ICMP"
        packet_count = 1000 + (i * 500)
        byte_count = packet_count * (64 + (i * 10))
        is_attack = i > 7  # Make last few paths attack traffic
        
        paths.append({
            'id': f"path{i}",
            'source': source,
            'target': target,
            'protocol': protocol,
            'packetCount': packet_count,
            'byteCount': byte_count,
            'isAttack': is_attack
        })
    
    return paths