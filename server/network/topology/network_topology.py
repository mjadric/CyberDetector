"""
Network topology analysis module for DDoS detection and visualization.
Implements graph theory algorithms to analyze vulnerability and attack paths.
"""

import networkx as nx
import numpy as np
import json
import os

class NetworkTopologyAnalyzer:
    """
    Analyzer for network topology using graph theory concepts.
    
    Attributes:
        G (nx.Graph): NetworkX graph representing the network topology
        nodes (list): List of network nodes
        links (list): List of network links
        node_types (dict): Dictionary mapping node types to their properties
    """
    
    def __init__(self):
        self.G = nx.DiGraph()
        self.nodes = []
        self.links = []
        self.node_types = {
            'router': {'size': 15, 'color': '#3B82F6'},
            'switch': {'size': 12, 'color': '#10B981'},
            'server': {'size': 10, 'color': '#8B5CF6'},
            'client': {'size': 10, 'color': '#F59E0B'},
            'attacker': {'size': 10, 'color': '#EF4444'}
        }
    
    def load_topology_from_file(self, file_path):
        """
        Load network topology from a JSON file
        
        Args:
            file_path (str): Path to the JSON file
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            self.nodes = data.get('nodes', [])
            self.links = data.get('links', [])
            
            # Build the graph
            self._build_graph()
            return True
        except Exception as e:
            print(f"Error loading topology: {e}")
            return False
    
    def generate_default_topology(self):
        """
        Generate a default hierarchical network topology
        
        Returns:
            dict: Generated topology with nodes and links
        """
        # Create core layer (routers)
        router = {'id': 'router1', 'name': 'R1', 'type': 'router', 'x': 400, 'y': 50}
        self.nodes.append(router)
        
        # Create distribution layer (switches)
        switches = [
            {'id': 'switch1', 'name': 'SW1', 'type': 'switch', 'x': 200, 'y': 150},
            {'id': 'switch2', 'name': 'SW2', 'type': 'switch', 'x': 400, 'y': 150},
            {'id': 'switch3', 'name': 'SW3', 'type': 'switch', 'x': 600, 'y': 150}
        ]
        self.nodes.extend(switches)
        
        # Create access layer (servers)
        servers = [
            {'id': 'server1', 'name': 'server-1', 'type': 'server', 'x': 150, 'y': 250},
            {'id': 'server2', 'name': 'server-2', 'type': 'server', 'x': 250, 'y': 250},
            {'id': 'server3', 'name': 'server-3', 'type': 'server', 'x': 400, 'y': 250, 'status': 'attack'}
        ]
        self.nodes.extend(servers)
        
        # Create clients
        clients = [
            {'id': 'client1', 'name': 'client-1', 'type': 'client', 'x': 100, 'y': 350},
            {'id': 'client2', 'name': 'client-2', 'type': 'client', 'x': 200, 'y': 350},
            {'id': 'client3', 'name': 'client-3', 'type': 'client', 'x': 300, 'y': 350},
            {'id': 'client4', 'name': 'client-4', 'type': 'client', 'x': 400, 'y': 350},
            {'id': 'client5', 'name': 'client-5', 'type': 'client', 'x': 500, 'y': 350},
            {'id': 'client6', 'name': 'client-6', 'type': 'client', 'x': 600, 'y': 350}
        ]
        self.nodes.extend(clients)
        
        # Create attackers
        attackers = [
            {'id': 'attacker1', 'name': '192.168.1.45', 'type': 'attacker', 'x': 700, 'y': 350},
            {'id': 'attacker2', 'name': '192.168.1.87', 'type': 'attacker', 'x': 730, 'y': 320},
            {'id': 'attacker3', 'name': '192.168.1.102', 'type': 'attacker', 'x': 670, 'y': 320}
        ]
        self.nodes.extend(attackers)
        
        # Create links
        self.links = [
            {'source': 'router1', 'target': 'switch1'},
            {'source': 'router1', 'target': 'switch2'},
            {'source': 'router1', 'target': 'switch3'},
            {'source': 'switch1', 'target': 'server1'},
            {'source': 'switch1', 'target': 'server2'},
            {'source': 'switch2', 'target': 'server3'},
            {'source': 'switch1', 'target': 'client1'},
            {'source': 'switch1', 'target': 'client2'},
            {'source': 'switch1', 'target': 'client3'},
            {'source': 'switch2', 'target': 'client4'},
            {'source': 'switch2', 'target': 'client5'},
            {'source': 'switch3', 'target': 'client6'},
            {'source': 'router1', 'target': 'attacker1', 'status': 'attack'},
            {'source': 'router1', 'target': 'attacker2', 'status': 'attack'},
            {'source': 'router1', 'target': 'attacker3', 'status': 'attack'},
            {'source': 'switch2', 'target': 'server3', 'status': 'attack'}
        ]
        
        # Build the graph
        self._build_graph()
        
        return self.get_topology()
    
    def _build_graph(self):
        """Build NetworkX graph from nodes and links"""
        self.G.clear()
        
        # Add nodes
        for node in self.nodes:
            self.G.add_node(
                node['id'], 
                name=node['name'], 
                type=node['type'], 
                x=node['x'], 
                y=node['y'],
                status=node.get('status', 'normal')
            )
        
        # Add links
        for link in self.links:
            self.G.add_edge(
                link['source'], 
                link['target'], 
                status=link.get('status', 'normal')
            )
    
    def get_topology(self):
        """
        Get the current network topology
        
        Returns:
            dict: Network topology with nodes and links
        """
        return {
            'nodes': self.nodes,
            'links': self.links,
            'structure': [
                {'layer': 'Core Layer', 'devices': '1 Router', 'status': 'Operational'},
                {'layer': 'Distribution Layer', 'devices': f"{len([n for n in self.nodes if n['type'] == 'switch'])} Switches", 'status': 'Operational'},
                {'layer': 'Access Layer', 'devices': f"{len([n for n in self.nodes if n['type'] == 'server'])} Servers, {len([n for n in self.nodes if n['type'] == 'client'])} Hosts", 'status': '1 Server Under Attack' if any(n.get('status') == 'attack' for n in self.nodes if n['type'] == 'server') else 'Operational'}
            ],
            'attackDetails': self._get_attack_details()
        }
    
    def _get_attack_details(self):
        """
        Get details about the current attack in the network
        
        Returns:
            dict: Attack details
        """
        # Find attacked servers
        attacked_servers = [n for n in self.nodes if n.get('type') == 'server' and n.get('status') == 'attack']
        attacked_server = attacked_servers[0]['name'] if attacked_servers else "None"
        
        # Find attacker nodes
        attackers = [n for n in self.nodes if n.get('type') == 'attacker']
        attacker_count = len(attackers)
        
        return {
            'target': attacked_server,
            'type': 'TCP SYN Flood',
            'sources': f"{attacker_count} malicious IPs",
            'status': 'Active' if attacked_servers else 'None'
        }
    
    def calculate_centrality_metrics(self):
        """
        Calculate various centrality metrics for the nodes in the graph
        
        Returns:
            dict: Dictionary of centrality metrics
        """
        # Degree centrality
        degree_centrality = nx.degree_centrality(self.G)
        
        # Closeness centrality
        try:
            closeness_centrality = nx.closeness_centrality(self.G)
        except:
            # Handle disconnected graph
            closeness_centrality = {node: 0 for node in self.G.nodes()}
        
        # Betweenness centrality
        try:
            betweenness_centrality = nx.betweenness_centrality(self.G)
        except:
            betweenness_centrality = {node: 0 for node in self.G.nodes()}
        
        # Find the most critical nodes
        max_degree_node = max(degree_centrality.items(), key=lambda x: x[1])[0]
        max_closeness_node = max(closeness_centrality.items(), key=lambda x: x[1])[0]
        max_betweenness_node = max(betweenness_centrality.items(), key=lambda x: x[1])[0]
        
        # Get node names
        max_degree_name = self.G.nodes[max_degree_node]['name']
        max_closeness_name = self.G.nodes[max_closeness_node]['name']
        max_betweenness_name = self.G.nodes[max_betweenness_node]['name']
        
        centrality_metrics = [
            {'name': f"Degree Centrality ({max_degree_name})", 'value': degree_centrality[max_degree_node]},
            {'name': f"Closeness Centrality ({max_closeness_name})", 'value': closeness_centrality[max_closeness_node]},
            {'name': f"Betweenness Centrality ({max_betweenness_name})", 'value': betweenness_centrality[max_betweenness_node]}
        ]
        
        return centrality_metrics
    
    def find_attack_paths(self):
        """
        Find potential attack paths in the network
        
        Returns:
            dict: Information about the most critical attack path
        """
        # Find attacker nodes
        attackers = [n['id'] for n in self.nodes if n.get('type') == 'attacker']
        
        # Find target nodes (servers with attack status)
        targets = [n['id'] for n in self.nodes if n.get('type') == 'server' and n.get('status') == 'attack']
        
        if not attackers or not targets:
            return {
                'path': 'No attack path detected',
                'score': '0/10'
            }
        
        # Find shortest paths from attackers to targets
        shortest_paths = []
        
        for attacker in attackers:
            for target in targets:
                try:
                    path = nx.shortest_path(self.G, source=attacker, target=target)
                    path_names = [self.G.nodes[node]['name'] for node in path]
                    shortest_paths.append({
                        'path': ' → '.join(path_names),
                        'length': len(path),
                        'attacker': attacker,
                        'target': target
                    })
                except nx.NetworkXNoPath:
                    # No path exists
                    pass
        
        if not shortest_paths:
            return {
                'path': 'No attack path detected',
                'score': '0/10'
            }
        
        # Sort paths by length (shorter paths are more critical)
        shortest_paths.sort(key=lambda x: x['length'])
        
        # Choose the most critical path (shortest)
        critical_path = shortest_paths[0]
        
        # Calculate a vulnerability score (0-10) based on path length
        # Shorter paths are more vulnerable
        max_possible_length = len(self.nodes)  # Maximum possible path length
        vulnerability_score = 10 - ((critical_path['length'] - 2) / (max_possible_length - 2)) * 5
        vulnerability_score = max(0, min(10, vulnerability_score))  # Clamp between 0-10
        
        return {
            'path': critical_path['path'],
            'score': f"{vulnerability_score:.1f}/10"
        }
    
    def detect_communities(self):
        """
        Detect communities/clusters in the network using the Louvain algorithm
        
        Returns:
            list: Information about detected communities
        """
        # Convert directed graph to undirected for community detection
        G_undirected = self.G.to_undirected()
        
        try:
            # Apply Louvain community detection
            from community import best_partition
            partition = best_partition(G_undirected)
        except ImportError:
            # If community package not available, fall back to connected components
            communities = list(nx.connected_components(G_undirected))
            partition = {}
            for i, comm in enumerate(communities):
                for node in comm:
                    partition[node] = i
        
        # Count node types in each community
        community_stats = {}
        for node, community_id in partition.items():
            if community_id not in community_stats:
                community_stats[community_id] = {
                    'router': 0,
                    'switch': 0,
                    'server': 0,
                    'client': 0,
                    'attacker': 0,
                    'size': 0,
                    'attacked': False
                }
            
            node_type = self.G.nodes[node]['type']
            community_stats[community_id][node_type] += 1
            community_stats[community_id]['size'] += 1
            
            # Check if this community contains attacked nodes
            if self.G.nodes[node].get('status') == 'attack':
                community_stats[community_id]['attacked'] = True
        
        # Create readable community descriptions
        community_descriptions = []
        colors = ['bg-[#3B82F6]', 'bg-[#F59E0B]', 'bg-[#EF4444]']
        color_index = 0
        
        for community_id, stats in community_stats.items():
            if stats['server'] > 0:
                if stats['attacked']:
                    description = f"Cluster {community_id+1}: Attack targets ({stats['server']} node{'s' if stats['server'] > 1 else ''})"
                    color = 'bg-[#EF4444]'  # Red for attacked clusters
                elif stats['server'] > 1:
                    description = f"Cluster {community_id+1}: Web servers ({stats['server']} nodes)"
                    color = 'bg-[#3B82F6]'  # Blue for web servers
                else:
                    description = f"Cluster {community_id+1}: Database servers ({stats['server']} node)"
                    color = 'bg-[#F59E0B]'  # Orange for DB servers
            elif stats['attacker'] > 0:
                description = f"Cluster {community_id+1}: Attacker group ({stats['attacker']} node{'s' if stats['attacker'] > 1 else ''})"
                color = 'bg-[#EF4444]'  # Red for attacker groups
            else:
                description = f"Cluster {community_id+1}: Client group ({stats['client']} node{'s' if stats['client'] > 1 else ''})"
                color = colors[color_index % len(colors)]
                color_index += 1
            
            community_descriptions.append({
                'name': description,
                'color': color
            })
        
        return community_descriptions
    
    def get_vulnerability_analysis(self):
        """
        Get comprehensive vulnerability analysis of the network
        
        Returns:
            dict: Vulnerability analysis results
        """
        centrality = self.calculate_centrality_metrics()
        attack_path = self.find_attack_paths()
        communities = self.detect_communities()
        
        return {
            'centrality': centrality,
            'attackPath': attack_path,
            'communities': communities
        }
    
    def generate_traffic_paths(self):
        """
        Generate traffic path information for visualization
        
        Returns:
            list: Traffic path information
        """
        traffic_paths = []
        
        # Get servers and clients/attackers
        servers = [n for n in self.nodes if n.get('type') == 'server']
        clients = [n for n in self.nodes if n.get('type') in ['client', 'attacker']]
        
        path_id = 1
        
        for client in clients:
            # Only create paths for some selected clients and attackers
            if client['id'] not in ['client2', 'client5', 'attacker1', 'attacker2']:
                continue
                
            # Select a target server for this client
            if client['type'] == 'attacker':
                # Attackers target the attacked server
                target_server = next((s for s in servers if s.get('status') == 'attack'), servers[0])
                status = 'anomalous' if client['id'] == 'attacker1' else 'suspicious'
                traffic_volume = '8.5K packets' if client['id'] == 'attacker1' else '3.2K packets'
            else:
                # Clients target normal servers
                target_server = next((s for s in servers if s.get('status') != 'attack'), servers[0])
                status = 'normal'
                traffic_volume = '1.2K packets' if client['id'] == 'client5' else '0.8K packets'
            
            # Find the path
            try:
                path = nx.shortest_path(self.G, source=client['id'], target=target_server['id'])
                path_names = [self.G.nodes[node]['name'] for node in path]
                hops = f"{len(path)-1} ({path_names[0]}→{path_names[1]}→{path_names[-1]})"
                
                traffic_paths.append({
                    'id': path_id,
                    'pathId': f"P-{path_id:03d}",
                    'source': client['name'],
                    'destination': target_server['name'],
                    'hops': hops,
                    'trafficVolume': traffic_volume,
                    'status': status
                })
                
                path_id += 1
            except nx.NetworkXNoPath:
                # No path exists
                pass
        
        return traffic_paths


if __name__ == "__main__":
    # Example usage
    analyzer = NetworkTopologyAnalyzer()
    topology = analyzer.generate_default_topology()
    
    # Get vulnerability analysis
    vulnerability_analysis = analyzer.get_vulnerability_analysis()
    
    # Generate traffic paths
    traffic_paths = analyzer.generate_traffic_paths()
    
    print("Network topology analyzer initialized successfully.")
