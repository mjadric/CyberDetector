import { 
  users, 
  type User, 
  type InsertUser,
  type NetworkTraffic,
  type Alert,
  type NetworkMetrics,
  type TrafficPath,
  type NetworkNode,
  type NetworkLink
} from "@shared/schema";
import { log } from "./vite";

// Import MongoDB functionality
import { 
  connectToMongoDB, 
  networkTrafficCollection, 
  attackEventsCollection, 
  alertsCollection, 
  packetSamplesCollection,
  timeSeriesDataCollection,
  aggregateTimeSeriesData,
  extractFeaturesForDDQN,
  type NetworkTrafficDoc,
  type AttackEventDoc,
  type AlertDoc
} from "./database/mongodb";

// Import PostgreSQL functionality
import { 
  connectToPostgres,
  getNetworkMetrics as pgGetNetworkMetrics,
  getAlerts as pgGetAlerts,
  getNetworkTopology as pgGetNetworkTopology,
  getTrafficPaths as pgGetTrafficPaths,
  getNetworkTrafficData as pgGetNetworkTrafficData
} from "./database/postgres";

// Import Neo4j functionality
import {
  connectToNeo4j,
  createNetworkTopologyModel,
  findVulnerablePaths,
  recordNetworkFlow,
  recordAttack,
  mitigateAttack as neo4jMitigateAttack
} from "./database/neo4j";

// Database connection status
const dbStatus = {
  mongoConnected: false,
  postgresConnected: false,
  neo4jConnected: false
};

/**
 * Set the connection status of a specific database
 */
export function setDatabaseConnectionStatus(db: 'mongo' | 'postgres' | 'neo4j', status: boolean) {
  if (db === 'mongo') dbStatus.mongoConnected = status;
  else if (db === 'postgres') dbStatus.postgresConnected = status;
  else if (db === 'neo4j') dbStatus.neo4jConnected = status;
}

/**
 * Get database connection status
 */
export function getDatabaseConnectionStatus() {
  return { ...dbStatus };
}

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Network metrics
  getLatestNetworkMetrics(): Promise<any>;
  getTrafficData(): Promise<any>;
  getProtocolDistribution(): Promise<any>;
  getRecentAlerts(): Promise<any>;
  getIpAnalysis(): Promise<any>;
  
  // Analysis methods
  getFeatureImportance(): Promise<any>;
  getDetectionMetrics(): Promise<any>;
  getEntropyData(): Promise<any>;
  getPatternAnalysis(): Promise<any>;
  getAttackClassification(): Promise<any>;
  
  // Network topology
  getNetworkTopology(): Promise<any>;
  getTrafficPaths(): Promise<any>;
  getVulnerabilityAnalysis(): Promise<any>;
  
  // Action methods
  mitigateAttack(alertId: number): Promise<any>;
  blockIp(ip: string): Promise<any>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private networkMetrics: any[];
  private alerts: any[];
  private trafficData: any;
  private protocolDistribution: any;
  private ipAnalysis: any[];
  private featureImportance: any;
  private detectionMetrics: any;
  private entropyData: any;
  private patternAnalysis: any;
  private attackClassification: any[];
  private networkTopology: any;
  private trafficPaths: any[];
  private vulnerabilityAnalysis: any;
  
  currentId: number;

  constructor() {
    this.users = new Map();
    this.currentId = 1;
    
    // Initialize with mock data
    this.initializeMockData();
  }

  private initializeMockData() {
    // Network metrics mock data
    this.networkMetrics = [
      { id: 1, name: "Network Load", value: "72%", change: "+15%", icon: "device_hub", color: "text-[#3B82F6]" },
      { id: 2, name: "Packet Rate", value: "5.2K/s", change: "+8%", icon: "speed", color: "text-[#10B981]" },
      { id: 3, name: "Threat Level", value: "High", change: "+23%", icon: "security", color: "text-[#F59E0B]" },
      { id: 4, name: "Blocked Attacks", value: "142", change: "98%", icon: "gpp_good", color: "text-[#5D3FD3]" },
    ];
    
    // Alerts mock data
    this.alerts = [
      { id: 1, time: "14:32:15", type: "TCP SYN Flood", source: "Multiple (23)", target: "server-3", severity: "high", status: "active" },
      { id: 2, time: "14:18:42", type: "UDP Flood", source: "192.168.1.45", target: "server-1", severity: "medium", status: "mitigated" },
      { id: 3, time: "13:45:22", type: "ICMP Flood", source: "Multiple (8)", target: "server-2", severity: "medium", status: "mitigated" },
      { id: 4, time: "12:12:05", type: "TCP SYN Flood", source: "192.168.1.87", target: "server-1", severity: "low", status: "mitigated" },
    ];
    
    // Traffic data mock
    this.trafficData = {
      labels: Array.from({ length: 24 }, (_, i) => `${i}:00`),
      normalData: [65, 59, 80, 81, 56, 55, 40, 30, 45, 62, 75, 85, 70, 65, 60, 55, 50, 55, 60, 70, 80, 75, 65, 60],
      attackData: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 30, 120, 250, 210],
    };
    
    // Protocol distribution mock
    this.protocolDistribution = [
      { protocol: "HTTP", percentage: 40, color: "bg-[#3B82F6]" },
      { protocol: "HTTPS", percentage: 30, color: "bg-[#10B981]" },
      { protocol: "DNS", percentage: 15, color: "bg-[#F59E0B]" },
      { protocol: "FTP", percentage: 10, color: "bg-[#5D3FD3]" },
      { protocol: "VoIP", percentage: 5, color: "bg-[#EF4444]" },
    ];
    
    // IP Analysis mock
    this.ipAnalysis = [
      { ip: "192.168.1.45", status: "blocked", packets: "8.5K", firstSeen: "14:15:22" },
      { ip: "192.168.1.87", status: "suspicious", packets: "3.2K", firstSeen: "12:05:18" },
      { ip: "192.168.1.102", status: "suspicious", packets: "2.7K", firstSeen: "14:22:45" },
    ];
    
    // Feature importance mock
    this.featureImportance = {
      labels: ["SYN Ratio", "Packet Rate", "Traffic Volume", "Source Entropy", "Dest. Entropy", "Src IPs Count", "Dst IPs Count", "Protocol Dist."],
      values: [0.25, 0.20, 0.15, 0.18, 0.12, 0.05, 0.02, 0.03],
    };
    
    // Detection metrics mock
    this.detectionMetrics = [
      { name: "Accuracy", value: 95 },
      { name: "Precision", value: 92 },
      { name: "Recall", value: 94 },
      { name: "F1 Score", value: 93 },
    ];
    
    // Entropy data mock
    this.entropyData = {
      labels: Array.from({ length: 24 }, (_, i) => `${i}:00`),
      sourceEntropy: [0.75, 0.72, 0.78, 0.76, 0.75, 0.77, 0.79, 0.76, 0.75, 0.74, 0.76, 0.75, 0.77, 0.76, 0.75, 0.74, 0.73, 0.72, 0.70, 0.65, 0.55, 0.40, 0.30, 0.35],
      destEntropy: [0.65, 0.67, 0.64, 0.66, 0.65, 0.67, 0.66, 0.65, 0.64, 0.65, 0.67, 0.66, 0.65, 0.64, 0.63, 0.62, 0.61, 0.60, 0.58, 0.55, 0.50, 0.45, 0.40, 0.45],
      currentSourceEntropy: 0.78,
      currentDestEntropy: 0.45,
      protocolDistribution: 0.62,
      status: "Unusual"
    };
    
    // Pattern analysis mock
    this.patternAnalysis = {
      labels: ["14:00", "14:05", "14:10", "14:15", "14:20", "14:25", "14:30", "14:35", "14:40", "14:45", "14:50", "14:55"],
      synRatio: [0.12, 0.14, 0.13, 0.15, 0.14, 0.16, 0.18, 0.20, 0.25, 0.45, 0.78, 0.82],
      trafficVolume: [1.0, 1.1, 0.9, 1.2, 1.1, 1.3, 1.5, 1.8, 2.2, 3.1, 3.8, 4.0],
      insights: [
        { title: "TCP SYN Flood Pattern", description: "High SYN ratio (>70%) detected at 14:30, consistent with SYN flood attack signature.", color: "border-[#EF4444]" },
        { title: "Source IP Entropy Drop", description: "Significant decrease in source IP entropy observed, indicating potential DDoS traffic origin.", color: "border-[#F59E0B]" },
        { title: "Traffic Volume Anomaly", description: "Sudden 350% increase in traffic volume compared to baseline for this time period.", color: "border-[#3B82F6]" },
      ]
    };
    
    // Attack classification mock
    this.attackClassification = [
      {
        attackType: "TCP SYN Flood", 
        confidence: 92,
        indicators: [
          { name: "High SYN ratio (78%)", color: "bg-[#EF4444]" },
          { name: "Low source entropy (0.32)", color: "bg-[#F59E0B]" }
        ],
        sourceProfile: "Multiple IPs (23)",
        recommendedAction: "Rate Limit"
      },
      {
        attackType: "UDP Flood", 
        confidence: 45,
        indicators: [
          { name: "Increased UDP traffic (38%)", color: "bg-[#F59E0B]" }
        ],
        sourceProfile: "Single IP (192.168.1.45)",
        recommendedAction: "Monitor"
      }
    ];
    
    // Network topology mock
    this.networkTopology = {
      nodes: [
        { id: "router1", name: "R1", type: "router", x: 400, y: 50 },
        { id: "switch1", name: "SW1", type: "switch", x: 200, y: 150 },
        { id: "switch2", name: "SW2", type: "switch", x: 400, y: 150 },
        { id: "switch3", name: "SW3", type: "switch", x: 600, y: 150 },
        { id: "server1", name: "server-1", type: "server", x: 150, y: 250 },
        { id: "server2", name: "server-2", type: "server", x: 250, y: 250 },
        { id: "server3", name: "server-3", type: "server", x: 400, y: 250, status: "attack" },
        { id: "client1", name: "client-1", type: "client", x: 100, y: 350 },
        { id: "client2", name: "client-2", type: "client", x: 200, y: 350 },
        { id: "client3", name: "client-3", type: "client", x: 300, y: 350 },
        { id: "client4", name: "client-4", type: "client", x: 400, y: 350 },
        { id: "client5", name: "client-5", type: "client", x: 500, y: 350 },
        { id: "client6", name: "client-6", type: "client", x: 600, y: 350 },
        { id: "attacker1", name: "192.168.1.45", type: "attacker", x: 700, y: 350 },
        { id: "attacker2", name: "192.168.1.87", type: "attacker", x: 730, y: 320 },
        { id: "attacker3", name: "192.168.1.102", type: "attacker", x: 670, y: 320 }
      ],
      links: [
        { source: "router1", target: "switch1" },
        { source: "router1", target: "switch2" },
        { source: "router1", target: "switch3" },
        { source: "switch1", target: "server1" },
        { source: "switch1", target: "server2" },
        { source: "switch2", target: "server3" },
        { source: "switch1", target: "client1" },
        { source: "switch1", target: "client2" },
        { source: "switch1", target: "client3" },
        { source: "switch2", target: "client4" },
        { source: "switch2", target: "client5" },
        { source: "switch3", target: "client6" },
        { source: "router1", target: "attacker1", status: "attack" },
        { source: "router1", target: "attacker2", status: "attack" },
        { source: "router1", target: "attacker3", status: "attack" },
        { source: "switch2", target: "server3", status: "attack" }
      ],
      structure: [
        { layer: "Core Layer", devices: "1 Router", status: "Operational" },
        { layer: "Distribution Layer", devices: "3 Switches", status: "Operational" },
        { layer: "Access Layer", devices: "3 Servers, 9 Hosts", status: "1 Server Under Attack" }
      ],
      attackDetails: {
        target: "server-3",
        type: "TCP SYN Flood",
        sources: "23 malicious IPs",
        status: "Active"
      }
    };
    
    // Traffic paths mock
    this.trafficPaths = [
      { id: 1, pathId: "P-001", source: "192.168.1.45", destination: "server-3", hops: "3 (R1→SW2→server-3)", trafficVolume: "8.5K packets", status: "anomalous" },
      { id: 2, pathId: "P-002", source: "client-5", destination: "server-1", hops: "3 (R1→SW1→server-1)", trafficVolume: "1.2K packets", status: "normal" },
      { id: 3, pathId: "P-003", source: "192.168.1.87", destination: "server-3", hops: "3 (R1→SW2→server-3)", trafficVolume: "3.2K packets", status: "suspicious" },
      { id: 4, pathId: "P-004", source: "client-2", destination: "server-2", hops: "3 (R1→SW1→server-2)", trafficVolume: "0.8K packets", status: "normal" }
    ];
    
    // Vulnerability analysis mock
    this.vulnerabilityAnalysis = {
      centrality: [
        { name: "Degree Centrality (server-3)", value: 0.85 },
        { name: "Closeness Centrality (server-3)", value: 0.72 },
        { name: "Betweenness Centrality (R1)", value: 0.94 }
      ],
      attackPath: {
        path: "Attacker(192.168.1.45) → R1 → SW2 → server-3",
        score: "8.7/10"
      },
      communities: [
        { name: "Cluster 1: Web servers (2 nodes)", color: "bg-[#3B82F6]" },
        { name: "Cluster 2: Database servers (1 node)", color: "bg-[#F59E0B]" },
        { name: "Cluster 3: Attack targets (1 node)", color: "bg-[#EF4444]" }
      ]
    };
  }

  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentId++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }
  
  // Network metrics
  async getLatestNetworkMetrics(): Promise<any> {
    return this.networkMetrics;
  }
  
  async getTrafficData(): Promise<any> {
    return this.trafficData;
  }
  
  async getProtocolDistribution(): Promise<any> {
    return this.protocolDistribution;
  }
  
  async getRecentAlerts(): Promise<any> {
    return this.alerts;
  }
  
  async getIpAnalysis(): Promise<any> {
    return this.ipAnalysis;
  }
  
  // Analysis methods
  async getFeatureImportance(): Promise<any> {
    return this.featureImportance;
  }
  
  async getDetectionMetrics(): Promise<any> {
    return this.detectionMetrics;
  }
  
  async getEntropyData(): Promise<any> {
    return this.entropyData;
  }
  
  async getPatternAnalysis(): Promise<any> {
    return this.patternAnalysis;
  }
  
  async getAttackClassification(): Promise<any> {
    return this.attackClassification;
  }
  
  // Network topology
  async getNetworkTopology(): Promise<any> {
    return this.networkTopology;
  }
  
  async getTrafficPaths(): Promise<any> {
    return this.trafficPaths;
  }
  
  async getVulnerabilityAnalysis(): Promise<any> {
    return this.vulnerabilityAnalysis;
  }
  
  // Action methods
  async mitigateAttack(alertId: number): Promise<any> {
    const alert = this.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.status = "mitigated";
      return { success: true, message: `Attack ${alertId} has been mitigated` };
    }
    return { success: false, message: "Alert not found" };
  }
  
  async blockIp(ip: string): Promise<any> {
    const ipAnalysisEntry = this.ipAnalysis.find(entry => entry.ip === ip);
    if (ipAnalysisEntry) {
      ipAnalysisEntry.status = "blocked";
      return { success: true, message: `IP ${ip} has been blocked` };
    }
    return { success: false, message: "IP not found" };
  }
}

export const storage = new MemStorage();
