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

  /**
   * Initializes the storage layer with support for multiple databases
   */
  constructor() {
    this.users = new Map();
    this.currentId = 1;
    
    // Initialize with mock data (fallback for when databases are not available)
    this.initializeMockData();
    
    // Initialize database connections
    this.initializeDatabases();
  }
  
  /**
   * Initialize connections to the databases
   */
  private async initializeDatabases() {
    try {
      // Try to connect to MongoDB
      const mongoConnected = await connectToMongoDB();
      setDatabaseConnectionStatus('mongo', mongoConnected);
      
      if (mongoConnected) {
        log('MongoDB connected successfully in storage layer', 'storage');
        
        // Check if we have data in MongoDB collections
        try {
          const trafficCount = await networkTrafficCollection.countDocuments();
          const alertsCount = await alertsCollection.countDocuments();
          
          log(`MongoDB has ${trafficCount} traffic documents and ${alertsCount} alerts`, 'storage');
          
          // If collections are empty, seed with some initial data
          if (trafficCount === 0) {
            log('Seeding MongoDB with initial traffic data...', 'storage');
            await this.seedMongoDBTrafficData();
          }
        } catch (err) {
          log(`Error checking MongoDB collections: ${err}`, 'storage');
        }
      }
      
      // Try to connect to PostgreSQL
      const postgresConnected = await connectToPostgres();
      setDatabaseConnectionStatus('postgres', postgresConnected);
      if (postgresConnected) {
        log('PostgreSQL connected successfully in storage layer', 'storage');
      }
      
      // Try to connect to Neo4j
      const neo4jConnected = await connectToNeo4j();
      setDatabaseConnectionStatus('neo4j', neo4jConnected);
      if (neo4jConnected) {
        log('Neo4j connected successfully in storage layer', 'storage');
      }
    } catch (error) {
      log(`Error initializing databases: ${error}`, 'storage');
    }
  }
  
  /**
   * Seed MongoDB with initial traffic data
   */
  private async seedMongoDBTrafficData() {
    try {
      const protocols = ['tcp', 'udp', 'icmp'];
      const now = new Date();
      
      // Create 100 traffic documents for the last hour
      const trafficData = Array.from({ length: 100 }, (_, i) => {
        const timestamp = new Date(now.getTime() - Math.random() * 3600 * 1000);
        const protocol = protocols[Math.floor(Math.random() * protocols.length)];
        const isAnomaly = Math.random() < 0.1; // 10% chance to be anomaly
        
        return {
          timestamp,
          source_ip: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
          destination_ip: `10.0.0.${Math.floor(Math.random() * 10) + 1}`,
          protocol,
          packet_size: Math.floor(Math.random() * 1000) + 64,
          flags: protocol === 'tcp' ? ['SYN', 'ACK'].filter(() => Math.random() < 0.5) : undefined,
          is_anomaly: isAnomaly,
          score: isAnomaly ? Math.random() * 0.9 + 0.1 : 0
        } as NetworkTrafficDoc;
      });
      
      // Insert traffic data
      await networkTrafficCollection.insertMany(trafficData);
      log(`Inserted ${trafficData.length} traffic documents into MongoDB`, 'storage');
      
      // Create an attack event
      const attackEvent: AttackEventDoc = {
        start_time: new Date(now.getTime() - 30 * 60 * 1000), // 30 minutes ago
        attack_type: 'TCP SYN Flood',
        source_ips: Array.from(new Set(trafficData.filter(t => t.is_anomaly).map(t => t.source_ip))),
        target_ips: ['10.0.0.1', '10.0.0.2'],
        severity: 8,
        confidence: 0.92,
        mitigated: false,
        packet_count: trafficData.filter(t => t.is_anomaly).length
      };
      
      // Insert attack event
      await attackEventsCollection.insertOne(attackEvent);
      log('Inserted attack event into MongoDB', 'storage');
      
      // Create alerts
      const alerts: AlertDoc[] = [
        {
          timestamp: new Date(now.getTime() - 25 * 60 * 1000), // 25 minutes ago
          type: 'TCP SYN Flood',
          message: 'High volume of SYN packets detected from multiple sources',
          severity: 'high',
          acknowledged: false
        },
        {
          timestamp: new Date(now.getTime() - 15 * 60 * 1000), // 15 minutes ago
          type: 'Source IP Entropy Drop',
          message: 'Significant decrease in source IP entropy observed',
          severity: 'medium',
          acknowledged: false
        }
      ];
      
      // Insert alerts
      await alertsCollection.insertMany(alerts);
      log(`Inserted ${alerts.length} alerts into MongoDB`, 'storage');
      
      // Generate time-series aggregation
      await aggregateTimeSeriesData(5);
      log('Generated time-series aggregation in MongoDB', 'storage');
      
    } catch (error) {
      log(`Error seeding MongoDB: ${error}`, 'storage');
    }
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
    try {
      // STEP 1: Try to get metrics from PostgreSQL
      if (dbStatus.postgresConnected) {
        try {
          // Check if we have metrics in PostgreSQL
          const pgMetrics = await pgGetNetworkMetrics();
          
          // If we have data in PostgreSQL, use it
          if (pgMetrics.length > 0) {
            // Format database metrics for frontend display
            const formattedMetrics = pgMetrics.map((metric, index) => {
              // Generate appropriate icon and color based on metric name
              let icon = 'device_hub';
              let color = 'text-[#3B82F6]';
              
              if (metric.name.includes('Packet')) {
                icon = 'speed';
                color = 'text-[#10B981]';
              } else if (metric.name.includes('Threat')) {
                icon = 'security';
                color = metric.value === 'High' ? 'text-[#F59E0B]' : 'text-[#10B981]';
              } else if (metric.name.includes('Blocked') || metric.name.includes('Attacks')) {
                icon = 'gpp_good';
                color = 'text-[#5D3FD3]';
              }
              
              // Format trend as change string
              const changeStr = metric.trend === 'up' 
                ? `+${metric.change_percent?.toFixed(0) || 0}%` 
                : metric.trend === 'down' 
                  ? `-${metric.change_percent?.toFixed(0) || 0}%` 
                  : '0%';
              
              return {
                id: index + 1,
                name: metric.name,
                value: metric.value,
                change: changeStr,
                icon,
                color
              };
            });
            
            log('Using PostgreSQL data for network metrics', 'storage');
            return formattedMetrics;
          } else {
            // Seed PostgreSQL with metrics from MongoDB if possible
            if (dbStatus.mongoConnected) {
              await this.seedPostgreSQLMetricsFromMongoDB();
            } else {
              await this.seedPostgreSQLMetrics();
            }
            
            // Try again after seeding
            const newPgMetrics = await pgGetNetworkMetrics();
            if (newPgMetrics.length > 0) {
              log('Using newly seeded PostgreSQL data for network metrics', 'storage');
              
              // Format the same way as above
              const formattedMetrics = newPgMetrics.map((metric, index) => {
                let icon = 'device_hub';
                let color = 'text-[#3B82F6]';
                
                if (metric.name.includes('Packet')) {
                  icon = 'speed';
                  color = 'text-[#10B981]';
                } else if (metric.name.includes('Threat')) {
                  icon = 'security';
                  color = metric.value === 'High' ? 'text-[#F59E0B]' : 'text-[#10B981]';
                } else if (metric.name.includes('Blocked') || metric.name.includes('Attacks')) {
                  icon = 'gpp_good';
                  color = 'text-[#5D3FD3]';
                }
                
                const changeStr = metric.trend === 'up' 
                  ? `+${metric.change_percent?.toFixed(0) || 0}%` 
                  : metric.trend === 'down' 
                    ? `-${metric.change_percent?.toFixed(0) || 0}%` 
                    : '0%';
                
                return {
                  id: index + 1,
                  name: metric.name,
                  value: metric.value,
                  change: changeStr,
                  icon,
                  color
                };
              });
              
              return formattedMetrics;
            }
          }
        } catch (error) {
          log(`PostgreSQL error getting metrics: ${error}`, 'storage');
        }
      }
      
      // STEP 2: Fall back to MongoDB-based metrics
      if (dbStatus.mongoConnected) {
        try {
          // Count recent traffic
          const now = new Date();
          const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
          
          const totalTraffic = await networkTrafficCollection.countDocuments({
            timestamp: { $gte: oneHourAgo }
          });
          
          const anomalyTraffic = await networkTrafficCollection.countDocuments({
            timestamp: { $gte: oneHourAgo },
            is_anomaly: true
          });
          
          const activeAttacks = await attackEventsCollection.countDocuments({
            mitigated: false
          });
          
          // Generate metrics from real MongoDB data
          if (totalTraffic > 0) {
            const metrics = [
              { 
                id: 1, 
                name: "Network Load", 
                value: `${Math.min(99, Math.round(totalTraffic / 10))}%`, 
                change: "+15%", 
                icon: "device_hub", 
                color: "text-[#3B82F6]" 
              },
              { 
                id: 2, 
                name: "Packet Rate", 
                value: `${Math.round(totalTraffic / 6) / 10}K/s`, 
                change: "+8%", 
                icon: "speed", 
                color: "text-[#10B981]" 
              },
              { 
                id: 3, 
                name: "Threat Level", 
                value: activeAttacks > 0 ? "High" : "Low", 
                change: activeAttacks > 0 ? "+23%" : "-5%", 
                icon: "security", 
                color: activeAttacks > 0 ? "text-[#F59E0B]" : "text-[#10B981]" 
              },
              { 
                id: 4, 
                name: "Blocked Attacks", 
                value: anomalyTraffic.toString(), 
                change: "98%", 
                icon: "gpp_good", 
                color: "text-[#5D3FD3]" 
              }
            ];
            
            // If PostgreSQL is available, save these for future use
            if (dbStatus.postgresConnected) {
              try {
                const dbMetrics = [
                  { 
                    name: "Network Load", 
                    value: `${Math.min(99, Math.round(totalTraffic / 10))}%`, 
                    trend: "up",
                    change_percent: 15.0
                  },
                  { 
                    name: "Packet Rate", 
                    value: `${Math.round(totalTraffic / 6) / 10}K/s`, 
                    trend: "up",
                    change_percent: 8.0
                  },
                  { 
                    name: "Threat Level", 
                    value: activeAttacks > 0 ? "High" : "Low", 
                    trend: activeAttacks > 0 ? "up" : "down",
                    change_percent: activeAttacks > 0 ? 23.0 : 5.0
                  },
                  { 
                    name: "Blocked Attacks", 
                    value: anomalyTraffic.toString(), 
                    trend: "up",
                    change_percent: 98.0
                  }
                ];
                
                // Insert into PostgreSQL
                for (const metric of dbMetrics) {
                  await pgInsertNetworkMetric(metric);
                }
                
                log('Saved MongoDB-derived metrics to PostgreSQL', 'storage');
              } catch (pgError) {
                log(`Error saving metrics to PostgreSQL: ${pgError}`, 'storage');
              }
            }
            
            log('Using MongoDB data for network metrics', 'storage');
            return metrics;
          }
        } catch (error) {
          log(`MongoDB error getting metrics: ${error}`, 'storage');
        }
      }
      
      // STEP 3: Fallback to mock data only if both databases fail
      log('Using mock data for network metrics', 'storage');
      return this.networkMetrics;
    } catch (error) {
      log(`Error in getLatestNetworkMetrics: ${error}`, 'storage');
      return this.networkMetrics;
    }
  }
  
  /**
   * Seed PostgreSQL with metrics data from MongoDB
   */
  private async seedPostgreSQLMetricsFromMongoDB(): Promise<void> {
    if (!dbStatus.postgresConnected || !dbStatus.mongoConnected) return;
    
    try {
      // Count recent traffic in MongoDB
      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      
      const totalTraffic = await networkTrafficCollection.countDocuments({
        timestamp: { $gte: oneHourAgo }
      });
      
      const anomalyTraffic = await networkTrafficCollection.countDocuments({
        timestamp: { $gte: oneHourAgo },
        is_anomaly: true
      });
      
      const activeAttacks = await attackEventsCollection.countDocuments({
        mitigated: false
      });
      
      if (totalTraffic > 0) {
        // Create metrics based on MongoDB data
        const dbMetrics = [
          { 
            name: "Network Load", 
            value: `${Math.min(99, Math.round(totalTraffic / 10))}%`, 
            trend: "up",
            change_percent: 15.0
          },
          { 
            name: "Packet Rate", 
            value: `${Math.round(totalTraffic / 6) / 10}K/s`, 
            trend: "up",
            change_percent: 8.0
          },
          { 
            name: "Threat Level", 
            value: activeAttacks > 0 ? "High" : "Low", 
            trend: activeAttacks > 0 ? "up" : "down",
            change_percent: activeAttacks > 0 ? 23.0 : 5.0
          },
          { 
            name: "Blocked Attacks", 
            value: anomalyTraffic.toString(), 
            trend: "up",
            change_percent: 98.0
          }
        ];
        
        // Insert into PostgreSQL
        for (const metric of dbMetrics) {
          await pgInsertNetworkMetric(metric);
        }
        
        log('Seeded PostgreSQL with metrics from MongoDB data', 'storage');
      }
    } catch (error) {
      log(`Error seeding PostgreSQL from MongoDB: ${error}`, 'storage');
    }
  }
  
  /**
   * Seed PostgreSQL with initial metrics data
   */
  private async seedPostgreSQLMetrics(): Promise<void> {
    if (!dbStatus.postgresConnected) return;
    
    try {
      // Create dashboard metrics
      const dashboardMetrics = [
        { 
          name: "Network Load", 
          value: "42%", 
          trend: "up",
          change_percent: 15.0
        },
        { 
          name: "Packet Rate", 
          value: "8.5K/s", 
          trend: "up",
          change_percent: 8.0
        },
        { 
          name: "Threat Level", 
          value: "Medium", 
          trend: "up",
          change_percent: 23.0
        },
        { 
          name: "Blocked Attacks", 
          value: "12", 
          trend: "up",
          change_percent: 98.0
        }
      ];
      
      // Import dashboard metric functions from postgres.ts
      const { insertDashboardMetric } = await import('./database/postgres');
      
      // Insert into PostgreSQL dashboardMetrics table
      for (const metric of dashboardMetrics) {
        await insertDashboardMetric(metric);
      }
      
      // Also seed the network_metrics table with more detailed data
      await this.seedNetworkMetricsData();
      
      log('Seeded PostgreSQL with initial metrics data', 'storage');
    } catch (error) {
      log(`Error seeding PostgreSQL metrics: ${error}`, 'storage');
    }
  }
  
  /**
   * Seed the network_metrics table with detailed metrics data
   */
  private async seedNetworkMetricsData(): Promise<void> {
    if (!dbStatus.postgresConnected) return;
    
    try {
      // Create network metrics with the new schema
      const networkMetricsData = [
        {
          trafficVolume: 2450,
          packetRate: 8500,
          synRatio: 0.32,
          sourceEntropy: 3.75,
          destinationEntropy: 2.95,
          uniqueSrcIps: 128,
          uniqueDstIps: 24,
          protocolDistribution: JSON.stringify({
            TCP: 42,
            UDP: 28,
            ICMP: 15,
            HTTP: 10,
            HTTPS: 5
          }),
          threatLevel: 'medium'
        },
        {
          trafficVolume: 1980,
          packetRate: 7200,
          synRatio: 0.28,
          sourceEntropy: 3.62,
          destinationEntropy: 2.88,
          uniqueSrcIps: 112,
          uniqueDstIps: 20,
          protocolDistribution: JSON.stringify({
            TCP: 45,
            UDP: 25,
            ICMP: 18,
            HTTP: 8,
            HTTPS: 4
          }),
          threatLevel: 'low'
        }
      ];
      
      // Import network metric functions from postgres.ts
      const { insertNetworkMetric } = await import('./database/postgres');
      
      // Insert into PostgreSQL networkMetrics table
      for (const metric of networkMetricsData) {
        await insertNetworkMetric(metric);
      }
      
      log('Seeded PostgreSQL with network metrics data', 'storage');
    } catch (error) {
      log(`Error seeding network metrics: ${error}`, 'storage');
    }
  }
  
  async getTrafficData(): Promise<any> {
    // Try to use MongoDB if available
    if (dbStatus.mongoConnected) {
      try {
        // Aggregate traffic data by hour for last 24 hours
        const now = new Date();
        const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        
        // Get all traffic from the last 24 hours
        const trafficDocs = await networkTrafficCollection.find({
          timestamp: { $gte: dayAgo }
        }).toArray();
        
        if (trafficDocs.length > 0) {
          // Create hour buckets for last 24 hours
          const hourBuckets: Record<string, { normal: number, attack: number }> = {};
          
          // Initialize all hour buckets with zeros
          for (let i = 0; i < 24; i++) {
            const hourString = `${i}:00`;
            hourBuckets[hourString] = { normal: 0, attack: 0 };
          }
          
          // Group traffic by hour
          trafficDocs.forEach(doc => {
            const hour = doc.timestamp.getHours();
            const hourString = `${hour}:00`;
            
            if (doc.is_anomaly) {
              hourBuckets[hourString].attack++;
            } else {
              hourBuckets[hourString].normal++;
            }
          });
          
          // Convert to arrays for chart.js
          const labels = Object.keys(hourBuckets).sort((a, b) => {
            const hourA = parseInt(a.split(':')[0]);
            const hourB = parseInt(b.split(':')[0]);
            return hourA - hourB;
          });
          
          const normalData = labels.map(hour => hourBuckets[hour].normal);
          const attackData = labels.map(hour => hourBuckets[hour].attack);
          
          log('Using MongoDB data for traffic chart', 'storage');
          return { labels, normalData, attackData };
        }
      } catch (error) {
        log(`MongoDB error getting traffic data: ${error}`, 'storage');
      }
    }
    
    // Fallback to mock data
    return this.trafficData;
  }
  
  async getProtocolDistribution(): Promise<any> {
    // Try to use MongoDB if available
    if (dbStatus.mongoConnected) {
      try {
        // Aggregate traffic by protocol
        const result = await networkTrafficCollection.aggregate([
          {
            $group: {
              _id: { $toUpper: "$protocol" },
              count: { $sum: 1 }
            }
          },
          {
            $project: {
              protocol: "$_id",
              count: 1,
              _id: 0
            }
          },
          {
            $sort: { count: -1 }
          },
          {
            $limit: 5
          }
        ]).toArray();
        
        if (result.length > 0) {
          // Calculate total
          const total = result.reduce((sum, item) => sum + item.count, 0);
          
          // Calculate percentages and assign colors
          const colors = ["bg-[#3B82F6]", "bg-[#10B981]", "bg-[#F59E0B]", "bg-[#5D3FD3]", "bg-[#EF4444]"];
          
          const protocols = result.map((item, index) => ({
            protocol: item.protocol,
            percentage: Math.round((item.count / total) * 100),
            color: colors[index % colors.length]
          }));
          
          log('Using MongoDB data for protocol distribution', 'storage');
          return protocols;
        }
      } catch (error) {
        log(`MongoDB error getting protocol distribution: ${error}`, 'storage');
      }
    }
    
    // Fallback to mock data
    return this.protocolDistribution;
  }
  
  async getRecentAlerts(): Promise<any> {
    // Try to use MongoDB if available
    if (dbStatus.mongoConnected) {
      try {
        // Get most recent alerts from MongoDB
        const alerts = await alertsCollection.find()
          .sort({ timestamp: -1 })
          .limit(5)
          .toArray();
          
        if (alerts.length > 0) {
          // Get attack events for context
          const attackEvents = await attackEventsCollection.find().toArray();
          
          // Format alerts for the frontend
          const formattedAlerts = alerts.map((alert, index) => {
            // Find related attack event if available
            const attackEvent = alert.attack_event_id ? 
              attackEvents.find(a => a._id.toString() === alert.attack_event_id) : 
              attackEvents[0]; // Just use the first attack event if no relation
              
            return {
              id: index + 1,
              time: `${alert.timestamp.getHours()}:${alert.timestamp.getMinutes().toString().padStart(2, '0')}:${alert.timestamp.getSeconds().toString().padStart(2, '0')}`,
              type: alert.type,
              source: attackEvent ? 
                (attackEvent.source_ips.length > 1 ? 
                  `Multiple (${attackEvent.source_ips.length})` : 
                  attackEvent.source_ips[0]) : 
                "Unknown",
              target: attackEvent ? 
                (attackEvent.target_ips.length > 0 ? 
                  attackEvent.target_ips[0] : 
                  "Multiple") : 
                "Unknown",
              severity: alert.severity,
              status: alert.acknowledged ? "mitigated" : "active"
            };
          });
          
          log('Using MongoDB data for alerts', 'storage');
          return formattedAlerts;
        }
      } catch (error) {
        log(`MongoDB error getting alerts: ${error}`, 'storage');
      }
    }
    
    // Try to use PostgreSQL if available
    if (dbStatus.postgresConnected) {
      try {
        const alerts = await pgGetAlerts();
        if (alerts.length > 0) {
          return alerts;
        }
      } catch (error) {
        log(`PostgreSQL error getting alerts: ${error}`, 'storage');
      }
    }
    
    // Fallback to mock data
    return this.alerts;
  }
  
  async getIpAnalysis(): Promise<any> {
    // Try to use MongoDB if available
    if (dbStatus.mongoConnected) {
      try {
        // Aggregate traffic by source IP to find suspicious IPs
        const result = await networkTrafficCollection.aggregate([
          {
            $group: {
              _id: "$source_ip",
              packetCount: { $sum: 1 },
              anomalyCount: { 
                $sum: { $cond: [{ $eq: ["$is_anomaly", true] }, 1, 0] }
              },
              firstSeen: { $min: "$timestamp" }
            }
          },
          {
            $match: {
              packetCount: { $gt: 10 } // Only IPs with significant traffic
            }
          },
          {
            $sort: { anomalyCount: -1, packetCount: -1 }
          },
          {
            $limit: 5
          }
        ]).toArray();
        
        if (result.length > 0) {
          // Format data for frontend
          const ipAnalysis = result.map(ip => {
            const status = ip.anomalyCount > 5 ? "blocked" : 
                          (ip.anomalyCount > 0 ? "suspicious" : "normal");
                          
            const now = new Date();
            const firstSeen = new Date(ip.firstSeen);
            const formatTime = (date: Date) => 
              `${date.getHours()}:${date.getMinutes().toString().padStart(2, '0')}`;
            
            return {
              ip: ip._id,
              status,
              packets: `${(ip.packetCount / 1000).toFixed(1)}K`,
              firstSeen: formatTime(firstSeen)
            };
          });
          
          log('Using MongoDB data for IP analysis', 'storage');
          return ipAnalysis;
        }
      } catch (error) {
        log(`MongoDB error getting IP analysis: ${error}`, 'storage');
      }
    }
    
    // Fallback to mock data
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
    // Try to use Neo4j if available
    if (dbStatus.neo4jConnected) {
      try {
        const topology = await createNetworkTopologyModel();
        if (topology.nodes.length > 0) {
          // Additional data for frontend
          const structure = [
            { 
              layer: "Core Layer", 
              devices: `${topology.nodes.filter(n => n.type === 'router').length} Router`,
              status: "Operational" 
            },
            { 
              layer: "Distribution Layer", 
              devices: `${topology.nodes.filter(n => n.type === 'switch').length} Switches`,
              status: "Operational" 
            },
            { 
              layer: "Access Layer", 
              devices: `${topology.nodes.filter(n => n.type === 'server').length} Servers, ${topology.nodes.filter(n => n.type === 'client').length} Hosts`,
              status: "Operational" 
            }
          ];
          
          // Format the data structure for the frontend
          const result = {
            nodes: topology.nodes.map(node => ({
              id: node.id,
              name: node.name,
              type: node.type,
              x: Math.random() * 800,  // Random positioning if not provided
              y: Math.random() * 400,
              status: node.status || 'normal'
            })),
            links: topology.links.map(link => ({
              source: link.source,
              target: link.target,
              status: link.properties?.status || 'normal'
            })),
            structure,
            attackDetails: {
              target: "server-3",
              type: "TCP SYN Flood",
              sources: "23 malicious IPs",
              status: "Active"
            }
          };
          
          log('Using Neo4j data for network topology', 'storage');
          return result;
        }
      } catch (error) {
        log(`Neo4j error getting network topology: ${error}`, 'storage');
      }
    }
    
    // Try to use PostgreSQL if available
    if (dbStatus.postgresConnected) {
      try {
        const topology = await pgGetNetworkTopology();
        if (topology.nodes.length > 0) {
          log('Using PostgreSQL data for network topology', 'storage');
          
          // Add structure data that might be missing from PostgreSQL
          const structure = [
            { 
              layer: "Core Layer", 
              devices: `${topology.nodes.filter(n => n.type === 'router').length} Router`,
              status: "Operational" 
            },
            { 
              layer: "Distribution Layer", 
              devices: `${topology.nodes.filter(n => n.type === 'switch').length} Switches`,
              status: "Operational" 
            },
            { 
              layer: "Access Layer", 
              devices: `${topology.nodes.filter(n => n.type === 'server').length} Servers, ${topology.nodes.filter(n => n.type === 'client').length} Hosts`,
              status: "Operational" 
            }
          ];
          
          return {
            ...topology,
            structure,
            attackDetails: {
              target: "server-3",
              type: "TCP SYN Flood",
              sources: "23 malicious IPs",
              status: "Active"
            }
          };
        } else {
          // If PostgreSQL tables are empty, seed them with initial data
          log('PostgreSQL network topology tables are empty. Seeding...', 'storage');
          await this.seedPostgreSQLTopology();
          
          // Try again after seeding
          const newTopology = await pgGetNetworkTopology();
          if (newTopology.nodes.length > 0) {
            log('Using newly seeded PostgreSQL data for network topology', 'storage');
            
            // Add structure data
            const structure = [
              { 
                layer: "Core Layer", 
                devices: `${newTopology.nodes.filter(n => n.type === 'router').length} Router`,
                status: "Operational" 
              },
              { 
                layer: "Distribution Layer", 
                devices: `${newTopology.nodes.filter(n => n.type === 'switch').length} Switches`,
                status: "Operational" 
              },
              { 
                layer: "Access Layer", 
                devices: `${newTopology.nodes.filter(n => n.type === 'server').length} Servers, ${newTopology.nodes.filter(n => n.type === 'client').length} Hosts`,
                status: "Operational" 
              }
            ];
            
            return {
              ...newTopology,
              structure,
              attackDetails: {
                target: "server-3",
                type: "TCP SYN Flood",
                sources: "23 malicious IPs",
                status: "Active"
              }
            };
          }
        }
      } catch (error) {
        log(`PostgreSQL error getting network topology: ${error}`, 'storage');
      }
    }
    
    // Fallback to mock data
    return this.networkTopology;
  }
  
  /**
   * Seed PostgreSQL with network topology data
   */
  private async seedPostgreSQLTopology(): Promise<void> {
    if (!dbStatus.postgresConnected) return;
    
    try {
      // Create some sample nodes
      const nodes = [
        {
          node_id: 'router-1',
          name: 'Core Router',
          type: 'router',
          ip_address: '10.0.0.1',
          x: 50,
          y: 50,
          status: 'active'
        },
        {
          node_id: 'switch-1',
          name: 'Distribution Switch 1',
          type: 'switch',
          ip_address: '10.0.1.1',
          x: 20,
          y: 80,
          status: 'active'
        },
        {
          node_id: 'switch-2',
          name: 'Distribution Switch 2',
          type: 'switch',
          ip_address: '10.0.2.1',
          x: 80,
          y: 80,
          status: 'active'
        },
        {
          node_id: 'server-1',
          name: 'Web Server',
          type: 'server',
          ip_address: '10.0.1.10',
          x: 10,
          y: 120,
          status: 'active'
        },
        {
          node_id: 'server-2',
          name: 'Database Server',
          type: 'server',
          ip_address: '10.0.1.11',
          x: 30,
          y: 120,
          status: 'active'
        },
        {
          node_id: 'server-3',
          name: 'Application Server',
          type: 'server',
          ip_address: '10.0.2.10',
          x: 70,
          y: 120,
          status: 'active'
        },
        {
          node_id: 'server-4',
          name: 'Backup Server',
          type: 'server',
          ip_address: '10.0.2.11',
          x: 90,
          y: 120,
          status: 'warning'
        }
      ];
      
      // Create links between nodes
      const links = [
        {
          source: 'router-1',
          target: 'switch-1',
          status: 'active',
          bandwidth: '1Gbps',
          latency: 2
        },
        {
          source: 'router-1',
          target: 'switch-2',
          status: 'active',
          bandwidth: '1Gbps',
          latency: 2
        },
        {
          source: 'switch-1',
          target: 'server-1',
          status: 'active',
          bandwidth: '1Gbps',
          latency: 1
        },
        {
          source: 'switch-1',
          target: 'server-2',
          status: 'active',
          bandwidth: '1Gbps',
          latency: 1
        },
        {
          source: 'switch-2',
          target: 'server-3',
          status: 'active',
          bandwidth: '1Gbps',
          latency: 1
        },
        {
          source: 'switch-2',
          target: 'server-4',
          status: 'warning',
          bandwidth: '100Mbps',
          latency: 5
        }
      ];
      
      // Insert nodes into PostgreSQL
      for (const node of nodes) {
        await pgInsertNetworkNode(node);
      }
      
      // Insert links into PostgreSQL
      for (const link of links) {
        await pgInsertNetworkLink(link);
      }
      
      log('Seeded PostgreSQL with network topology data', 'storage');
    } catch (error) {
      log(`Error seeding PostgreSQL topology: ${error}`, 'storage');
    }
  }
  
  async getTrafficPaths(): Promise<any> {
    // Try to use PostgreSQL if available
    if (dbStatus.postgresConnected) {
      try {
        const paths = await pgGetTrafficPaths();
        if (paths.length > 0) {
          log('Using PostgreSQL data for traffic paths', 'storage');
          return paths;
        }
      } catch (error) {
        log(`PostgreSQL error getting traffic paths: ${error}`, 'storage');
      }
    }
    
    // Try to use Neo4j for path analysis if available
    if (dbStatus.neo4jConnected) {
      try {
        // Create a custom path analysis
        const paths = [];
        
        // Get some source and target nodes
        if (dbStatus.mongoConnected) {
          try {
            // Find top source IPs from MongoDB
            const topSources = await networkTrafficCollection.aggregate([
              { $group: { _id: "$source_ip", count: { $sum: 1 } } },
              { $sort: { count: -1 } },
              { $limit: 3 }
            ]).toArray();
            
            // Find top destination IPs from MongoDB
            const topDests = await networkTrafficCollection.aggregate([
              { $group: { _id: "$destination_ip", count: { $sum: 1 } } },
              { $sort: { count: -1 } },
              { $limit: 3 }
            ]).toArray();
            
            if (topSources.length > 0 && topDests.length > 0) {
              // Format paths for the frontend
              let pathId = 1;
              for (let i = 0; i < Math.min(3, topSources.length); i++) {
                for (let j = 0; j < Math.min(1, topDests.length); j++) {
                  const source = topSources[i]._id;
                  const dest = topDests[j]._id;
                  const anomaly = await networkTrafficCollection.countDocuments({
                    source_ip: source,
                    destination_ip: dest,
                    is_anomaly: true
                  });
                  
                  paths.push({
                    id: pathId++,
                    pathId: `P-${String(pathId).padStart(3, '0')}`,
                    source,
                    destination: dest,
                    hops: "3 (R1→SW2→server)",
                    trafficVolume: `${(topSources[i].count / 1000).toFixed(1)}K packets`,
                    status: anomaly > 0 ? "anomalous" : "normal"
                  });
                }
              }
              
              log('Using MongoDB + Neo4j for traffic paths', 'storage');
              return paths;
            }
          } catch (error) {
            log(`MongoDB error for traffic paths: ${error}`, 'storage');
          }
        }
      } catch (error) {
        log(`Neo4j error getting traffic paths: ${error}`, 'storage');
      }
    }
    
    // Fallback to mock data
    return this.trafficPaths;
  }
  
  async getVulnerabilityAnalysis(): Promise<any> {
    // Try to use Neo4j for vulnerability analysis if available
    if (dbStatus.neo4jConnected) {
      try {
        const vulnerablePaths = await findVulnerablePaths();
        
        if (vulnerablePaths.length > 0) {
          // Format data for frontend
          const vulnerabilityAnalysis = {
            centrality: [
              { name: "Degree Centrality (server-3)", value: 0.85 },
              { name: "Closeness Centrality (server-3)", value: 0.72 },
              { name: "Betweenness Centrality (R1)", value: 0.94 }
            ],
            attackPath: {
              path: `Attacker(${vulnerablePaths[0].source.id}) → ${vulnerablePaths[0].path.join(' → ')}`,
              score: `${Math.round((vulnerablePaths[0].risk === 'high' ? 8.7 : (vulnerablePaths[0].risk === 'medium' ? 6.5 : 3.2)) * 10) / 10}/10`
            },
            communities: [
              { name: "Cluster 1: Web servers (2 nodes)", color: "bg-[#3B82F6]" },
              { name: "Cluster 2: Database servers (1 node)", color: "bg-[#F59E0B]" },
              { name: "Cluster 3: Attack targets (1 node)", color: "bg-[#EF4444]" }
            ]
          };
          
          log('Using Neo4j data for vulnerability analysis', 'storage');
          return vulnerabilityAnalysis;
        }
      } catch (error) {
        log(`Neo4j error getting vulnerability analysis: ${error}`, 'storage');
      }
    }
    
    // Fallback to mock data
    return this.vulnerabilityAnalysis;
  }
  
  // Action methods
  async mitigateAttack(alertId: number): Promise<any> {
    // Try to use MongoDB if available
    if (dbStatus.mongoConnected) {
      try {
        // Get the alert by ID (using our own ID system since MongoDB has ObjectId)
        const alerts = await alertsCollection.find().sort({ timestamp: -1 }).limit(10).toArray();
        const alert = alerts[alertId - 1]; // Convert 1-based index to 0-based
        
        if (alert) {
          // Update the alert in MongoDB
          await alertsCollection.updateOne(
            { _id: alert._id },
            { $set: { acknowledged: true } }
          );
          
          // If there's an associated attack, mark it as mitigated too
          if (alert.attack_event_id) {
            await attackEventsCollection.updateOne(
              { _id: alert.attack_event_id },
              { 
                $set: { 
                  mitigated: true,
                  end_time: new Date(),
                  mitigation_action: "Auto-mitigation via DDQN"
                } 
              }
            );
          }
          
          // Try to also update Neo4j if connected
          if (dbStatus.neo4jConnected && alert.attack_event_id) {
            try {
              await neo4jMitigateAttack(
                alert.attack_event_id.toString(),
                "Auto-mitigation via DDQN"
              );
            } catch (neoError) {
              log(`Neo4j error mitigating attack: ${neoError}`, 'storage');
            }
          }
          
          log(`MongoDB: Mitigated attack with alert ID ${alertId}`, 'storage');
          return { success: true, message: `Attack ${alertId} has been mitigated` };
        }
      } catch (error) {
        log(`MongoDB error mitigating attack: ${error}`, 'storage');
      }
    }
    
    // Fallback to in-memory implementation
    const alert = this.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.status = "mitigated";
      return { success: true, message: `Attack ${alertId} has been mitigated` };
    }
    return { success: false, message: "Alert not found" };
  }
  
  async blockIp(ip: string): Promise<any> {
    // Try to use MongoDB if available
    if (dbStatus.mongoConnected) {
      try {
        // Find all traffic from this IP
        const count = await networkTrafficCollection.countDocuments({ source_ip: ip });
        
        if (count > 0) {
          // Mark all traffic from this IP as anomaly
          await networkTrafficCollection.updateMany(
            { source_ip: ip },
            { $set: { is_anomaly: true, score: 0.95 } }
          );
          
          // Create a new alert for this blocked IP
          const alert: AlertDoc = {
            timestamp: new Date(),
            type: "IP Blocked",
            message: `IP ${ip} has been blocked by administrator action`,
            severity: "high",
            acknowledged: false
          };
          
          await alertsCollection.insertOne(alert);
          
          log(`MongoDB: Blocked IP ${ip}`, 'storage');
          return { success: true, message: `IP ${ip} has been blocked` };
        }
      } catch (error) {
        log(`MongoDB error blocking IP: ${error}`, 'storage');
      }
    }
    
    // Fallback to in-memory implementation
    const ipAnalysisEntry = this.ipAnalysis.find(entry => entry.ip === ip);
    if (ipAnalysisEntry) {
      ipAnalysisEntry.status = "blocked";
      return { success: true, message: `IP ${ip} has been blocked` };
    }
    return { success: false, message: "IP not found" };
  }
}

export const storage = new MemStorage();
