import { 
  users,
  networkTraffic,
  alerts,
  networkMetrics, 
  dashboardMetrics,
  trafficPaths,
  networkNodes,
  networkLinks,
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
import { db } from "./db";
import { eq } from "drizzle-orm";

// Import MongoDB functionality
import { 
  connectToMongoDB, 
  networkTrafficCollection, 
  attackEventsCollection, 
  alertsCollection, 
  packetSamplesCollection,
  timeSeriesDataCollection,
  aggregateTimeSeriesData,
  extractFeaturesForDDQN
} from "./database/mongodb";

// Import PostgreSQL functionality
import { 
  connectToPostgres
} from "./database/postgres";

// Import Neo4j functionality
import {
  connectToNeo4j
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

/**
 * Storage implementation that uses Python visualization modules and multiple databases
 */
export class Storage implements IStorage {
  constructor() {
    this.initializeDatabases();
  }
  
  async getUser(id: number): Promise<User | undefined> {
    // Use Drizzle to find user
    try {
      const [user] = await db.select().from(users).where(eq(users.id, id));
      return user;
    } catch (error) {
      log(`Error finding user by ID: ${error}`, 'storage');
      return undefined;
    }
  }
  
  async getUserByUsername(username: string): Promise<User | undefined> {
    // Use Drizzle to find user by username
    try {
      const [user] = await db.select().from(users).where(eq(users.username, username));
      return user;
    } catch (error) {
      log(`Error finding user by username: ${error}`, 'storage');
      return undefined;
    }
  }
  
  async createUser(insertUser: InsertUser): Promise<User> {
    // Use Drizzle to create user
    try {
      const [user] = await db.insert(users).values(insertUser).returning();
      return user;
    } catch (error) {
      log(`Error creating user: ${error}`, 'storage');
      throw error;
    }
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
        log('MongoDB connected successfully', 'storage');
      }
      
      // Try to connect to PostgreSQL
      const postgresConnected = await connectToPostgres();
      setDatabaseConnectionStatus('postgres', postgresConnected);
      if (postgresConnected) {
        log('PostgreSQL connected successfully', 'storage');
      }
      
      // Try to connect to Neo4j
      const neo4jConnected = await connectToNeo4j();
      setDatabaseConnectionStatus('neo4j', neo4jConnected);
      if (neo4jConnected) {
        log('Neo4j connected successfully', 'storage');
      }
    } catch (error) {
      log(`Error initializing databases: ${error}`, 'storage');
    }
  }
  
  async getLatestNetworkMetrics(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/metrics/network');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting metrics from Python API: ${error}`, 'storage');
    }
    
    // If Python API failed, try to get from PostgreSQL directly
    if (dbStatus.postgresConnected) {
      try {
        // Use SQL to get dashboard metrics
        const metrics = await db.select().from(dashboardMetrics);
        if (metrics && metrics.length > 0) {
          return metrics;
        }
      } catch (error) {
        log(`Error getting metrics from PostgreSQL: ${error}`, 'storage');
      }
    }
    
    // If all database attempts failed, return empty metrics
    return [];
  }
  
  async getTrafficData(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/visualization/traffic');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting traffic data from Python API: ${error}`, 'storage');
    }
    
    // If Python API failed, try to get from MongoDB directly
    if (dbStatus.mongoConnected) {
      try {
        // Get time series aggregated data
        const timeSeriesData = await timeSeriesDataCollection.find({})
          .sort({ timestamp: 1 })
          .limit(24)
          .toArray();
        
        if (timeSeriesData.length > 0) {
          // Process data for chart
          const labels = timeSeriesData.map(doc => {
            const date = new Date(doc.timestamp);
            return `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
          });
          
          const normalData = timeSeriesData.map(doc => doc.normal_traffic_volume || 0);
          const attackData = timeSeriesData.map(doc => doc.attack_traffic_volume || 0);
          
          return {
            labels,
            normalData,
            attackData
          };
        }
      } catch (error) {
        log(`Error getting traffic data from MongoDB: ${error}`, 'storage');
      }
    }
    
    // If all database attempts failed, return empty data with current time labels
    const currentTime = new Date();
    const labels = [];
    for (let i = 0; i < 24; i++) {
      const timePoint = new Date(currentTime.getTime() - (23 - i) * 60 * 60 * 1000);
      labels.push(`${timePoint.getHours().toString().padStart(2, '0')}:00`);
    }
    
    return {
      labels,
      normalData: Array(24).fill(0),
      attackData: Array(24).fill(0)
    };
  }
  
  async getProtocolDistribution(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/visualization/protocol');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting protocol distribution from Python API: ${error}`, 'storage');
    }
    
    // If Python API failed, try from MongoDB directly
    if (dbStatus.mongoConnected) {
      try {
        // Aggregate protocol distribution from networkTrafficCollection
        const pipeline = [
          {
            $match: {
              timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // Last hour
            }
          },
          {
            $group: {
              _id: "$protocol",
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
          }
        ];
        
        const protocolData = await networkTrafficCollection.aggregate(pipeline).toArray();
        
        if (protocolData.length > 0) {
          // Calculate percentages
          const totalPackets = protocolData.reduce((sum, item) => sum + item.count, 0);
          
          // Assign colors
          const colors = [
            "bg-[#3B82F6]", // blue
            "bg-[#10B981]", // green
            "bg-[#F59E0B]", // amber
            "bg-[#5D3FD3]", // purple
            "bg-[#EF4444]"  // red
          ];
          
          const result = protocolData.map((item, index) => ({
            protocol: item.protocol.toUpperCase(),
            percentage: Math.round((item.count / totalPackets) * 100),
            color: colors[index % colors.length]
          }));
          
          return result;
        }
      } catch (error) {
        log(`Error getting protocol distribution from MongoDB: ${error}`, 'storage');
      }
    }
    
    // Return empty protocol distribution if all attempts fail
    return [];
  }
  
  async getRecentAlerts(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/visualization/alerts');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting alerts from Python API: ${error}`, 'storage');
    }
    
    // If Python API failed, try from MongoDB directly
    if (dbStatus.mongoConnected) {
      try {
        // Get most recent alerts from MongoDB
        const alerts = await alertsCollection
          .find({})
          .sort({ timestamp: -1 })
          .limit(10)
          .toArray();
        
        if (alerts.length > 0) {
          // Transform to expected format
          return alerts.map((alert, index) => {
            const timestamp = new Date(alert.timestamp);
            const timeString = `${timestamp.getHours().toString().padStart(2, '0')}:${timestamp.getMinutes().toString().padStart(2, '0')}:${timestamp.getSeconds().toString().padStart(2, '0')}`;
            
            return {
              id: index + 1,
              time: timeString,
              type: alert.type,
              source: alert.source || "Unknown",
              target: alert.target || "System",
              severity: alert.severity,
              status: alert.acknowledged ? "acknowledged" : "active"
            };
          });
        }
      } catch (error) {
        log(`Error getting alerts from MongoDB: ${error}`, 'storage');
      }
    }
    
    // Return empty alerts if all attempts fail
    return [];
  }
  
  async getIpAnalysis(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/visualization/ip_analysis');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting IP analysis from Python API: ${error}`, 'storage');
    }
    
    // If Python API failed, try from MongoDB directly
    if (dbStatus.mongoConnected) {
      try {
        // Aggregate IP data from networkTrafficCollection
        const pipeline = [
          {
            $match: {
              timestamp: { $gte: new Date(Date.now() - 3600 * 1000) }, // Last hour
              is_anomaly: true
            }
          },
          {
            $group: {
              _id: "$source_ip",
              packetCount: { $sum: 1 },
              firstSeen: { $min: "$timestamp" }
            }
          },
          {
            $sort: { packetCount: -1 }
          },
          {
            $limit: 10
          }
        ];
        
        const ipData = await networkTrafficCollection.aggregate(pipeline).toArray();
        
        if (ipData.length > 0) {
          // Format the data
          const formatTime = (date: Date) => 
            `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}`;
          
          return ipData.map(ip => ({
            ip: ip._id,
            status: ip.packetCount > 1000 ? 'blocked' : 'suspicious',
            packets: ip.packetCount > 1000 ? `${(ip.packetCount / 1000).toFixed(1)}K` : ip.packetCount.toString(),
            firstSeen: formatTime(new Date(ip.firstSeen))
          }));
        }
      } catch (error) {
        log(`Error getting IP analysis from MongoDB: ${error}`, 'storage');
      }
    }
    
    // Return empty IP analysis if all attempts fail
    return [];
  }
  
  async getFeatureImportance(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/analysis/feature_importance');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting feature importance from Python API: ${error}`, 'storage');
    }
    
    // Return empty feature importance if Python API fails
    return {
      labels: [],
      values: []
    };
  }
  
  async getDetectionMetrics(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/analysis/detection_metrics');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting detection metrics from Python API: ${error}`, 'storage');
    }
    
    // Return empty detection metrics if Python API fails
    return [];
  }
  
  async getEntropyData(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/analysis/entropy');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting entropy data from Python API: ${error}`, 'storage');
    }
    
    // Return empty entropy data if Python API fails
    return {
      labels: [],
      sourceEntropy: [],
      destEntropy: [],
      currentSourceEntropy: 0,
      currentDestEntropy: 0,
      protocolDistribution: 0,
      status: "Normal"
    };
  }
  
  async getPatternAnalysis(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/analysis/pattern');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting pattern analysis from Python API: ${error}`, 'storage');
    }
    
    // Return empty pattern analysis if Python API fails
    return {
      labels: [],
      synRatio: [],
      trafficVolume: [],
      insights: []
    };
  }
  
  async getAttackClassification(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/analysis/classification');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting attack classification from Python API: ${error}`, 'storage');
    }
    
    // Return empty attack classification if Python API fails
    return [];
  }
  
  async getNetworkTopology(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/visualization/topology');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting network topology from Python API: ${error}`, 'storage');
    }
    
    // If Python API failed and Neo4j is connected (future implementation)
    if (dbStatus.neo4jConnected) {
      log('Neo4j network topology visualization is not yet implemented', 'storage');
    }
    
    // If Python API failed, try from PostgreSQL
    if (dbStatus.postgresConnected) {
      try {
        // Get nodes from PostgreSQL
        const nodes = await db.select().from(networkNodes);
        
        // Get links from PostgreSQL
        const links = await db.select().from(networkLinks);
        
        if (nodes.length > 0 || links.length > 0) {
          return {
            nodes: nodes.map(node => ({
              id: node.nodeId,
              name: node.name,
              type: node.type,
              x: node.x,
              y: node.y,
              status: node.status || 'operational'
            })),
            links: links.map(link => ({
              source: link.source,
              target: link.target,
              status: link.status || 'operational'
            })),
            structure: [],
            attackDetails: {}
          };
        }
      } catch (error) {
        log(`Error getting network topology from PostgreSQL: ${error}`, 'storage');
      }
    }
    
    // Return empty network topology if all attempts fail
    return {
      nodes: [],
      links: [],
      structure: [],
      attackDetails: {}
    };
  }
  
  async getTrafficPaths(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/visualization/paths');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting traffic paths from Python API: ${error}`, 'storage');
    }
    
    // If Python API failed, try from PostgreSQL
    if (dbStatus.postgresConnected) {
      try {
        // Get paths from PostgreSQL
        const paths = await db.select().from(trafficPaths);
        
        if (paths.length > 0) {
          return paths.map(path => ({
            id: path.id,
            source: path.source,
            target: path.target,
            pathStatus: path.status,
            volume: path.volume,
            attackProbability: path.attackProbability
          }));
        }
      } catch (error) {
        log(`Error getting traffic paths from PostgreSQL: ${error}`, 'storage');
      }
    }
    
    // Return empty traffic paths if all attempts fail
    return [];
  }
  
  async getVulnerabilityAnalysis(): Promise<any> {
    // Try to get from Python API
    try {
      const response = await fetch('http://localhost:5001/api/visualization/vulnerability');
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error getting vulnerability analysis from Python API: ${error}`, 'storage');
    }
    
    // Return empty vulnerability analysis if Python API fails
    return {
      vulnerableNodes: [],
      vulnerableLinks: [],
      riskFactors: [],
      topVulnerabilities: []
    };
  }
  
  async mitigateAttack(alertId: number): Promise<any> {
    // Try to use Python API
    try {
      const response = await fetch(`http://localhost:5001/api/defense/mitigate/${alertId}`, {
        method: 'POST'
      });
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error mitigating attack via Python API: ${error}`, 'storage');
    }
    
    // If MongoDB is connected, update alert to mitigated
    if (dbStatus.mongoConnected) {
      try {
        // Find alert by our internal ID (we'll use alertId as index in alerts array)
        const alerts = await alertsCollection
          .find({})
          .sort({ timestamp: -1 })
          .limit(20)
          .toArray();
        
        if (alerts.length >= alertId && alertId > 0) {
          const alert = alerts[alertId - 1];
          
          // Update the alert
          await alertsCollection.updateOne(
            { _id: alert._id },
            { $set: { acknowledged: true } }
          );
          
          return {
            success: true,
            message: `Alert "${alert.type}" has been acknowledged`,
            alertId
          };
        }
      } catch (error) {
        log(`Error mitigating attack in MongoDB: ${error}`, 'storage');
      }
    }
    
    // Return generic response if all attempts fail
    return {
      success: false,
      message: "Could not mitigate attack - data source unavailable",
      alertId
    };
  }
  
  async blockIp(ip: string): Promise<any> {
    // Try to use Python API
    try {
      const response = await fetch(`http://localhost:5001/api/defense/block`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ip })
      });
      
      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
      log(`Error blocking IP via Python API: ${error}`, 'storage');
    }
    
    // If MongoDB is connected, add a blocking alert
    if (dbStatus.mongoConnected) {
      try {
        // Add blocking alert
        const result = await alertsCollection.insertOne({
          timestamp: new Date(),
          type: 'IP Blocking',
          message: `IP address ${ip} has been blocked`,
          severity: 'medium',
          acknowledged: false,
          source: ip,
          action_taken: 'block'
        });
        
        return {
          success: true,
          message: `IP ${ip} has been blocked`,
          id: result.insertedId
        };
      } catch (error) {
        log(`Error blocking IP in MongoDB: ${error}`, 'storage');
      }
    }
    
    // Return generic response if all attempts fail
    return {
      success: false,
      message: `Could not block IP ${ip} - data source unavailable`,
      ip
    };
  }
}

// Instantiate storage
export const storage = new Storage();