import { MongoClient, Db, Collection, Document } from 'mongodb';
import { log } from '../vite';

// MongoDB connection variables
let client: MongoClient;
let db: Db;

// Collection names
export const COLLECTIONS = {
  NETWORK_TRAFFIC: 'network_traffic',
  ATTACK_EVENTS: 'attack_events',
  ALERTS: 'alerts',
  PACKET_SAMPLES: 'packet_samples',
  TIME_SERIES_DATA: 'time_series_data',
};

// Collection interfaces
export interface NetworkTrafficDoc extends Document {
  timestamp: Date;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  packet_size: number;
  flags?: string[];
  is_anomaly?: boolean;
  score?: number;
}

export interface AttackEventDoc extends Document {
  start_time: Date;
  end_time?: Date;
  attack_type: string;
  source_ips: string[];
  target_ips: string[];
  severity: number;
  confidence: number;
  mitigated: boolean;
  mitigation_action?: string;
  packet_count: number;
}

export interface AlertDoc extends Document {
  timestamp: Date;
  type: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  acknowledged: boolean;
  attack_event_id?: string;
}

export interface PacketSampleDoc extends Document {
  timestamp: Date;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  raw_data: string; // Base64 encoded packet data
  is_attack: boolean;
  attack_type?: string;
  features?: Record<string, number>; // Extracted features for ML
}

export interface TimeSeriesDataDoc extends Document {
  timestamp: Date;
  interval: string; // '1m', '5m', '1h' etc.
  metrics: {
    packet_count: number;
    byte_count: number;
    unique_source_ips: number;
    unique_dest_ips: number;
    tcp_ratio: number;
    udp_ratio: number;
    icmp_ratio: number;
    entropy_src_ip: number;
    entropy_dest_ip: number;
    entropy_port: number;
    syn_ratio?: number;
  };
  is_anomaly: boolean;
  anomaly_score?: number;
}

// Collections
export let networkTrafficCollection: Collection<NetworkTrafficDoc>;
export let attackEventsCollection: Collection<AttackEventDoc>;
export let alertsCollection: Collection<AlertDoc>;
export let packetSamplesCollection: Collection<PacketSampleDoc>;
export let timeSeriesDataCollection: Collection<TimeSeriesDataDoc>;

/**
 * Connect to MongoDB
 */
export async function connectToMongoDB(): Promise<boolean> {
  if (!process.env.MONGODB_URI) {
    log('MongoDB URI is not defined in environment variables', 'mongodb');
    return false;
  }

  try {
    log('Connecting to MongoDB...', 'mongodb');
    client = new MongoClient(process.env.MONGODB_URI);
    await client.connect();
    
    db = client.db(); // Uses the database from the connection string
    
    // Initialize collections
    networkTrafficCollection = db.collection<NetworkTrafficDoc>(COLLECTIONS.NETWORK_TRAFFIC);
    attackEventsCollection = db.collection<AttackEventDoc>(COLLECTIONS.ATTACK_EVENTS);
    alertsCollection = db.collection<AlertDoc>(COLLECTIONS.ALERTS);
    packetSamplesCollection = db.collection<PacketSampleDoc>(COLLECTIONS.PACKET_SAMPLES);
    timeSeriesDataCollection = db.collection<TimeSeriesDataDoc>(COLLECTIONS.TIME_SERIES_DATA);
    
    // Create indexes for better query performance
    await createIndexes();
    
    log('Successfully connected to MongoDB', 'mongodb');
    return true;
  } catch (error) {
    log(`Failed to connect to MongoDB: ${error}`, 'mongodb');
    return false;
  }
}

/**
 * Create indexes for MongoDB collections
 */
async function createIndexes() {
  try {
    // Network traffic indexes
    await networkTrafficCollection.createIndex({ timestamp: -1 });
    await networkTrafficCollection.createIndex({ source_ip: 1 });
    await networkTrafficCollection.createIndex({ destination_ip: 1 });
    await networkTrafficCollection.createIndex({ protocol: 1 });
    await networkTrafficCollection.createIndex({ is_anomaly: 1 });
    
    // Attack events indexes
    await attackEventsCollection.createIndex({ start_time: -1 });
    await attackEventsCollection.createIndex({ attack_type: 1 });
    await attackEventsCollection.createIndex({ mitigated: 1 });
    await attackEventsCollection.createIndex({ severity: -1 });
    
    // Alerts indexes
    await alertsCollection.createIndex({ timestamp: -1 });
    await alertsCollection.createIndex({ severity: -1 });
    await alertsCollection.createIndex({ acknowledged: 1 });
    
    // Packet samples indexes
    await packetSamplesCollection.createIndex({ timestamp: -1 });
    await packetSamplesCollection.createIndex({ is_attack: 1 });
    
    // Time series data indexes
    await timeSeriesDataCollection.createIndex({ timestamp: -1 });
    await timeSeriesDataCollection.createIndex({ interval: 1, timestamp: -1 });
    await timeSeriesDataCollection.createIndex({ is_anomaly: 1 });
    
    log('MongoDB indexes created successfully', 'mongodb');
  } catch (error) {
    log(`Error creating MongoDB indexes: ${error}`, 'mongodb');
  }
}

/**
 * Close MongoDB connection
 */
export async function closeMongoDB() {
  if (client) {
    await client.close();
    log('MongoDB connection closed', 'mongodb');
  }
}

/**
 * Create time-series aggregation for DDQN input
 * This function will aggregate packet data into time windows for the DDQN model
 */
export async function aggregateTimeSeriesData(intervalMinutes: number = 5): Promise<TimeSeriesDataDoc[]> {
  try {
    const windowSize = intervalMinutes * 60 * 1000; // Convert to milliseconds
    const now = new Date();
    const timeAgo = new Date(now.getTime() - windowSize);
    
    // Find packets in the time window
    const packets = await networkTrafficCollection.find({
      timestamp: { $gte: timeAgo, $lte: now }
    }).toArray();
    
    if (packets.length === 0) {
      return [];
    }
    
    // Calculate aggregate metrics
    const uniqueSrcIps = new Set(packets.map(p => p.source_ip)).size;
    const uniqueDestIps = new Set(packets.map(p => p.destination_ip)).size;
    
    const protocolCounts = {
      tcp: packets.filter(p => p.protocol.toLowerCase() === 'tcp').length,
      udp: packets.filter(p => p.protocol.toLowerCase() === 'udp').length,
      icmp: packets.filter(p => p.protocol.toLowerCase() === 'icmp').length
    };
    
    const totalPackets = packets.length;
    const totalBytes = packets.reduce((sum, p) => sum + (p.packet_size || 0), 0);
    
    // Calculate protocol ratios
    const tcpRatio = totalPackets > 0 ? protocolCounts.tcp / totalPackets : 0;
    const udpRatio = totalPackets > 0 ? protocolCounts.udp / totalPackets : 0;
    const icmpRatio = totalPackets > 0 ? protocolCounts.icmp / totalPackets : 0;
    
    // Calculate SYN ratio (for TCP SYN flood detection)
    const synCount = packets.filter(p => 
      p.protocol.toLowerCase() === 'tcp' && 
      p.flags && 
      p.flags.includes('SYN') && 
      !p.flags.includes('ACK')
    ).length;
    
    const synRatio = protocolCounts.tcp > 0 ? synCount / protocolCounts.tcp : 0;
    
    // Calculate entropy (simplified)
    function calculateEntropy(values: string[]): number {
      const valueFrequency: Record<string, number> = {};
      values.forEach(value => {
        valueFrequency[value] = (valueFrequency[value] || 0) + 1;
      });
      
      return Object.values(valueFrequency).reduce((entropy, freq) => {
        const p = freq / values.length;
        return entropy - p * Math.log2(p);
      }, 0);
    }
    
    const entropySrcIp = calculateEntropy(packets.map(p => p.source_ip));
    const entropyDestIp = calculateEntropy(packets.map(p => p.destination_ip));
    // Port information might not be available in this model, using a placeholder
    const entropyPort = 0;
    
    // Check for anomalies (simplified detection)
    // In a real system, this would use more advanced techniques like statistical methods or ML
    const isSynFlood = synRatio > 0.8 && totalPackets > 100;
    const isVolumeAnomaly = totalPackets > 1000 || totalBytes > 1000000;
    const isDistributionAnomaly = tcpRatio > 0.9 || udpRatio > 0.9 || icmpRatio > 0.5;
    
    const isAnomaly = isSynFlood || isVolumeAnomaly || isDistributionAnomaly;
    
    // Create time series document
    const timeSeriesDoc: TimeSeriesDataDoc = {
      timestamp: now,
      interval: `${intervalMinutes}m`,
      metrics: {
        packet_count: totalPackets,
        byte_count: totalBytes,
        unique_source_ips: uniqueSrcIps,
        unique_dest_ips: uniqueDestIps,
        tcp_ratio: tcpRatio,
        udp_ratio: udpRatio,
        icmp_ratio: icmpRatio,
        entropy_src_ip: entropySrcIp,
        entropy_dest_ip: entropyDestIp,
        entropy_port: entropyPort,
        syn_ratio: synRatio
      },
      is_anomaly: isAnomaly,
      anomaly_score: isSynFlood ? 0.9 : (isVolumeAnomaly ? 0.8 : (isDistributionAnomaly ? 0.7 : 0))
    };
    
    // Save to database
    await timeSeriesDataCollection.insertOne(timeSeriesDoc);
    
    // Get recent time series data
    return timeSeriesDataCollection.find({
      interval: `${intervalMinutes}m`
    })
    .sort({ timestamp: -1 })
    .limit(10)
    .toArray();
    
  } catch (error) {
    log(`Error aggregating time series data: ${error}`, 'mongodb');
    return [];
  }
}

/**
 * Get features vector for DDQN model input
 */
export function extractFeaturesForDDQN(timeSeriesData: TimeSeriesDataDoc[]): number[] {
  if (timeSeriesData.length === 0) {
    // Return default feature vector with zeros if no data
    return [0, 0, 0, 0, 0, 0, 0, 0];
  }
  
  // Use the most recent data point
  const latestData = timeSeriesData[0];
  
  // Extract features relevant for DDQN
  return [
    latestData.metrics.syn_ratio || 0,
    latestData.metrics.tcp_ratio,
    latestData.metrics.udp_ratio,
    latestData.metrics.icmp_ratio,
    latestData.metrics.entropy_src_ip,
    latestData.metrics.entropy_dest_ip,
    latestData.metrics.packet_count / 1000, // Normalize packet count
    latestData.metrics.unique_source_ips / 100 // Normalize unique IPs
  ];
}

// Export the MongoDB connection
export default {
  connectToMongoDB,
  closeMongoDB,
  aggregateTimeSeriesData,
  extractFeaturesForDDQN
};