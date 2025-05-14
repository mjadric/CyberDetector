import { neon, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-http';
import { eq, and } from 'drizzle-orm';
import { log } from '../vite';
import * as schema from '../../shared/schema';
import {
  networkTraffic, type NetworkTraffic, type InsertNetworkTraffic,
  alerts, type Alert, type InsertAlert,
  networkMetrics, type NetworkMetrics, type InsertNetworkMetrics,
  trafficPaths, type TrafficPath, type InsertTrafficPath,
  networkNodes, type NetworkNode, type InsertNetworkNode,
  networkLinks, type NetworkLink, type InsertNetworkLink
} from '../../shared/schema';

// Configure Neon client
neonConfig.fetchConnectionCache = true;

// Database connection
let sql: ReturnType<typeof neon> | null = null;
let db: ReturnType<typeof drizzle> | null = null;

/**
 * Connect to PostgreSQL database
 */
export async function connectToPostgres(): Promise<boolean> {
  if (!process.env.DATABASE_URL) {
    log('DATABASE_URL is not defined in environment variables', 'postgres');
    return false;
  }

  try {
    log('Connecting to PostgreSQL...', 'postgres');
    
    // Initialize Neon SQL client
    sql = neon(process.env.DATABASE_URL);
    
    // Initialize Drizzle ORM
    db = drizzle(sql, { schema });
    
    // Test connection with a simple query
    if (sql) {
      await sql`SELECT 1`;
      log('Successfully connected to PostgreSQL', 'postgres');
      
      // Try to create tables if they don't exist
      try {
        log('Checking and creating database tables if needed...', 'postgres');
        await createTables();
        log('Database tables are ready', 'postgres');
      } catch (tableError) {
        log(`Warning: Error handling tables: ${tableError}`, 'postgres');
        // Continue even if tables can't be fully set up
      }
      
      return true;
    } else {
      throw new Error('SQL client is null after initialization');
    }
  } catch (error) {
    log(`Failed to connect to PostgreSQL: ${error}`, 'postgres');
    return false;
  }
}

/**
 * Create database tables if they don't exist
 */
async function createTables() {
  if (!sql) return;
  
  // We'll use raw SQL queries for table creation since Drizzle 
  // doesn't have a built-in migration system in serverless mode
  
  // Create network_metrics table
  await sql`
    CREATE TABLE IF NOT EXISTS network_metrics (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      value VARCHAR(255) NOT NULL,
      change_percent DECIMAL(5,2),
      trend VARCHAR(50),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;
  
  // Create network_traffic table
  await sql`
    CREATE TABLE IF NOT EXISTS network_traffic (
      id SERIAL PRIMARY KEY,
      source_ip VARCHAR(255) NOT NULL,
      destination_ip VARCHAR(255) NOT NULL,
      protocol VARCHAR(50) NOT NULL,
      packet_size INTEGER NOT NULL,
      timestamp TIMESTAMPTZ DEFAULT NOW(),
      is_anomaly BOOLEAN DEFAULT FALSE,
      anomaly_score DECIMAL(5,2)
    )
  `;
  
  // Create alerts table
  await sql`
    CREATE TABLE IF NOT EXISTS alerts (
      id SERIAL PRIMARY KEY,
      time VARCHAR(255) NOT NULL,
      type VARCHAR(255) NOT NULL,
      source_ip VARCHAR(255),
      destination_ip VARCHAR(255),
      severity VARCHAR(50) NOT NULL,
      is_acknowledged BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;
  
  // Create traffic_paths table
  await sql`
    CREATE TABLE IF NOT EXISTS traffic_paths (
      id SERIAL PRIMARY KEY,
      path_id VARCHAR(255) NOT NULL,
      source VARCHAR(255) NOT NULL,
      destination VARCHAR(255) NOT NULL,
      hop_count INTEGER NOT NULL,
      status VARCHAR(50) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;
  
  // Create network_nodes table
  await sql`
    CREATE TABLE IF NOT EXISTS network_nodes (
      id SERIAL PRIMARY KEY,
      node_id VARCHAR(255) UNIQUE NOT NULL,
      name VARCHAR(255) NOT NULL,
      type VARCHAR(50) NOT NULL,
      ip_address VARCHAR(255),
      x DECIMAL(10,2),
      y DECIMAL(10,2),
      status VARCHAR(50) DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;
  
  // Create network_links table
  await sql`
    CREATE TABLE IF NOT EXISTS network_links (
      id SERIAL PRIMARY KEY,
      source VARCHAR(255) NOT NULL,
      target VARCHAR(255) NOT NULL,
      status VARCHAR(50) DEFAULT 'active',
      bandwidth VARCHAR(50),
      latency INTEGER,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(source, target)
    )
  `;
}

/**
 * Get all network metrics
 */
export async function getNetworkMetrics(): Promise<NetworkMetrics[]> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    return await db.select().from(networkMetrics).orderBy(networkMetrics.id);
  } catch (error) {
    log(`Error getting network metrics: ${error}`, 'postgres');
    return [];
  }
}

/**
 * Insert a new network metric
 */
export async function insertNetworkMetric(metric: InsertNetworkMetrics): Promise<NetworkMetrics | null> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    const result = await db.insert(networkMetrics).values(metric).returning();
    return result[0] || null;
  } catch (error) {
    log(`Error inserting network metric: ${error}`, 'postgres');
    return null;
  }
}

/**
 * Get all alerts
 */
export async function getAlerts(): Promise<Alert[]> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    return await db.select().from(alerts).orderBy(alerts.id);
  } catch (error) {
    log(`Error getting alerts: ${error}`, 'postgres');
    return [];
  }
}

/**
 * Insert a new alert
 */
export async function insertAlert(alert: InsertAlert): Promise<Alert | null> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    const result = await db.insert(alerts).values(alert).returning();
    return result[0] || null;
  } catch (error) {
    log(`Error inserting alert: ${error}`, 'postgres');
    return null;
  }
}

/**
 * Get network topology (nodes and links)
 */
export async function getNetworkTopology(): Promise<{ nodes: NetworkNode[], links: NetworkLink[] }> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    const nodes = await db.select().from(networkNodes);
    const links = await db.select().from(networkLinks);
    
    return { nodes, links };
  } catch (error) {
    log(`Error getting network topology: ${error}`, 'postgres');
    return { nodes: [], links: [] };
  }
}

/**
 * Insert a new network node
 */
export async function insertNetworkNode(node: InsertNetworkNode): Promise<NetworkNode | null> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    const result = await db.insert(networkNodes).values(node).returning();
    return result[0] || null;
  } catch (error) {
    log(`Error inserting network node: ${error}`, 'postgres');
    return null;
  }
}

/**
 * Insert a new network link
 */
export async function insertNetworkLink(link: InsertNetworkLink): Promise<NetworkLink | null> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    const result = await db.insert(networkLinks).values(link).returning();
    return result[0] || null;
  } catch (error) {
    log(`Error inserting network link: ${error}`, 'postgres');
    return null;
  }
}

/**
 * Get traffic paths
 */
export async function getTrafficPaths(): Promise<TrafficPath[]> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    return await db.select().from(trafficPaths).orderBy(trafficPaths.id);
  } catch (error) {
    log(`Error getting traffic paths: ${error}`, 'postgres');
    return [];
  }
}

/**
 * Insert a new traffic path
 */
export async function insertTrafficPath(path: InsertTrafficPath): Promise<TrafficPath | null> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    const result = await db.insert(trafficPaths).values(path).returning();
    return result[0] || null;
  } catch (error) {
    log(`Error inserting traffic path: ${error}`, 'postgres');
    return null;
  }
}

/**
 * Insert a network traffic record
 */
export async function insertNetworkTraffic(traffic: InsertNetworkTraffic): Promise<NetworkTraffic | null> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    const result = await db.insert(networkTraffic).values(traffic).returning();
    return result[0] || null;
  } catch (error) {
    log(`Error inserting network traffic: ${error}`, 'postgres');
    return null;
  }
}

/**
 * Get network traffic data (for charts and analysis)
 */
export async function getNetworkTrafficData(): Promise<any> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    // Get last 24 hours of traffic data (aggregated by hour)
    // This would normally be a more complex query using window functions and time buckets
    if (!sql) {
      throw new Error('SQL client is not initialized');
    }
    
    const trafficData = await sql`
      WITH hours AS (
        SELECT generate_series(
          date_trunc('hour', now()) - interval '23 hours',
          date_trunc('hour', now()),
          interval '1 hour'
        ) AS hour
      )
      SELECT 
        to_char(hours.hour, 'HH24:00') AS label,
        COUNT(nt.id) AS normal_traffic,
        COUNT(nt.id) FILTER (WHERE nt.is_anomaly = true) AS anomaly_traffic
      FROM hours
      LEFT JOIN network_traffic nt ON 
        nt.timestamp >= hours.hour AND 
        nt.timestamp < hours.hour + interval '1 hour'
      GROUP BY hours.hour
      ORDER BY hours.hour
    `;
    
    // Format the data for chart.js
    const labels = trafficData.map((row: any) => row.label);
    const normalTraffic = trafficData.map((row: any) => row.normal_traffic || 0);
    const anomalyTraffic = trafficData.map((row: any) => row.anomaly_traffic || 0);
    
    return {
      labels,
      datasets: [
        {
          label: 'Normal Traffic',
          data: normalTraffic,
          backgroundColor: 'rgba(75, 192, 192, 0.2)',
          borderColor: 'rgba(75, 192, 192, 1)',
          borderWidth: 1
        },
        {
          label: 'Anomaly Traffic',
          data: anomalyTraffic,
          backgroundColor: 'rgba(255, 99, 132, 0.2)',
          borderColor: 'rgba(255, 99, 132, 1)',
          borderWidth: 1
        }
      ]
    };
  } catch (error) {
    log(`Error getting network traffic data: ${error}`, 'postgres');
    
    // Return empty data structure
    return {
      labels: [],
      datasets: [
        {
          label: 'Normal Traffic',
          data: [],
          backgroundColor: 'rgba(75, 192, 192, 0.2)',
          borderColor: 'rgba(75, 192, 192, 1)',
          borderWidth: 1
        },
        {
          label: 'Anomaly Traffic',
          data: [],
          backgroundColor: 'rgba(255, 99, 132, 0.2)',
          borderColor: 'rgba(255, 99, 132, 1)',
          borderWidth: 1
        }
      ]
    };
  }
}

/**
 * Close the PostgreSQL connection
 */
export async function closePostgres() {
  // Neon HTTP doesn't need explicit closing
  log('PostgreSQL connection closed', 'postgres');
}

// Export the database functions
export default {
  connectToPostgres,
  closePostgres,
  getNetworkMetrics,
  insertNetworkMetric,
  getAlerts,
  insertAlert,
  getNetworkTopology,
  insertNetworkNode,
  insertNetworkLink,
  getTrafficPaths,
  insertTrafficPath,
  insertNetworkTraffic,
  getNetworkTrafficData
};