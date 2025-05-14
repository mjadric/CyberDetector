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

// Is this a Supabase connection?
const isSupabase = process.env.DATABASE_URL?.includes('supabase.co') || false;

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
    
    let connectionUrl = process.env.DATABASE_URL;
    
    // Special handling for Supabase connections
    if (isSupabase) {
      log('Detected Supabase connection', 'postgres');
      
      try {
        // Extract the hostname for logging purposes only
        const hostname = connectionUrl.includes('@') ? 
          connectionUrl.split('@')[1].split('/')[0] : 
          'unknown';
        log(`Attempting connection to ${hostname}`, 'postgres');
        
        // Format URL correctly for Supabase using DIRECT CONNECTION format
        // Add sslmode=require for secure connection
        if (!connectionUrl.includes('sslmode=')) {
          connectionUrl += connectionUrl.includes('?') ? 
            '&sslmode=require' : 
            '?sslmode=require';
        }
        
        log('Added SSL mode requirement for Supabase connection', 'postgres');
      } catch (e) {
        log(`Error parsing connection URL: ${e}`, 'postgres');
      }
    }
    
    // Initialize Neon SQL client
    sql = neon(connectionUrl);
    
    // Initialize Drizzle ORM
    db = drizzle(sql, { schema });
    
    // Test connection with a simple query
    if (sql) {
      try {
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
      } catch (testError) {
        throw new Error(`Test query failed: ${testError}`);
      }
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
  
  try {
    log('Creating database tables in PostgreSQL...', 'postgres');
    
    // Use @neondatabase/serverless to create tables
    // Create tables with better error handling
    
    // Create network_metrics table
    try {
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
      log('Created network_metrics table', 'postgres');
    } catch (error) {
      log(`Error creating network_metrics table: ${error}`, 'postgres');
    }
    
    // Create network_traffic table
    try {
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
      log('Created network_traffic table', 'postgres');
    } catch (error) {
      log(`Error creating network_traffic table: ${error}`, 'postgres');
    }
    
    // Create alerts table
    try {
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
      log('Created alerts table', 'postgres');
    } catch (error) {
      log(`Error creating alerts table: ${error}`, 'postgres');
    }
    
    // Create traffic_paths table
    try {
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
      log('Created traffic_paths table', 'postgres');
    } catch (error) {
      log(`Error creating traffic_paths table: ${error}`, 'postgres');
    }
    
    // Create network_nodes table
    try {
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
      log('Created network_nodes table', 'postgres');
    } catch (error) {
      log(`Error creating network_nodes table: ${error}`, 'postgres');
    }
    
    // Create network_links table
    try {
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
      log('Created network_links table', 'postgres');
    } catch (error) {
      log(`Error creating network_links table: ${error}`, 'postgres');
    }
    
    log('Finished creating PostgreSQL tables', 'postgres');
  } catch (error) {
    log(`Error in createTables: ${error}`, 'postgres');
  }
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
    
    // Generate mock data for 24 hours as a fallback
    const mockLabels = Array.from({ length: 24 }, (_, i) => 
      `${i.toString().padStart(2, '0')}:00`
    );
    
    try {
      // Simple query to check connection
      await sql`SELECT 1`;
      
      // For now, return mock data until tables are properly set up
      // In production, this would be replaced with actual query results
      return {
        labels: mockLabels,
        datasets: [
          {
            label: 'Normal Traffic',
            data: mockLabels.map(() => Math.floor(Math.random() * 100)),
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 1
          },
          {
            label: 'Anomaly Traffic',
            data: mockLabels.map(() => Math.floor(Math.random() * 20)),
            backgroundColor: 'rgba(255, 99, 132, 0.2)',
            borderColor: 'rgba(255, 99, 132, 1)',
            borderWidth: 1
          }
        ]
      };
    } catch (queryError) {
      log(`SQL query error: ${queryError}`, 'postgres');
      throw queryError;
    }
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