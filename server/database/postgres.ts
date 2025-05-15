import { neon, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-http';
import { eq, and } from 'drizzle-orm';
import { log } from '../vite';
import * as schema from '../../shared/schema';
import {
  networkTraffic, type NetworkTraffic, type InsertNetworkTraffic,
  alerts, type Alert, type InsertAlert,
  networkMetrics, type NetworkMetrics, type InsertNetworkMetrics,
  dashboardMetrics, type DashboardMetrics, type InsertDashboardMetrics,
  trafficPaths, type TrafficPath, type InsertTrafficPath,
  networkNodes, type NetworkNode, type InsertNetworkNode,
  networkLinks, type NetworkLink, type InsertNetworkLink
} from '../../shared/schema';

// Configure Neon client - WebSockets are handled automatically in newer versions

// Database connection
let sql: ReturnType<typeof neon> | null = null;
let db: ReturnType<typeof drizzle> | null = null;

/**
 * Detect database type from connection URL
 */
function detectDatabaseType(url: string = '') {
  return {
    isSupabase: url.includes('supabase.co'),
    isNeon: url.includes('neon.tech')
  };
}

/**
 * Connect to PostgreSQL database
 */
export async function connectToPostgres(): Promise<boolean> {
  // Check for database connection info
  // Either DATABASE_URL should be defined, or individual PG* variables
  if (!process.env.DATABASE_URL && 
      !(process.env.PGHOST && process.env.PGUSER && process.env.PGPASSWORD && process.env.PGDATABASE)) {
    log('Neither DATABASE_URL nor PG* variables are defined', 'postgres');
    return false;
  }

  try {
    log('Connecting to PostgreSQL...', 'postgres');
    
    let connectionUrl = '';
    
    // Prefer individual PG* variables over DATABASE_URL if both exist
    if (process.env.PGHOST && process.env.PGUSER && process.env.PGPASSWORD && process.env.PGDATABASE) {
      log('Using PG* environment variables for connection', 'postgres');
      
      const pgHost = process.env.PGHOST;
      const pgUser = process.env.PGUSER;
      const pgPassword = process.env.PGPASSWORD;
      const pgDatabase = process.env.PGDATABASE;
      const pgPort = process.env.PGPORT || '5432';
      
      // Construct connection URL from PG* variables
      connectionUrl = `postgresql://${pgUser}:${pgPassword}@${pgHost}:${pgPort}/${pgDatabase}`;
      log(`Created connection URL from PG* variables to host: ${pgHost}`, 'postgres');
    } else {
      // Fall back to DATABASE_URL if PG* variables aren't complete
      connectionUrl = process.env.DATABASE_URL as string;
      log('Using DATABASE_URL environment variable for connection', 'postgres');
    }
    
    // Detect database type
    const { isSupabase, isNeon } = detectDatabaseType(connectionUrl);
    
    // Special handling for Supabase connections
    if (isSupabase) {
      log('Detected Supabase connection', 'postgres');
      
      try {
        // Extract the hostname for logging purposes only
        const hostname = connectionUrl.includes('@') ? 
          connectionUrl.split('@')[1].split('/')[0] : 
          'unknown';
        log(`Attempting connection to ${hostname}`, 'postgres');
        
        // Format URL correctly for Supabase using CONNECTION POOLING format
        // Add pgbouncer for connection pooling
        if (!connectionUrl.includes('pgbouncer=')) {
          connectionUrl += connectionUrl.includes('?') ? 
            '&pgbouncer=true&connection_limit=1' : 
            '?pgbouncer=true&connection_limit=1';
        }
        
        // Add sslmode=require for secure connection
        if (!connectionUrl.includes('sslmode=')) {
          connectionUrl += connectionUrl.includes('?') ? 
            '&sslmode=require' : 
            '?sslmode=require';
        }
        
        log('Added connection pooling and SSL requirement for Supabase', 'postgres');
      } catch (e) {
        log(`Error parsing connection URL: ${e}`, 'postgres');
      }
    }
    
    // Special handling for Neon connections
    if (isNeon) {
      log('Detected Neon connection', 'postgres');
      
      try {
        // Extract the hostname for logging purposes only
        const hostname = connectionUrl.includes('@') ? 
          connectionUrl.split('@')[1].split('/')[0] : 
          'unknown';
        log(`Attempting connection to ${hostname}`, 'postgres');
        
        // Neon.tech works well with @neondatabase/serverless out of the box
        // No specific modifications needed
        log('Using standard Neon connection parameters', 'postgres');
      } catch (e) {
        log(`Error parsing connection URL: ${e}`, 'postgres');
      }
    }
    
    // Generic PostgreSQL connection
    if (!isSupabase && !isNeon) {
      log('Using generic PostgreSQL connection', 'postgres');
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
 * Reset database by dropping and recreating tables
 */
export async function resetDatabase(): Promise<boolean> {
  if (!sql) {
    log('Cannot reset database: SQL client not initialized', 'postgres');
    return false;
  }
  
  try {
    log('Resetting PostgreSQL database...', 'postgres');
    
    // Drop all tables in reverse order of dependencies
    await sql`DROP TABLE IF EXISTS network_links`;
    await sql`DROP TABLE IF EXISTS network_nodes`;
    await sql`DROP TABLE IF EXISTS traffic_paths`;
    await sql`DROP TABLE IF EXISTS alerts`;
    await sql`DROP TABLE IF EXISTS network_traffic`;
    await sql`DROP TABLE IF EXISTS dashboard_metrics`;
    await sql`DROP TABLE IF EXISTS network_metrics`;
    await sql`DROP TABLE IF EXISTS users`;
    
    log('All tables dropped successfully', 'postgres');
    
    // Recreate tables
    await createTables();
    
    // Seed with initial data
    await seedInitialData();
    
    return true;
  } catch (error) {
    log(`Error resetting database: ${error}`, 'postgres');
    return false;
  }
}

/**
 * Seed the database with initial data
 */
async function seedInitialData(): Promise<void> {
  try {
    log('Seeding database with initial data...', 'postgres');
    
    // Insert network metrics for dashboard directly with SQL
    if (sql) {
      await sql`
        INSERT INTO network_metrics (name, value, change, icon, color)
        VALUES 
          ('Network Load', '72%', '+15%', 'device_hub', 'text-[#3B82F6]'),
          ('Packet Rate', '5.2K/s', '+8%', 'speed', 'text-[#10B981]'),
          ('Threat Level', 'High', '+23%', 'security', 'text-[#F59E0B]'),
          ('Blocked Attacks', '142', '98%', 'gpp_good', 'text-[#5D3FD3]')
      `;
      
      log('Database seeded with initial metrics', 'postgres');
    } else {
      log('SQL client not available for seeding data', 'postgres');
    }
  } catch (error) {
    log(`Error seeding initial data: ${error}`, 'postgres');
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
          change VARCHAR(255),
          icon VARCHAR(100),
          color VARCHAR(100),
          timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          trend VARCHAR(50),
          change_percent DECIMAL(5,2)
        )
      `;
      log('Created network_metrics table', 'postgres');
    } catch (error) {
      log(`Error creating network_metrics table: ${error}`, 'postgres');
    }
    
    // Create dashboard_metrics table for simplified dashboard display
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS dashboard_metrics (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          value VARCHAR(255) NOT NULL,
          change_percent DECIMAL(5,2),
          trend VARCHAR(50),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `;
      log('Created dashboard_metrics table', 'postgres');
    } catch (error) {
      log(`Error creating dashboard_metrics table: ${error}`, 'postgres');
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
  if (!db || !sql) {
    throw new Error('Database not initialized');
  }
  
  try {
    // Use raw SQL query to fetch metrics
    const result = await sql`
      SELECT * FROM network_metrics ORDER BY id
    `;
    
    // Convert to expected format with explicit typing
    return (result as any[]).map(row => ({
      id: row.id,
      name: row.name,
      value: row.value,
      change: row.change,
      icon: row.icon,
      color: row.color,
      createTime: row.timestamp,
      trend: row.trend,
      change_percent: row.change_percent
    }));
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
    // Use SQL query to manually insert since we had schema changes
    const result = await sql`
      INSERT INTO network_metrics 
        (name, value, change, icon, color, trend, change_percent)
      VALUES 
        (${metric.name}, ${metric.value}, ${metric.change}, ${metric.icon}, ${metric.color}, ${metric.trend}, ${metric.change_percent})
      RETURNING *
    `;
    
    // Convert to expected format if successful
    if (result && result.length > 0) {
      return {
        id: result[0].id,
        name: result[0].name,
        value: result[0].value,
        change: result[0].change,
        icon: result[0].icon,
        color: result[0].color,
        createTime: result[0].timestamp,
        trend: result[0].trend,
        change_percent: result[0].change_percent,
      };
    }
    
    return null;
  } catch (error) {
    log(`Error inserting network metric: ${error}`, 'postgres');
    return null;
  }
}

/**
 * Get all dashboard metrics
 */
export async function getDashboardMetrics(): Promise<DashboardMetrics[]> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    return await db.select().from(dashboardMetrics).orderBy(dashboardMetrics.id);
  } catch (error) {
    log(`Error getting dashboard metrics: ${error}`, 'postgres');
    return [];
  }
}

/**
 * Insert a new dashboard metric
 */
export async function insertDashboardMetric(metric: InsertDashboardMetrics): Promise<DashboardMetrics | null> {
  if (!db) {
    throw new Error('Database not initialized');
  }
  
  try {
    const result = await db.insert(dashboardMetrics).values(metric).returning();
    return result[0] || null;
  } catch (error) {
    log(`Error inserting dashboard metric: ${error}`, 'postgres');
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