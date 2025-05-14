import neo4j, { Driver, Session, Record } from 'neo4j-driver';
import { log } from '../vite';

// Neo4j connection settings
let driver: Driver | null = null;

/**
 * Connect to Neo4j database
 */
export async function connectToNeo4j(): Promise<boolean> {
  if (!process.env.NEO4J_URI || !process.env.NEO4J_USERNAME || !process.env.NEO4J_PASSWORD) {
    log('Neo4j connection details are not defined in environment variables', 'neo4j');
    return false;
  }

  try {
    log('Connecting to Neo4j...', 'neo4j');
    
    driver = neo4j.driver(
      process.env.NEO4J_URI,
      neo4j.auth.basic(process.env.NEO4J_USERNAME, process.env.NEO4J_PASSWORD)
    );
    
    // Verify connection
    const session = driver.session();
    try {
      await session.run('RETURN 1');
      log('Successfully connected to Neo4j', 'neo4j');
      return true;
    } finally {
      await session.close();
    }
  } catch (error) {
    log(`Failed to connect to Neo4j: ${error}`, 'neo4j');
    return false;
  }
}

/**
 * Close Neo4j connection
 */
export async function closeNeo4j() {
  if (driver) {
    await driver.close();
    driver = null;
    log('Neo4j connection closed', 'neo4j');
  }
}

/**
 * Run a Cypher query on Neo4j
 */
export async function runQuery(query: string, params = {}): Promise<Record[]> {
  if (!driver) {
    throw new Error('Neo4j driver not initialized');
  }
  
  const session = driver.session();
  try {
    const result = await session.run(query, params);
    return result.records;
  } finally {
    await session.close();
  }
}

/**
 * Initialize Neo4j schema with constraints
 */
export async function initializeSchema(): Promise<void> {
  try {
    // Create constraints for Device nodes (unique ID)
    await runQuery(`
      CREATE CONSTRAINT device_id_unique IF NOT EXISTS
      FOR (d:Device) REQUIRE d.id IS UNIQUE
    `);
    
    // Create constraints for IP nodes (unique address)
    await runQuery(`
      CREATE CONSTRAINT ip_address_unique IF NOT EXISTS 
      FOR (i:IP) REQUIRE i.address IS UNIQUE
    `);
    
    // Create constraints for Flow nodes (unique ID)
    await runQuery(`
      CREATE CONSTRAINT flow_id_unique IF NOT EXISTS
      FOR (f:Flow) REQUIRE f.id IS UNIQUE
    `);
    
    // Create constraints for Attack nodes (unique ID)
    await runQuery(`
      CREATE CONSTRAINT attack_id_unique IF NOT EXISTS
      FOR (a:Attack) REQUIRE a.id IS UNIQUE
    `);
    
    log('Neo4j schema initialized successfully', 'neo4j');
  } catch (error) {
    log(`Error initializing Neo4j schema: ${error}`, 'neo4j');
  }
}

/**
 * Create or update a device in the graph
 */
export async function upsertDevice(deviceData: {
  id: string;
  name: string;
  type: string;
  status?: string;
  ip?: string;
  properties?: Record<string, any>;
}): Promise<Record[]> {
  const properties = deviceData.properties || {};
  
  const query = `
    MERGE (d:Device {id: $id})
    ON CREATE SET
      d.name = $name,
      d.type = $type,
      d.status = $status,
      d.created_at = datetime(),
      d += $properties
    ON MATCH SET
      d.name = $name,
      d.type = $type,
      d.status = $status,
      d.updated_at = datetime(),
      d += $properties
    RETURN d
  `;
  
  const params = {
    id: deviceData.id,
    name: deviceData.name,
    type: deviceData.type,
    status: deviceData.status || 'active',
    properties
  };
  
  // If IP is provided, create relationship to IP node
  if (deviceData.ip) {
    return await runQuery(`
      MERGE (d:Device {id: $id})
      ON CREATE SET
        d.name = $name,
        d.type = $type,
        d.status = $status,
        d.created_at = datetime(),
        d += $properties
      ON MATCH SET
        d.name = $name,
        d.type = $type,
        d.status = $status,
        d.updated_at = datetime(),
        d += $properties
      
      MERGE (i:IP {address: $ip})
      ON CREATE SET
        i.created_at = datetime()
      ON MATCH SET
        i.updated_at = datetime()
        
      MERGE (d)-[r:HAS_IP]->(i)
      
      RETURN d, i, r
    `, { ...params, ip: deviceData.ip });
  }
  
  return await runQuery(query, params);
}

/**
 * Create a connection between two devices
 */
export async function createConnection(
  sourceId: string,
  targetId: string,
  relationshipType: string = 'CONNECTS_TO',
  properties: Record<string, any> = {}
): Promise<Record[]> {
  const query = `
    MATCH (source:Device {id: $sourceId})
    MATCH (target:Device {id: $targetId})
    MERGE (source)-[r:${relationshipType}]->(target)
    ON CREATE SET
      r.created_at = datetime(),
      r += $properties
    ON MATCH SET
      r.updated_at = datetime(),
      r += $properties
    RETURN source, r, target
  `;
  
  return await runQuery(query, { sourceId, targetId, properties });
}

/**
 * Record a network flow between IPs
 */
export async function recordNetworkFlow(
  sourceIp: string,
  targetIp: string,
  protocol: string,
  port: number,
  packetCount: number,
  isAnomaly: boolean = false
): Promise<Record[]> {
  const flowId = `${sourceIp}-${targetIp}-${protocol}-${port}-${Date.now()}`;
  
  const query = `
    // Create or update source IP
    MERGE (source:IP {address: $sourceIp})
    ON CREATE SET source.created_at = datetime()
    ON MATCH SET source.updated_at = datetime()
    
    // Create or update target IP
    MERGE (target:IP {address: $targetIp})
    ON CREATE SET target.created_at = datetime()
    ON MATCH SET target.updated_at = datetime()
    
    // Create Flow node
    CREATE (flow:Flow {
      id: $flowId,
      protocol: $protocol,
      port: $port,
      packet_count: $packetCount,
      is_anomaly: $isAnomaly,
      created_at: datetime()
    })
    
    // Connect IPs to the flow
    CREATE (source)-[:SOURCE_OF]->(flow)
    CREATE (flow)-[:TARGETS]->(target)
    
    RETURN source, flow, target
  `;
  
  return await runQuery(query, {
    sourceIp,
    targetIp,
    protocol,
    port,
    packetCount,
    isAnomaly,
    flowId
  });
}

/**
 * Record an attack event in the graph
 */
export async function recordAttack(
  attackId: string,
  attackType: string,
  sourceIps: string[],
  targetIps: string[],
  startTime: Date,
  severity: number,
  properties: Record<string, any> = {}
): Promise<Record[]> {
  // Convert Date to ISO string for Neo4j datetime
  const startTimeStr = startTime.toISOString();
  
  // Basic query to create attack node
  const query = `
    CREATE (a:Attack {
      id: $attackId,
      type: $attackType,
      start_time: datetime($startTimeStr),
      severity: $severity,
      active: true
    })
    SET a += $properties
    
    // Connect source IPs
    WITH a
    UNWIND $sourceIps AS sourceIp
    MERGE (source:IP {address: sourceIp})
    ON CREATE SET source.created_at = datetime()
    MERGE (source)-[r:SOURCE_OF]->(a)
    
    // Connect target IPs
    WITH a
    UNWIND $targetIps AS targetIp
    MERGE (target:IP {address: targetIp})
    ON CREATE SET target.created_at = datetime()
    MERGE (a)-[t:TARGETS]->(target)
    
    RETURN a, collect(DISTINCT source) as sources, collect(DISTINCT target) as targets
  `;
  
  return await runQuery(query, {
    attackId,
    attackType,
    sourceIps,
    targetIps,
    startTimeStr,
    severity,
    properties
  });
}

/**
 * Mark an attack as mitigated
 */
export async function mitigateAttack(
  attackId: string,
  mitigationAction: string,
  endTime: Date = new Date()
): Promise<Record[]> {
  const endTimeStr = endTime.toISOString();
  
  const query = `
    MATCH (a:Attack {id: $attackId})
    SET a.active = false,
        a.mitigated = true,
        a.end_time = datetime($endTimeStr),
        a.mitigation_action = $mitigationAction,
        a.mitigation_time = datetime()
    RETURN a
  `;
  
  return await runQuery(query, {
    attackId,
    endTimeStr,
    mitigationAction
  });
}

/**
 * Get attack propagation path
 */
export async function getAttackPropagation(attackId: string): Promise<any> {
  const query = `
    MATCH (a:Attack {id: $attackId})
    OPTIONAL MATCH path = (source:IP)-[:SOURCE_OF]->(a)-[:TARGETS]->(target:IP)
    OPTIONAL MATCH (target)<-[:HAS_IP]-(device:Device)
    RETURN a.type as attackType, 
           a.severity as severity,
           a.start_time as startTime,
           collect(DISTINCT source.address) as sourceIps,
           collect(DISTINCT target.address) as targetIps,
           collect(DISTINCT device.id) as affectedDevices
  `;
  
  const records = await runQuery(query, { attackId });
  
  if (records.length === 0) {
    return null;
  }
  
  const record = records[0];
  return {
    id: attackId,
    type: record.get('attackType'),
    severity: record.get('severity').toNumber(),
    startTime: new Date(record.get('startTime').toString()),
    sourceIps: record.get('sourceIps'),
    targetIps: record.get('targetIps'),
    affectedDevices: record.get('affectedDevices')
  };
}

/**
 * Find the shortest attack path between two devices
 */
export async function findAttackPath(sourceDeviceId: string, targetDeviceId: string): Promise<any[]> {
  const query = `
    MATCH (source:Device {id: $sourceDeviceId}),
          (target:Device {id: $targetDeviceId})
    MATCH path = shortestPath((source)-[:CONNECTS_TO*]-(target))
    RETURN nodes(path) as nodes, relationships(path) as rels
  `;
  
  const records = await runQuery(query, { sourceDeviceId, targetDeviceId });
  
  if (records.length === 0) {
    return [];
  }
  
  const pathNodes = records[0].get('nodes').map((node: any) => ({
    id: node.properties.id,
    label: node.properties.name,
    type: node.properties.type
  }));
  
  return pathNodes;
}

/**
 * Create a network topology visualization model
 */
export async function createNetworkTopologyModel(): Promise<{
  nodes: any[];
  links: any[];
}> {
  // First, make sure we have some basic network topology if none exists
  await ensureNetworkTopology();
  
  // Query to get all devices and their connections
  const query = `
    MATCH (d:Device)
    OPTIONAL MATCH (d)-[r:CONNECTS_TO]->(target:Device)
    RETURN d, collect({relationship: r, target: target}) as connections
  `;
  
  const records = await runQuery(query);
  
  // Create nodes and links arrays
  const nodes: any[] = [];
  const links: any[] = [];
  const nodeIds = new Set<string>();
  
  records.forEach(record => {
    const device = record.get('d').properties;
    
    // Only add each node once
    if (!nodeIds.has(device.id)) {
      nodes.push({
        id: device.id,
        name: device.name,
        type: device.type,
        status: device.status || 'active'
      });
      nodeIds.add(device.id);
    }
    
    // Add connections as links
    const connections = record.get('connections');
    connections.forEach((conn: any) => {
      if (conn.relationship && conn.target && conn.target.properties) {
        links.push({
          source: device.id,
          target: conn.target.properties.id,
          properties: conn.relationship.properties || {}
        });
      }
    });
  });
  
  return { nodes, links };
}

/**
 * Ensure we have at least a basic network topology
 */
async function ensureNetworkTopology(): Promise<void> {
  try {
    // Check if we have any devices
    const deviceCount = await runQuery('MATCH (d:Device) RETURN count(d) as count');
    
    if (deviceCount[0].get('count').toNumber() === 0) {
      log('Creating default network topology in Neo4j', 'neo4j');
      
      // Create some basic devices
      await upsertDevice({ id: 'router1', name: 'Edge Router', type: 'router', ip: '192.168.1.1' });
      await upsertDevice({ id: 'firewall1', name: 'Main Firewall', type: 'firewall', ip: '192.168.1.2' });
      await upsertDevice({ id: 'switch1', name: 'Core Switch', type: 'switch', ip: '192.168.1.3' });
      await upsertDevice({ id: 'server1', name: 'Web Server', type: 'server', ip: '192.168.1.10' });
      await upsertDevice({ id: 'server2', name: 'Database Server', type: 'server', ip: '192.168.1.11' });
      await upsertDevice({ id: 'client1', name: 'Client 1', type: 'client', ip: '192.168.1.100' });
      
      // Create connections
      await createConnection('router1', 'firewall1');
      await createConnection('firewall1', 'switch1');
      await createConnection('switch1', 'server1');
      await createConnection('switch1', 'server2');
      await createConnection('switch1', 'client1');
      
      log('Default network topology created', 'neo4j');
    }
  } catch (error) {
    log(`Error ensuring network topology: ${error}`, 'neo4j');
  }
}

/**
 * Find vulnerable paths in the network
 */
export async function findVulnerablePaths(): Promise<any[]> {
  const query = `
    // Find paths from external devices to critical servers
    MATCH path = (source:Device {type: 'router'})-[:CONNECTS_TO*]->
                  (middle:Device)-[:CONNECTS_TO*]->
                  (target:Device {type: 'server'})
    WHERE source.id <> target.id
    WITH path, source, target, length(path) as pathLength
    ORDER BY pathLength
    RETURN 
      source.id as sourceId,
      source.name as sourceName,
      target.id as targetId, 
      target.name as targetName,
      [node in nodes(path) | node.id] as nodeIds,
      pathLength,
      CASE
        WHEN pathLength <= 2 THEN 'high'
        WHEN pathLength <= 4 THEN 'medium'
        ELSE 'low'
      END as risk
    LIMIT 5
  `;
  
  const records = await runQuery(query);
  
  return records.map(record => ({
    source: {
      id: record.get('sourceId'),
      name: record.get('sourceName')
    },
    target: {
      id: record.get('targetId'),
      name: record.get('targetName')
    },
    path: record.get('nodeIds'),
    pathLength: record.get('pathLength').toNumber(),
    risk: record.get('risk')
  }));
}

// Export functions
export default {
  connectToNeo4j,
  closeNeo4j,
  runQuery,
  initializeSchema,
  upsertDevice,
  createConnection,
  recordNetworkFlow,
  recordAttack,
  mitigateAttack,
  getAttackPropagation,
  findAttackPath,
  createNetworkTopologyModel,
  findVulnerablePaths
};