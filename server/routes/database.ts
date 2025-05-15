import { Router, Request, Response } from 'express';
import { log } from '../vite';
import { db } from '../db';
import { MongoClient } from 'mongodb';
import { 
  users, 
  networkTraffic, 
  alerts, 
  networkMetrics, 
  dashboardMetrics, 
  trafficPaths,
  networkNodes,
  networkLinks
} from "@shared/schema";

const router = Router();

// MongoDB konekcija
const getMongoDbConnection = async () => {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/ddos_defender';
  const client = new MongoClient(mongoUri);
  await client.connect();
  return { client, db: client.db('ddos_defender') };
};

// Dohvat MongoDB podataka
router.get('/mongodb', async (req: Request, res: Response) => {
  let mongoClient = null;
  try {
    // Spajanje na MongoDB
    const { client, db } = await getMongoDbConnection();
    mongoClient = client;
    
    // Dohvat imena kolekcija
    const collections = await db.listCollections().toArray();
    const collectionNames = collections.map(c => c.name);
    
    // Ograničeni dohvat dokumenata iz svake kolekcije
    const data: Record<string, any[]> = {};
    
    for (const collectionName of collectionNames) {
      // Limit na 10 dokumenata po kolekciji da ne preopteretimo frontend
      const documents = await db.collection(collectionName)
        .find({})
        .sort({ _id: -1 }) // najnoviji dokumenti prvi
        .limit(10)
        .toArray();
      
      data[collectionName] = documents;
    }
    
    res.json({ collections: data });
  } catch (error) {
    log(`Error fetching MongoDB data: ${error}`, 'mongodb-api');
    res.status(500).json({ error: `Failed to fetch MongoDB data: ${error}` });
  } finally {
    if (mongoClient) {
      await mongoClient.close();
    }
  }
});

// Dohvat PostgreSQL podataka
router.get('/postgresql', async (req: Request, res: Response) => {
  try {
    // Definicija tablica koje želimo dohvatiti
    const tables = [
      users,
      networkTraffic,
      alerts,
      networkMetrics,
      dashboardMetrics,
      trafficPaths,
      networkNodes,
      networkLinks
    ];
    
    const data: Record<string, any[]> = {};
    
    // Dohvat podataka iz svake tablice
    for (const table of tables) {
      // Dohvaćamo ime tablice iz definicije
      const tableName = table._.name;
      
      // Limit na 10 redaka po tablici
      const rows = await db.select().from(table).limit(10);
      
      data[tableName] = rows;
    }
    
    res.json({ tables: data });
  } catch (error) {
    log(`Error fetching PostgreSQL data: ${error}`, 'postgresql-api');
    res.status(500).json({ error: `Failed to fetch PostgreSQL data: ${error}` });
  }
});

export default router;