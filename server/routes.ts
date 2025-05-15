import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { exec, spawn } from "child_process";
import path from "path";
import { z } from "zod";
import fs from "fs";
import axios from "axios";
import { fileURLToPath } from "url";
import { dirname } from "path";
import { MongoClient } from 'mongodb';

// Get current directory equivalent in ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Python backend API URL
const PYTHON_API_URL = "http://localhost:5001";

// Flag to track if Python server is started
let pythonServerStarted = false;

// Function to start Python API server
function startPythonServer() {
  if (pythonServerStarted) return;
  
  console.log("Starting Python API server...");
  
  const pythonProcess = spawn("python3", [
    path.join(__dirname, "run_python_api.py")
  ]);
  
  pythonProcess.stdout.on("data", (data) => {
    console.log(`[Python] ${data.toString().trim()}`);
  });
  
  pythonProcess.stderr.on("data", (data) => {
    console.error(`[Python Error] ${data.toString().trim()}`);
  });
  
  pythonProcess.on("close", (code) => {
    console.log(`Python API server process exited with code ${code}`);
    pythonServerStarted = false;
  });
  
  pythonServerStarted = true;
}

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);
  
  // Database explorer routes
  app.get('/api/database/mongodb', async (req: Request, res: Response) => {
    try {
      // Attempt to connect to MongoDB
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/ddos_defender';
      const client = new MongoClient(mongoUri);
      await client.connect();
      const db = client.db('ddos_defender');
      
      // Get collection names
      const collections = await db.listCollections().toArray();
      const collectionNames = collections.map((c: any) => c.name);
      
      // Get limited documents from each collection
      const data: Record<string, any[]> = {};
      
      for (const collectionName of collectionNames) {
        // Limit to 10 documents per collection to avoid overwhelming the frontend
        const documents = await db.collection(collectionName)
          .find({})
          .sort({ _id: -1 }) // newest documents first
          .limit(10)
          .toArray();
        
        data[collectionName] = documents;
      }
      
      await client.close();
      res.json({ collections: data });
    } catch (error) {
      console.error(`Error fetching MongoDB data: ${error}`);
      res.status(500).json({ error: `Failed to fetch MongoDB data: ${error}` });
    }
  });
  
  // PostgreSQL explorer route
  app.get('/api/database/postgresql', async (req: Request, res: Response) => {
    try {
      const { db } = await import('./db');
      
      // Direktno dohvaćamo podatke iz definiranih tablica u shemi
      const data: Record<string, any[]> = {};
      
      // Popis tablica za koje znamo da postoje
      const tableNames = [
        'users', 
        'network_traffic', 
        'alerts', 
        'network_metrics',
        'dashboard_metrics', 
        'traffic_paths',
        'network_nodes',
        'network_links'
      ];
      
      // Importiramo sve tablice iz shared/schema
      const schema = await import('../shared/schema');
      
      for (const tableName of tableNames) {
        try {
          // Koristimo tablice iz sheme ako postoje, inače preskačemo
          if (schema[tableName]) {
            const rows = await db.select().from(schema[tableName]).limit(10);
            data[tableName] = rows || [];
          } else {
            console.log(`Tablica ${tableName} nije definirana u shemi`);
            data[tableName] = [];
          }
        } catch (err) {
          // Nastavljamo s drugim tablicama ako jedna ne postoji
          console.log(`Tablica ${tableName} nije dostupna: ${err}`);
          data[tableName] = [];
        }
      }
      
      res.json({ tables: data });
    } catch (error) {
      console.error(`Error fetching PostgreSQL data: ${error}`);
      res.status(500).json({ error: `Failed to fetch PostgreSQL data: ${error}` });
    }
  });
  
  // Start Python backend server
  try {
    startPythonServer();
  } catch (error) {
    console.error("Failed to start Python server:", error);
  }
  
  // Python API proxy routes
  app.use("/api/python", async (req: Request, res: Response) => {
    try {
      const pythonUrl = `${PYTHON_API_URL}${req.url}`;
      const method = req.method.toLowerCase();
      
      let pythonResponse;
      if (method === "get") {
        pythonResponse = await axios.get(pythonUrl);
      } else if (method === "post") {
        pythonResponse = await axios.post(pythonUrl, req.body);
      } else {
        return res.status(405).json({ error: "Method not allowed" });
      }
      
      return res.json(pythonResponse.data);
    } catch (error) {
      console.error(`Error proxying to Python API (${req.url}):`, error);
      return res.status(500).json({ 
        error: "Python API server error", 
        message: "Could not connect to Python backend"
      });
    }
  });
  
  // Python status check endpoint
  app.get("/api/python-status", async (req, res) => {
    try {
      const response = await axios.get(`${PYTHON_API_URL}/api/python/status`);
      res.json({ 
        available: true, 
        status: response.data 
      });
    } catch (error) {
      res.json({ 
        available: false, 
        error: "Python backend not available" 
      });
    }
  });

  // Endpoint to get network metrics
  app.get("/api/metrics", async (req, res) => {
    try {
      const metrics = await storage.getLatestNetworkMetrics();
      res.json(metrics);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch network metrics" });
    }
  });

  // Endpoint to get alerts
  app.get("/api/alerts", async (req, res) => {
    try {
      const alerts = await storage.getRecentAlerts();
      res.json(alerts);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch alerts" });
    }
  });

  // Endpoint to get traffic data
  app.get("/api/traffic", async (req, res) => {
    try {
      const traffic = await storage.getTrafficData();
      res.json(traffic);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch traffic data" });
    }
  });

  // Endpoint to get protocol distribution
  app.get("/api/protocols", async (req, res) => {
    try {
      const protocols = await storage.getProtocolDistribution();
      res.json(protocols);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch protocol distribution" });
    }
  });

  // Endpoint to get IP analysis data
  app.get("/api/ip-analysis", async (req, res) => {
    try {
      const ipAnalysis = await storage.getIpAnalysis();
      res.json(ipAnalysis);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch IP analysis data" });
    }
  });

  // Endpoint to get feature importance data
  app.get("/api/feature-importance", async (req, res) => {
    try {
      const featureImportance = await storage.getFeatureImportance();
      res.json(featureImportance);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch feature importance data" });
    }
  });

  // Endpoint to get detection metrics
  app.get("/api/detection-metrics", async (req, res) => {
    try {
      const detectionMetrics = await storage.getDetectionMetrics();
      res.json(detectionMetrics);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch detection metrics" });
    }
  });

  // Endpoint to get entropy data
  app.get("/api/entropy", async (req, res) => {
    try {
      const entropy = await storage.getEntropyData();
      res.json(entropy);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch entropy data" });
    }
  });

  // Endpoint to get pattern analysis data
  app.get("/api/pattern-analysis", async (req, res) => {
    try {
      const patternAnalysis = await storage.getPatternAnalysis();
      res.json(patternAnalysis);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch pattern analysis data" });
    }
  });

  // Endpoint to get attack classification data
  app.get("/api/attack-classification", async (req, res) => {
    try {
      const attackClassification = await storage.getAttackClassification();
      res.json(attackClassification);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch attack classification data" });
    }
  });

  // Endpoint to get network topology data
  app.get("/api/network-topology", async (req, res) => {
    try {
      // Try to get data from Python backend first
      try {
        const pythonResponse = await axios.get(`${PYTHON_API_URL}/api/python/topology`);
        console.log("Using Python backend for network topology data");
        return res.json(pythonResponse.data);
      } catch (pythonError) {
        console.log("Python backend not available, falling back to Node.js implementation");
        // Fall back to Node.js implementation if Python fails
        const networkTopology = await storage.getNetworkTopology();
        res.json(networkTopology);
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch network topology data" });
    }
  });

  // Endpoint to get traffic path data
  app.get("/api/traffic-paths", async (req, res) => {
    try {
      // Try to get data from Python backend first
      try {
        const pythonResponse = await axios.get(`${PYTHON_API_URL}/api/python/traffic-paths`);
        console.log("Using Python backend for traffic paths data");
        return res.json(pythonResponse.data);
      } catch (pythonError) {
        console.log("Python backend not available, falling back to Node.js implementation");
        // Fall back to Node.js implementation if Python fails
        const trafficPaths = await storage.getTrafficPaths();
        res.json(trafficPaths);
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch traffic path data" });
    }
  });

  // Endpoint to get vulnerability analysis data
  app.get("/api/vulnerability-analysis", async (req, res) => {
    try {
      // Try to get data from Python backend first
      try {
        const pythonResponse = await axios.get(`${PYTHON_API_URL}/api/python/vulnerability`);
        console.log("Using Python backend for vulnerability analysis data");
        return res.json(pythonResponse.data);
      } catch (pythonError) {
        console.log("Python backend not available, falling back to Node.js implementation");
        // Fall back to Node.js implementation if Python fails
        const vulnerabilityAnalysis = await storage.getVulnerabilityAnalysis();
        res.json(vulnerabilityAnalysis);
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch vulnerability analysis data" });
    }
  });

  // Endpoint to mitigate an attack
  app.post("/api/mitigate", async (req, res) => {
    try {
      const schema = z.object({
        alertId: z.number(),
      });
      
      const validatedData = schema.parse(req.body);
      const result = await storage.mitigateAttack(validatedData.alertId);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "Failed to mitigate attack" });
    }
  });

  // Endpoint to block an IP
  app.post("/api/block-ip", async (req, res) => {
    try {
      const schema = z.object({
        ip: z.string(),
      });
      
      const validatedData = schema.parse(req.body);
      const result = await storage.blockIp(validatedData.ip);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "Failed to block IP" });
    }
  });

  // Endpoint to run Python analysis script
  app.post("/api/run-analysis", async (req, res) => {
    try {
      const scriptPath = path.join(__dirname, "analysis", "traffic_analyzer.py");
      
      // Execute Python script using child_process
      exec(`python ${scriptPath}`, (error, stdout, stderr) => {
        if (error) {
          console.error(`Error executing Python script: ${error}`);
          return res.status(500).json({ error: "Failed to run analysis" });
        }
        
        if (stderr) {
          console.error(`Python script stderr: ${stderr}`);
        }
        
        const result = JSON.parse(stdout);
        res.json(result);
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to run analysis" });
    }
  });
  
  // Database maintenance route (admin only)
  app.post("/api/admin/reset-database", async (req, res) => {
    try {
      // This should be protected with proper authentication in production
      // Import the resetDatabase function
      const { resetDatabase } = await import('./database/postgres');
      
      // Reset the database
      const result = await resetDatabase();
      
      if (result) {
        // Set environment variable for the current process only
        process.env.RESET_DATABASE = 'true';
        res.json({ success: true, message: 'Database reset successfully' });
      } else {
        res.status(500).json({ success: false, message: 'Failed to reset database' });
      }
    } catch (error) {
      res.status(500).json({ success: false, error: (error as Error).message });
    }
  });
  
  // Configure Neo4j connection
  app.post("/api/admin/configure-neo4j", async (req, res) => {
    try {
      const schema = z.object({
        uri: z.string().min(1),
        username: z.string().min(1),
        password: z.string().min(1)
      });
      
      const validatedData = schema.parse(req.body);
      
      // Set environment variables
      process.env.NEO4J_URI = validatedData.uri;
      process.env.NEO4J_USERNAME = validatedData.username;
      process.env.NEO4J_PASSWORD = validatedData.password;
      
      // Import Neo4j module
      const { connectToNeo4j, initializeSchema } = await import('./database/neo4j');
      
      // Try connection
      const connected = await connectToNeo4j();
      
      if (connected) {
        // Initialize Neo4j schema
        await initializeSchema();
        
        // Update database status
        const { setDatabaseConnectionStatus } = await import('./storage');
        setDatabaseConnectionStatus('neo4j', true);
        
        res.json({ 
          success: true, 
          message: 'Neo4j connection configured successfully' 
        });
      } else {
        res.status(500).json({ 
          success: false, 
          message: 'Failed to connect to Neo4j with provided credentials' 
        });
      }
    } catch (error) {
      res.status(500).json({ 
        success: false, 
        error: (error as Error).message 
      });
    }
  });
  
  // Get database connection status
  app.get("/api/admin/database-status", async (req, res) => {
    try {
      const { getDatabaseConnectionStatus } = await import('./storage');
      res.json(getDatabaseConnectionStatus());
    } catch (error) {
      res.status(500).json({ 
        success: false, 
        error: (error as Error).message 
      });
    }
  });

  return httpServer;
}
