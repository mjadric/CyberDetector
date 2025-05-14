import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { exec, spawn } from "child_process";
import path from "path";
import { z } from "zod";
import fs from "fs";
import axios from "axios";

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

  return httpServer;
}
