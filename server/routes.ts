import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { exec } from "child_process";
import path from "path";
import { z } from "zod";
import fs from "fs";

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);

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
      const networkTopology = await storage.getNetworkTopology();
      res.json(networkTopology);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch network topology data" });
    }
  });

  // Endpoint to get traffic path data
  app.get("/api/traffic-paths", async (req, res) => {
    try {
      const trafficPaths = await storage.getTrafficPaths();
      res.json(trafficPaths);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch traffic path data" });
    }
  });

  // Endpoint to get vulnerability analysis data
  app.get("/api/vulnerability-analysis", async (req, res) => {
    try {
      const vulnerabilityAnalysis = await storage.getVulnerabilityAnalysis();
      res.json(vulnerabilityAnalysis);
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
