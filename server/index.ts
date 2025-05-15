import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { connectToMongoDB, closeMongoDB } from "./database/mongodb";
import { connectToPostgres, closePostgres } from "./database/postgres";
import { connectToNeo4j, closeNeo4j, initializeSchema } from "./database/neo4j";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  log('SIGTERM signal received. Closing database connections...');
  await closeDatabases();
  process.exit(0);
});

process.on('SIGINT', async () => {
  log('SIGINT signal received. Closing database connections...');
  await closeDatabases();
  process.exit(0);
});

// Function to close all database connections
async function closeDatabases() {
  try {
    await closeMongoDB();
    await closePostgres();
    await closeNeo4j();
    log('All database connections closed');
  } catch (error) {
    log(`Error closing database connections: ${error}`);
  }
}

// Function to initialize database connections
async function initializeDatabases() {
  // Connect to MongoDB
  const mongoConnected = await connectToMongoDB();
  if (mongoConnected) {
    log('MongoDB connection established', 'mongodb');
  } else {
    log('MongoDB connection failed - continuing without MongoDB', 'mongodb');
  }
  
  // Connect to PostgreSQL
  const postgresConnected = await connectToPostgres();
  if (postgresConnected) {
    log('PostgreSQL connection established', 'postgres');
    
    // Check if we need to reset the database
    if (process.env.RESET_DATABASE === 'true') {
      try {
        const { resetDatabase } = await import('./database/postgres');
        log('Resetting PostgreSQL database due to RESET_DATABASE=true env variable', 'postgres');
        const result = await resetDatabase();
        log(`PostgreSQL database reset ${result ? 'successful' : 'failed'}`, 'postgres');
      } catch (resetError) {
        log(`Error resetting database: ${resetError}`, 'postgres');
      }
    }
  } else {
    log('PostgreSQL connection failed - continuing without PostgreSQL', 'postgres');
  }
  
  // Connect to Neo4j
  const neo4jConnected = await connectToNeo4j();
  if (neo4jConnected) {
    log('Neo4j connection established', 'neo4j');
    // Initialize Neo4j schema
    await initializeSchema();
  } else {
    log('Neo4j connection failed - continuing without Neo4j', 'neo4j');
  }
  
  return {
    mongoConnected,
    postgresConnected,
    neo4jConnected
  };
}

(async () => {
  // Initialize database connections
  const dbStatus = await initializeDatabases();
  log(`Database connections: MongoDB=${dbStatus.mongoConnected}, PostgreSQL=${dbStatus.postgresConnected}, Neo4j=${dbStatus.neo4jConnected}`, 'db');
  
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on port 5000
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = 5000;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
  });
})();
