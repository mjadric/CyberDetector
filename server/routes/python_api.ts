import { Router, Request, Response } from 'express';
import { log } from '../vite';
import { spawn } from 'child_process';
import path from 'path';

const router = Router();

// Start Python API server
let pythonApiProcess: any = null;

function startPythonApiServer() {
  if (pythonApiProcess) {
    log('Python API server already running', 'python-api');
    return;
  }

  const pythonScriptPath = path.join(process.cwd(), 'server', 'run_python_api.py');
  
  log(`Starting Python API server from ${pythonScriptPath}`, 'python-api');
  
  // Use Node.js to spawn a Python process
  pythonApiProcess = spawn('python', [pythonScriptPath]);
  
  pythonApiProcess.stdout.on('data', (data: Buffer) => {
    log(`Python API stdout: ${data.toString().trim()}`, 'python-api');
  });
  
  pythonApiProcess.stderr.on('data', (data: Buffer) => {
    log(`Python API stderr: ${data.toString().trim()}`, 'python-api');
  });
  
  pythonApiProcess.on('close', (code: number) => {
    log(`Python API server exited with code ${code}`, 'python-api');
    pythonApiProcess = null;
  });
}

// Start the Python API server when this module is imported
startPythonApiServer();

// Cleanup function to properly terminate the Python API server
export function shutdownPythonApiServer() {
  if (pythonApiProcess) {
    log('Shutting down Python API server', 'python-api');
    pythonApiProcess.kill();
    pythonApiProcess = null;
  }
}

// API endpoint to check the status of the Python API server
router.get('/status', (req: Request, res: Response) => {
  if (pythonApiProcess) {
    res.json({ status: 'running' });
  } else {
    res.json({ status: 'stopped' });
    // Try to restart the server
    startPythonApiServer();
  }
});

// API endpoint to restart the Python API server
router.post('/restart', (req: Request, res: Response) => {
  // Kill existing process if any
  if (pythonApiProcess) {
    log('Restarting Python API server', 'python-api');
    pythonApiProcess.kill();
    pythonApiProcess = null;
  }
  
  // Start a new process
  startPythonApiServer();
  
  res.json({ status: 'restarting' });
});

// API endpoints for visualization data

// Network metrics
router.get('/metrics/network', async (req: Request, res: Response) => {
  try {
    // Forward the request to the Python API
    const response = await fetch('http://localhost:5001/api/metrics/network');
    
    if (response.ok) {
      const data = await response.json();
      res.json(data);
    } else {
      res.status(response.status).json({ error: 'Error fetching network metrics from Python API' });
    }
  } catch (error) {
    log(`Error in /metrics/network endpoint: ${error}`, 'python-api');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Traffic data
router.get('/visualization/traffic', async (req: Request, res: Response) => {
  try {
    // Forward the request to the Python API
    const response = await fetch('http://localhost:5001/api/visualization/traffic');
    
    if (response.ok) {
      const data = await response.json();
      res.json(data);
    } else {
      res.status(response.status).json({ error: 'Error fetching traffic data from Python API' });
    }
  } catch (error) {
    log(`Error in /visualization/traffic endpoint: ${error}`, 'python-api');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protocol distribution
router.get('/visualization/protocol', async (req: Request, res: Response) => {
  try {
    // Forward the request to the Python API
    const response = await fetch('http://localhost:5001/api/visualization/protocol');
    
    if (response.ok) {
      const data = await response.json();
      res.json(data);
    } else {
      res.status(response.status).json({ error: 'Error fetching protocol distribution from Python API' });
    }
  } catch (error) {
    log(`Error in /visualization/protocol endpoint: ${error}`, 'python-api');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Network topology
router.get('/visualization/topology', async (req: Request, res: Response) => {
  try {
    // Forward the request to the Python API
    const response = await fetch('http://localhost:5001/api/visualization/topology');
    
    if (response.ok) {
      const data = await response.json();
      res.json(data);
    } else {
      res.status(response.status).json({ error: 'Error fetching network topology from Python API' });
    }
  } catch (error) {
    log(`Error in /visualization/topology endpoint: ${error}`, 'python-api');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Analysis endpoints

// DDQN training
router.post('/training/start', async (req: Request, res: Response) => {
  try {
    // Forward the request to the Python API
    const response = await fetch('http://localhost:5001/api/training/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(req.body)
    });
    
    if (response.ok) {
      const data = await response.json();
      res.json(data);
    } else {
      res.status(response.status).json({ error: 'Error starting DDQN training in Python API' });
    }
  } catch (error) {
    log(`Error in /training/start endpoint: ${error}`, 'python-api');
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;