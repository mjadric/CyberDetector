import { useState } from 'react';
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Slider } from "@/components/ui/slider";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Radar, FileJson, Zap, Play, Cog, Brain, RefreshCw } from "lucide-react";
import FeatureWeights from "@/components/detection/feature-weights";
import DecisionTree from "@/components/detection/decision-tree";
import RealTimeDetection from "@/components/detection/real-time-detection";
import RecentAlerts from "@/components/detection/recent-alerts";

// Feature weights for the detection algorithm
const featureWeightsData = [
  {
    name: "Source Entropy",
    value: 0.18,
    description: "Entropy of source IP addresses indicating distributed nature of traffic"
  },
  {
    name: "Destination Entropy",
    value: 0.12,
    description: "Entropy of destination IP addresses showing targeting patterns"
  },
  {
    name: "SYN Ratio",
    value: 0.25,
    description: "Ratio of SYN packets to total packets - critical for SYN flood detection"
  },
  {
    name: "Traffic Volume",
    value: 0.15,
    description: "Overall volume of network traffic per time unit"
  },
  {
    name: "Packet Rate",
    value: 0.20,
    description: "Rate of packets per second - key indicator of volumetric attacks"
  },
  {
    name: "Unique Source IPs",
    value: 0.05,
    description: "Number of unique source IP addresses"
  },
  {
    name: "Unique Destination IPs",
    value: 0.02,
    description: "Number of unique destination IP addresses"
  },
  {
    name: "Protocol Distribution",
    value: 0.03,
    description: "Distribution imbalance across network protocols"
  }
];

// Decision thresholds for the detection algorithm
const decisionThresholds = [
  {
    label: "No anomalies detected, normal network traffic patterns",
    value: 0.0,
    action: "Monitor",
    actionType: "monitor" as const
  },
  {
    label: "Minor anomalies detected, increased vigilance recommended",
    value: 0.3,
    action: "Rate Limit",
    actionType: "rate-limit" as const
  },
  {
    label: "Significant anomalies detected, potentially malicious traffic",
    value: 0.5,
    action: "Filter Traffic",
    actionType: "filter" as const
  },
  {
    label: "Attack patterns identified, immediate action required",
    value: 0.7,
    action: "Block Sources",
    actionType: "block" as const
  }
];

export default function Detection() {
  const [activeTab, setActiveTab] = useState("realtime");
  
  // Fetch alerts for the alerts component
  const { data: alerts, isLoading: isLoadingAlerts } = useQuery<any[]>({
    queryKey: ['/api/alerts'],
  });
  
  // Detection state from the most recent scan
  const [detectionResult, setDetectionResult] = useState<any>(null);
  
  // State for hybrid DDQN model training
  const [trainingConfig, setTrainingConfig] = useState({
    episodes: 10,
    batchSize: 32,
    syntheticRatio: 0.5,
  });
  
  // State for tracking training status
  const [trainingStatus, setTrainingStatus] = useState({
    isTraining: false,
    progress: 0,
    message: '',
  });
  
  // Mutation for training the DDQN model
  const trainModelMutation = useMutation({
    mutationFn: async () => {
      setTrainingStatus({
        isTraining: true,
        progress: 10,
        message: 'Inicijalizacija DDQN modela...',
      });
      
      // Call the Python API endpoint for training
      const response = await fetch('/api/python/train', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          episodes: trainingConfig.episodes,
          batch_size: trainingConfig.batchSize,
          synthetic_ratio: trainingConfig.syntheticRatio,
        }),
      });
      
      setTrainingStatus(prev => ({
        ...prev,
        progress: 50,
        message: 'Hibridno treniranje u tijeku...',
      }));
      
      if (!response.ok) {
        throw new Error('Neuspješno treniranje modela');
      }
      
      const result = await response.json();
      
      setTrainingStatus(prev => ({
        ...prev,
        progress: 100,
        message: 'Treniranje završeno!',
      }));
      
      return result;
    },
    onSuccess: (data) => {
      console.log("Training success:", data);
      setTimeout(() => {
        setTrainingStatus({
          isTraining: false,
          progress: 0,
          message: 'Model uspješno treniran',
        });
      }, 2000);
    },
    onError: (error) => {
      console.error("Training error:", error);
      setTrainingStatus({
        isTraining: false,
        progress: 0,
        message: `Greška: ${error}`,
      });
    }
  });
  
  // Mutation for running a detection scan
  const runDetectionMutation = useMutation({
    mutationFn: async () => {
      // Generate sample state features (would normally come from real traffic)
      const sampleState = [
        Math.random() * 0.8, // source_entropy
        Math.random() * 0.5, // destination_entropy
        Math.random() * 0.3, // syn_ratio
        Math.random() * 0.9, // traffic_volume
        Math.random() * 0.7, // packet_rate
        Math.random() * 0.4, // unique_src_ips
        Math.random() * 0.2, // unique_dst_ips
        Math.random() * 0.3  // protocol_distribution
      ];
      
      // Call the Python API endpoint for detection
      const response = await fetch('/api/python/mitigate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ state: sampleState }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to perform detection');
      }
      
      return response.json();
    },
    onSuccess: (data) => {
      setDetectionResult(data);
      // Invalidate alerts cache to show any new alerts that might have been generated
      queryClient.invalidateQueries({ queryKey: ['/api/alerts'] });
    },
  });
  
  // Handler for running detection
  const handleRunDetection = async () => {
    return runDetectionMutation.mutateAsync();
  };
  
  // Simulation mutation for running an attack simulation
  const runSimulationMutation = useMutation({
    mutationFn: async (type: string) => {
      const response = await fetch('/api/python/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          attack_type: type,
          duration: 60,
          intensity: 0.8
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to run simulation');
      }
      
      return response.json();
    },
    onSuccess: () => {
      // After simulation, immediately run detection
      handleRunDetection();
    },
  });

  return (
    <div className="mt-8 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-semibold">DDoS Detection</h2>
          <p className="text-muted-foreground">Real-time traffic analysis and threat detection</p>
        </div>
        <div className="flex space-x-3">
          <Button 
            variant="outline" 
            className="flex items-center"
            onClick={() => runSimulationMutation.mutate('tcp_syn_flood')}
            disabled={runSimulationMutation.isPending}
          >
            <Play className="h-4 w-4 mr-1" />
            Simulate Attack
          </Button>
          <Button 
            className="flex items-center"
            onClick={() => handleRunDetection()}
            disabled={runDetectionMutation.isPending}
          >
            <Radar className="h-4 w-4 mr-1" />
            Run Detection
          </Button>
        </div>
      </div>
      
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="realtime" className="flex items-center">
            <Zap className="h-4 w-4 mr-2" />
            Real-time Detection
          </TabsTrigger>
          <TabsTrigger value="model" className="flex items-center">
            <FileJson className="h-4 w-4 mr-2" />
            Model Visualization
          </TabsTrigger>
          <TabsTrigger value="train" className="flex items-center">
            <Brain className="h-4 w-4 mr-2" />
            Hibridni DDQN
          </TabsTrigger>
          <TabsTrigger value="alerts" className="flex items-center">
            <Radar className="h-4 w-4 mr-2" />
            Detection Alerts
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="realtime" className="mt-6">
          <RealTimeDetection 
            onRunDetection={handleRunDetection} 
            isAutoRefresh={true} 
          />
        </TabsContent>
        
        <TabsContent value="model" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <FeatureWeights weights={featureWeightsData} />
            <DecisionTree 
              thresholds={decisionThresholds} 
              currentScore={detectionResult?.threat_score} 
            />
          </div>
        </TabsContent>
        
        <TabsContent value="train" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-xl flex items-center">
                  <Brain className="h-5 w-5 mr-2" />
                  Hibridno treniranje DDQN modela
                </CardTitle>
                <CardDescription>
                  Trenirajte DDQN model s kombinacijom stvarnih i sintetičkih podataka
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="episodes">Broj epizoda:</Label>
                    <div className="flex items-center gap-4">
                      <Slider 
                        id="episodes"
                        min={1} 
                        max={50} 
                        step={1}
                        value={[trainingConfig.episodes]}
                        onValueChange={(value) => setTrainingConfig(prev => ({ ...prev, episodes: value[0] }))}
                        disabled={trainingStatus.isTraining}
                      />
                      <span className="text-right font-medium">{trainingConfig.episodes}</span>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="batchSize">Veličina batcha:</Label>
                    <div className="flex items-center gap-4">
                      <Slider 
                        id="batchSize"
                        min={8} 
                        max={128} 
                        step={8}
                        value={[trainingConfig.batchSize]}
                        onValueChange={(value) => setTrainingConfig(prev => ({ ...prev, batchSize: value[0] }))}
                        disabled={trainingStatus.isTraining}
                      />
                      <span className="text-right font-medium">{trainingConfig.batchSize}</span>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="syntheticRatio">Udio sintetičkih podataka:</Label>
                    <div className="flex items-center gap-4">
                      <Slider 
                        id="syntheticRatio"
                        min={0} 
                        max={1} 
                        step={0.1}
                        value={[trainingConfig.syntheticRatio]}
                        onValueChange={(value) => setTrainingConfig(prev => ({ ...prev, syntheticRatio: value[0] }))}
                        disabled={trainingStatus.isTraining}
                      />
                      <span className="text-right font-medium">{Math.round(trainingConfig.syntheticRatio * 100)}%</span>
                    </div>
                  </div>
                </div>
              </CardContent>
              <CardFooter>
                <Button 
                  className="w-full"
                  onClick={() => trainModelMutation.mutate()} 
                  disabled={trainingStatus.isTraining}
                >
                  <RefreshCw className={`mr-2 h-4 w-4 ${trainingStatus.isTraining ? 'animate-spin' : ''}`} />
                  {trainingStatus.isTraining ? 'Treniranje u tijeku...' : 'Treniraj model'}
                </Button>
              </CardFooter>
            </Card>
            
            <Card>
              <CardHeader>
                <CardTitle className="text-xl flex items-center">
                  <Cog className="h-5 w-5 mr-2" />
                  Status treniranja
                </CardTitle>
                <CardDescription>
                  Prati napredak i performanse treniranja
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {trainingStatus.isTraining ? (
                  <div className="space-y-4">
                    <Progress value={trainingStatus.progress} />
                    <p className="text-center text-muted-foreground">{trainingStatus.message}</p>
                  </div>
                ) : (
                  <div className="space-y-4 pt-6">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="bg-primary/10 p-4 rounded-lg">
                        <div className="text-xl font-semibold">{trainingConfig.episodes}</div>
                        <div className="text-xs text-muted-foreground">Broj epizoda</div>
                      </div>
                      <div className="bg-primary/10 p-4 rounded-lg">
                        <div className="text-xl font-semibold">{trainingConfig.batchSize}</div>
                        <div className="text-xs text-muted-foreground">Veličina batcha</div>
                      </div>
                      <div className="bg-primary/10 p-4 rounded-lg">
                        <div className="text-xl font-semibold">{Math.round(trainingConfig.syntheticRatio * 100)}%</div>
                        <div className="text-xs text-muted-foreground">Sintetički podaci</div>
                      </div>
                      <div className="bg-primary/10 p-4 rounded-lg">
                        <div className="text-xl font-semibold">MongoDB</div>
                        <div className="text-xs text-muted-foreground">Izvor podataka</div>
                      </div>
                    </div>
                    
                    <div className="pt-4">
                      <h4 className="text-sm font-medium mb-2">Prednosti hibridnog pristupa:</h4>
                      <ul className="text-sm text-muted-foreground space-y-1">
                        <li>• Koristi MongoDB podatke za DDoS detekciju</li>
                        <li>• Generira sintetičke podatke kad nema dovoljno stvarnih podataka</li>
                        <li>• Podržava treniranje na specifičnim vrstama napada</li>
                        <li>• Primjenjuje napredne nagrade za poboljšano učenje</li>
                        <li>• Automatski sprema težine modela za buduću upotrebu</li>
                      </ul>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
        
        <TabsContent value="alerts" className="mt-6">
          {!isLoadingAlerts && alerts && (
            <RecentAlerts alerts={alerts as any} />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}