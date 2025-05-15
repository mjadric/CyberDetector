import { useState } from 'react';
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Radar, FileJson, Zap, Play } from "lucide-react";
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
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="realtime" className="flex items-center">
            <Zap className="h-4 w-4 mr-2" />
            Real-time Detection
          </TabsTrigger>
          <TabsTrigger value="model" className="flex items-center">
            <FileJson className="h-4 w-4 mr-2" />
            Model Visualization
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
        
        <TabsContent value="alerts" className="mt-6">
          {!isLoadingAlerts && alerts && (
            <RecentAlerts alerts={alerts as any} />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}