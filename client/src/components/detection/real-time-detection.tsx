import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Radar, Loader2, Activity, AlertOctagon } from "lucide-react";
import { Progress } from "@/components/ui/progress";

interface RealTimeDetectionProps {
  onRunDetection: () => Promise<any>;
  isAutoRefresh?: boolean;
}

export default function RealTimeDetection({ onRunDetection, isAutoRefresh = false }: RealTimeDetectionProps) {
  const [detection, setDetection] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(isAutoRefresh);
  const [tab, setTab] = useState("overview");
  
  const runDetection = async () => {
    setIsLoading(true);
    try {
      const result = await onRunDetection();
      setDetection(result);
    } catch (error) {
      console.error("Detection error:", error);
    } finally {
      setIsLoading(false);
    }
  };
  
  useEffect(() => {
    // Run detection immediately on mount
    runDetection();
    
    // Set up auto-refresh interval if enabled
    let interval: NodeJS.Timeout | null = null;
    if (autoRefresh) {
      interval = setInterval(() => {
        runDetection();
      }, 30000); // Refresh every 30 seconds
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh]);
  
  const getActionColor = (action: number) => {
    switch (action) {
      case 0: return "bg-blue-500 text-white";
      case 1: return "bg-yellow-500 text-white";
      case 2: return "bg-red-500 text-white";
      case 3: return "bg-orange-500 text-white";
      default: return "bg-slate-500 text-white";
    }
  };
  
  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleString();
    } catch (e) {
      return timestamp;
    }
  };
  
  return (
    <Card className="overflow-hidden">
      <CardHeader>
        <div className="flex justify-between items-center">
          <div>
            <CardTitle className="flex items-center">
              <Radar className="h-5 w-5 mr-2" />
              Real-Time Detection
            </CardTitle>
            <CardDescription>
              Live monitoring and anomaly detection
            </CardDescription>
          </div>
          
          <div className="flex items-center space-x-2">
            {detection && (
              <Badge variant={detection.action > 0 ? "destructive" : "outline"}>
                {detection.action > 0 ? "Threat Detected" : "Normal Traffic"}
              </Badge>
            )}
            
            <Button 
              variant="outline" 
              size="sm" 
              onClick={runDetection}
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Activity className="h-4 w-4 mr-2" />
                  Scan Now
                </>
              )}
            </Button>
          </div>
        </div>
      </CardHeader>
      
      <CardContent>
        {detection ? (
          <div className="space-y-6">
            <Tabs value={tab} onValueChange={setTab}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="details">Technical Details</TabsTrigger>
              </TabsList>
              
              <TabsContent value="overview" className="space-y-4 pt-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <div className="text-sm font-medium">Threat Score</div>
                    <div className="flex items-center">
                      <Progress value={detection.threat_score * 100} className="h-2 flex-1" />
                      <span className="ml-2 text-sm">{(detection.threat_score * 100).toFixed(0)}%</span>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {detection.threat_score < 0.3 ? "Low risk - normal traffic patterns" :
                       detection.threat_score < 0.5 ? "Moderate risk - some anomalies detected" :
                       detection.threat_score < 0.7 ? "High risk - suspicious activity detected" :
                       "Critical risk - active attack detected"}
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="text-sm font-medium">Confidence Level</div>
                    <div className="flex items-center">
                      <Progress value={detection.confidence * 100} className="h-2 flex-1" />
                      <span className="ml-2 text-sm">{(detection.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Certainty level of detection algorithm
                    </div>
                  </div>
                </div>
                
                <div className="bg-muted rounded-lg p-4">
                  <div className="flex items-center mb-2">
                    <AlertOctagon className="h-5 w-5 mr-2" />
                    <h3 className="font-medium">Mitigation Action</h3>
                  </div>
                  
                  <div className="flex items-center">
                    <Badge className={getActionColor(detection.action)}>
                      {detection.mitigation.name}
                    </Badge>
                    <span className="text-sm ml-3">{detection.mitigation.description}</span>
                  </div>
                </div>
                
                <div className="text-xs text-muted-foreground text-right">
                  Last updated: {formatTimestamp(detection.timestamp)}
                </div>
              </TabsContent>
              
              <TabsContent value="details" className="space-y-4 pt-4">
                <div className="bg-muted p-4 rounded-lg">
                  <h3 className="text-sm font-medium mb-2">Feature State Vector</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {detection.state.map((value: number, index: number) => (
                      <div key={index} className="flex justify-between text-xs">
                        <span>Feature {index + 1}</span>
                        <span className="font-mono">{value.toFixed(4)}</span>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="space-y-2">
                  <h3 className="text-sm font-medium">Raw Detection Data</h3>
                  <pre className="text-xs bg-muted p-2 rounded-lg overflow-x-auto">
                    {JSON.stringify(detection, null, 2)}
                  </pre>
                </div>
              </TabsContent>
            </Tabs>
          </div>
        ) : isLoading ? (
          <div className="flex justify-center items-center p-8">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </div>
        ) : (
          <div className="text-center p-8 text-muted-foreground">
            No detection data available
          </div>
        )}
      </CardContent>
    </Card>
  );
}