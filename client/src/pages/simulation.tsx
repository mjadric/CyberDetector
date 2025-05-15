import { useQuery, useMutation } from "@tanstack/react-query";
import NetworkTopology from "@/components/simulation/network-topology";
import NetworkStructure from "@/components/simulation/network-structure";
import TrafficPath from "@/components/simulation/traffic-path";
import VulnerabilityAnalysis from "@/components/simulation/vulnerability-analysis";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Slider } from "@/components/ui/slider";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { RefreshCw, Layout, AlertTriangle, Network, LineChart, Play } from "lucide-react";
import { useState, useEffect } from "react";

export default function Simulation() {
  // Topology view state
  const [topologyView, setTopologyView] = useState("Hierarchical View");
  
  // Traffic simulation state
  const [activeTab, setActiveTab] = useState("topology");
  const [simulationType, setSimulationType] = useState("syn_flood");
  const [simulationIntensity, setSimulationIntensity] = useState(0.7);
  const [simulationDuration, setSimulationDuration] = useState(60);
  const [simulationStatus, setSimulationStatus] = useState({
    isSimulating: false,
    progress: 0,
    startTime: null as Date | null,
    endTime: null as Date | null
  });
  const [simulationResult, setSimulationResult] = useState<any>(null);
  const [trafficFeatures, setTrafficFeatures] = useState<number[]>([]);
  
  // Progress tracking for simulation
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;
    
    if (simulationStatus.isSimulating && simulationStatus.startTime) {
      interval = setInterval(() => {
        const elapsed = new Date().getTime() - simulationStatus.startTime!.getTime();
        const progress = Math.min(100, (elapsed / (simulationDuration * 1000)) * 100);
        
        setSimulationStatus(prev => ({
          ...prev,
          progress
        }));
        
        if (progress >= 100) {
          setSimulationStatus(prev => ({
            ...prev,
            isSimulating: false,
            endTime: new Date()
          }));
          
          if (interval) clearInterval(interval);
        }
      }, 100);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [simulationStatus.isSimulating, simulationStatus.startTime, simulationDuration]);
  
  // Network data queries
  const { data: networkTopology, isLoading: isLoadingNetworkTopology } = useQuery({
    queryKey: ['/api/network-topology'],
  });
  
  const { data: trafficPaths, isLoading: isLoadingTrafficPaths } = useQuery({
    queryKey: ['/api/traffic-paths'],
  });
  
  const { data: vulnerabilityAnalysis, isLoading: isLoadingVulnerabilityAnalysis } = useQuery({
    queryKey: ['/api/vulnerability-analysis'],
  });
  
  // Mutation for running simulation
  const runSimulationMutation = useMutation({
    mutationFn: async () => {
      setSimulationStatus({
        isSimulating: true,
        progress: 0,
        startTime: new Date(),
        endTime: null
      });
      
      const response = await fetch('/api/python/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          attack_type: simulationType,
          duration: simulationDuration,
          intensity: simulationIntensity
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to run simulation');
      }
      
      return response.json();
    },
    onSuccess: (data) => {
      console.log("Simulation success:", data);
      setSimulationResult(data);
      
      if (data.features) {
        setTrafficFeatures(data.features);
      }
    },
    onError: (error) => {
      console.error("Simulation error:", error);
      setSimulationStatus({
        isSimulating: false,
        progress: 0,
        startTime: null,
        endTime: null
      });
    }
  });

  const resetView = () => {
    // Would reset the network topology view to default state
    console.log("Reset view");
  };
  
  // Attack type options with their Croatian names
  const attackTypes = [
    { value: "syn_flood", label: "TCP SYN Flood" },
    { value: "udp_flood", label: "UDP Flood" },
    { value: "http_flood", label: "HTTP Flood" },
    { value: "slowloris", label: "Slowloris" },
    { value: "dns_amplification", label: "DNS Amplification" }
  ];

  return (
    <div className="mt-8 space-y-6">
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-2 mb-6">
          <TabsTrigger value="topology" className="flex items-center">
            <Network className="h-4 w-4 mr-2" />
            Mrežna topologija
          </TabsTrigger>
          <TabsTrigger value="simulation" className="flex items-center">
            <LineChart className="h-4 w-4 mr-2" />
            Napredna simulacija prometa
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="topology">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-2xl font-semibold">Network Topology</h2>
              <p className="text-muted-foreground">Interactive visualization of network structure and traffic flow</p>
            </div>
            <div className="flex space-x-3">
              <Button variant="outline" className="flex items-center">
                <Layout className="h-4 w-4 mr-1" />
                {topologyView}
              </Button>
              <Button variant="outline" className="flex items-center" onClick={resetView}>
                <RefreshCw className="h-4 w-4 mr-1" />
                Reset View
              </Button>
            </div>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 mt-4">
            <div className="lg:col-span-3">
              {!isLoadingNetworkTopology && (
                <NetworkTopology data={{
                  nodes: [
                    { id: "router1", name: "R1", type: "router", x: 50, y: 50 },
                    { id: "router2", name: "R2", type: "router", x: 200, y: 50 },
                    { id: "server1", name: "S1", type: "server", x: 50, y: 150 },
                    { id: "server2", name: "S2", type: "server", x: 200, y: 150 },
                    { id: "client1", name: "C1", type: "client", x: 125, y: 250 }
                  ],
                  links: [
                    { source: "router1", target: "router2" },
                    { source: "router1", target: "server1" },
                    { source: "router2", target: "server2" },
                    { source: "router1", target: "client1" },
                    { source: "router2", target: "client1" }
                  ]
                }} />
              )}
            </div>
            
            <div>
              {!isLoadingNetworkTopology && (
                <NetworkStructure 
                  data={[
                    {
                      layer: "Pristupni sloj",
                      devices: "Klijentski uređaji (5)",
                      status: "Normalno"
                    },
                    {
                      layer: "Distribucijski sloj",
                      devices: "Routeri i switchevi (2)",
                      status: "Normalno"
                    },
                    {
                      layer: "Jezgreni sloj",
                      devices: "Serverski sustavi (2)",
                      status: "Pod napadom"
                    }
                  ]}
                  attackDetails={{
                    target: "Server S1",
                    type: "TCP SYN Flood",
                    sources: "Više izvora",
                    status: "Aktivni napad"
                  }}
                />
              )}
            </div>
          </div>
          
          {/* Traffic Path Analysis */}
          {!isLoadingTrafficPaths && (
            <TrafficPath paths={[
              {
                id: 1,
                pathId: "P-001",
                source: "192.168.1.100",
                destination: "10.0.0.5",
                hops: "3",
                trafficVolume: "Medium",
                status: "normal"
              },
              {
                id: 2,
                pathId: "P-002",
                source: "192.168.1.45",
                destination: "10.0.0.10",
                hops: "4",
                trafficVolume: "High",
                status: "anomalous"
              }
            ]} />
          )}
          
          {/* Graph Theory Analysis */}
          {!isLoadingVulnerabilityAnalysis && (
            <VulnerabilityAnalysis data={{
              centrality: [
                { name: "Degree Centrality", value: 0.85 },
                { name: "Betweenness Centrality", value: 0.67 },
                { name: "Closeness Centrality", value: 0.76 }
              ],
              attackPath: {
                probability: 0.78,
                paths: ["client1 → router1 → server1", "client1 → router2 → server2"]
              },
              communities: [
                { name: "Mrežna grupa 1", nodeCount: 3, risk: "high" },
                { name: "Mrežna grupa 2", nodeCount: 2, risk: "medium" }
              ]
            }} />
          )}
        </TabsContent>
        
        <TabsContent value="simulation">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-2xl font-semibold">Napredna simulacija mrežnog prometa</h2>
              <p className="text-muted-foreground">
                Generirajte napredne uzorke mrežnog prometa s različitim vrstama DDoS napada
              </p>
            </div>
            <div>
              <Button 
                variant="default" 
                className="flex items-center"
                disabled={simulationStatus.isSimulating}
                onClick={() => runSimulationMutation.mutate()}
              >
                <Play className="h-4 w-4 mr-1" />
                Pokreni simulaciju
              </Button>
            </div>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
            {/* Simulation Configuration Card */}
            <Card>
              <CardHeader>
                <CardTitle className="text-xl flex items-center">
                  <AlertTriangle className="h-5 w-5 text-yellow-500 mr-2" />
                  Konfiguracija napada
                </CardTitle>
                <CardDescription>
                  Definirajte parametre simulacije DDoS napada
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="attackType">Vrsta napada:</Label>
                    <Select 
                      value={simulationType} 
                      onValueChange={setSimulationType}
                      disabled={simulationStatus.isSimulating}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Odaberite vrstu napada" />
                      </SelectTrigger>
                      <SelectContent>
                        {attackTypes.map(type => (
                          <SelectItem key={type.value} value={type.value}>
                            {type.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <Label htmlFor="intensity">Intenzitet napada:</Label>
                      <span className="text-sm text-muted-foreground">
                        {Math.round(simulationIntensity * 100)}%
                      </span>
                    </div>
                    <Slider
                      id="intensity"
                      min={0.1}
                      max={1.0}
                      step={0.05}
                      value={[simulationIntensity]}
                      onValueChange={(value) => setSimulationIntensity(value[0])}
                      disabled={simulationStatus.isSimulating}
                    />
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>Niski</span>
                      <span>Srednji</span>
                      <span>Visoki</span>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <Label htmlFor="duration">Trajanje (sekunde):</Label>
                      <span className="text-sm text-muted-foreground">
                        {simulationDuration}s
                      </span>
                    </div>
                    <Slider
                      id="duration"
                      min={10}
                      max={300}
                      step={10}
                      value={[simulationDuration]}
                      onValueChange={(value) => setSimulationDuration(value[0])}
                      disabled={simulationStatus.isSimulating}
                    />
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>10s</span>
                      <span>150s</span>
                      <span>300s</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            {/* Simulation Status Card */}
            <Card>
              <CardHeader>
                <CardTitle className="text-xl flex items-center">
                  <Network className="h-5 w-5 mr-2" />
                  Status simulacije
                </CardTitle>
                <CardDescription>
                  Parametri i napredak simulacije napada
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {simulationStatus.isSimulating ? (
                  <div className="space-y-4">
                    <div className="flex justify-between text-sm">
                      <span>Status: <span className="text-green-500">U tijeku</span></span>
                      <span>Napad: {attackTypes.find(t => t.value === simulationType)?.label}</span>
                    </div>
                    <Progress value={simulationStatus.progress} />
                    <p className="text-center text-sm text-muted-foreground">
                      Simuliram {attackTypes.find(t => t.value === simulationType)?.label} napad, intenzitet {Math.round(simulationIntensity * 100)}%
                    </p>
                  </div>
                ) : simulationResult ? (
                  <div className="space-y-4">
                    <div className="flex justify-between text-sm">
                      <span>Status: <span className="text-blue-500">Završeno</span></span>
                      <span>Spremljeno u MongoDB: {simulationResult.mongodb_saved ? 'Da' : 'Ne'}</span>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-primary/10 p-3 rounded-lg">
                        <div className="text-xl font-semibold">{attackTypes.find(t => t.value === simulationType)?.label}</div>
                        <div className="text-xs text-muted-foreground">Vrsta napada</div>
                      </div>
                      <div className="bg-primary/10 p-3 rounded-lg">
                        <div className="text-xl font-semibold">{Math.round(simulationIntensity * 100)}%</div>
                        <div className="text-xs text-muted-foreground">Intenzitet</div>
                      </div>
                    </div>
                    
                    {trafficFeatures.length > 0 && (
                      <div>
                        <div className="text-sm font-medium mb-2">Karakteristike napada:</div>
                        <div className="grid grid-cols-2 gap-2">
                          <div className="text-xs flex items-center justify-between">
                            <span>Izvorišna entropija:</span>
                            <span className="font-mono">{trafficFeatures[0].toFixed(3)}</span>
                          </div>
                          <div className="text-xs flex items-center justify-between">
                            <span>Odredišna entropija:</span>
                            <span className="font-mono">{trafficFeatures[1].toFixed(3)}</span>
                          </div>
                          <div className="text-xs flex items-center justify-between">
                            <span>SYN omjer:</span>
                            <span className="font-mono">{trafficFeatures[2].toFixed(3)}</span>
                          </div>
                          <div className="text-xs flex items-center justify-between">
                            <span>Volumen prometa:</span>
                            <span className="font-mono">{trafficFeatures[3].toFixed(3)}</span>
                          </div>
                          <div className="text-xs flex items-center justify-between">
                            <span>Brzina paketa:</span>
                            <span className="font-mono">{trafficFeatures[4].toFixed(3)}</span>
                          </div>
                          <div className="text-xs flex items-center justify-between">
                            <span>Jedinstveni izvor IP:</span>
                            <span className="font-mono">{trafficFeatures[5].toFixed(3)}</span>
                          </div>
                          <div className="text-xs flex items-center justify-between">
                            <span>Jedinstveni odred. IP:</span>
                            <span className="font-mono">{trafficFeatures[6].toFixed(3)}</span>
                          </div>
                          <div className="text-xs flex items-center justify-between">
                            <span>Distribucija protokola:</span>
                            <span className="font-mono">{trafficFeatures[7].toFixed(3)}</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-8">
                    <Network className="h-16 w-16 text-muted-foreground/50 mb-4" />
                    <p className="text-muted-foreground text-center">
                      Pokrenite simulaciju DDoS napada za prikaz rezultata
                    </p>
                  </div>
                )}
              </CardContent>
              <CardFooter>
                <p className="text-xs text-muted-foreground">
                  * Simulirani promet se sprema u MongoDB za treniranje DDQN modela 
                  i može se koristiti za hibridno treniranje
                </p>
              </CardFooter>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
