import { useQuery } from "@tanstack/react-query";
import NetworkTopology from "@/components/simulation/network-topology";
import NetworkStructure from "@/components/simulation/network-structure";
import TrafficPath from "@/components/simulation/traffic-path";
import VulnerabilityAnalysis from "@/components/simulation/vulnerability-analysis";
import { Button } from "@/components/ui/button";
import { RefreshCw, Layout } from "lucide-react";
import { useState } from "react";

export default function Simulation() {
  const [topologyView, setTopologyView] = useState("Hierarchical View");
  
  const { data: networkTopology, isLoading: isLoadingNetworkTopology } = useQuery({
    queryKey: ['/api/network-topology'],
  });
  
  const { data: trafficPaths, isLoading: isLoadingTrafficPaths } = useQuery({
    queryKey: ['/api/traffic-paths'],
  });
  
  const { data: vulnerabilityAnalysis, isLoading: isLoadingVulnerabilityAnalysis } = useQuery({
    queryKey: ['/api/vulnerability-analysis'],
  });

  const resetView = () => {
    // Would reset the network topology view to default state
    console.log("Reset view");
  };

  return (
    <div className="mt-8 space-y-6">
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
      
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3">
          {!isLoadingNetworkTopology && networkTopology && (
            <NetworkTopology data={networkTopology} />
          )}
        </div>
        
        <div>
          {!isLoadingNetworkTopology && networkTopology && (
            <NetworkStructure 
              data={networkTopology.structure}
              attackDetails={networkTopology.attackDetails}
            />
          )}
        </div>
      </div>
      
      {/* Traffic Path Analysis */}
      {!isLoadingTrafficPaths && trafficPaths && (
        <TrafficPath paths={trafficPaths} />
      )}
      
      {/* Graph Theory Analysis */}
      {!isLoadingVulnerabilityAnalysis && vulnerabilityAnalysis && (
        <VulnerabilityAnalysis data={vulnerabilityAnalysis} />
      )}
    </div>
  );
}
