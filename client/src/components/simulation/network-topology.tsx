import { useEffect, useRef } from "react";
import { Card } from "@/components/ui/card";
import { renderNetworkTopology, type NetworkData } from "@/lib/d3-utils";

interface NetworkTopologyProps {
  data: NetworkData;
}

export default function NetworkTopology({ data }: NetworkTopologyProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    if (containerRef.current) {
      const width = containerRef.current.clientWidth;
      const height = 400;
      
      renderNetworkTopology("topologyContainer", data, width, height);
    }
    
    const handleResize = () => {
      if (containerRef.current) {
        const width = containerRef.current.clientWidth;
        const height = 400;
        
        renderNetworkTopology("topologyContainer", data, width, height);
      }
    };
    
    window.addEventListener("resize", handleResize);
    
    return () => {
      window.removeEventListener("resize", handleResize);
    };
  }, [data]);
  
  return (
    <Card className="p-4">
      <div className="network-topology" id="topologyContainer" ref={containerRef}></div>
      <div className="mt-3 text-xs text-muted-foreground flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center">
            <span className="inline-block w-3 h-3 rounded-full bg-[#3B82F6] mr-1"></span>
            <span>Normal Traffic</span>
          </div>
          <div className="flex items-center">
            <span className="inline-block w-3 h-3 rounded-full bg-[#EF4444] mr-1"></span>
            <span>Attack Traffic</span>
          </div>
        </div>
        <div>
          <span>Zoom: 100%</span>
        </div>
      </div>
    </Card>
  );
}
