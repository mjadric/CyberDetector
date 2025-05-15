import { useQuery } from "@tanstack/react-query";
import { queryClient } from "@/lib/queryClient";
import AlertPanel from "@/components/dashboard/alert-panel";
import StatusCard from "@/components/dashboard/status-card";
import TrafficChart from "@/components/dashboard/traffic-chart";
import ProtocolChart from "@/components/dashboard/protocol-chart";
import AlertHistory from "@/components/dashboard/alert-history";
import IpAnalysis from "@/components/dashboard/ip-analysis";
import { Button } from "@/components/ui/button";
import { Calendar, RefreshCw } from "lucide-react";
import { useState } from "react";

export default function Dashboard() {
  const [timeRange, setTimeRange] = useState("Last 24 hours");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(5000); // 5 sekundi
  
  // Koristimo automatsko osvježavanje preko React Query 
  // Nema potrebe za dodatnim setInterval-om
  
  const { data: metrics, isLoading: isLoadingMetrics } = useQuery({
    queryKey: ['/api/metrics'],
    refetchInterval: autoRefresh ? refreshInterval : false,
  });
  
  const { data: alerts, isLoading: isLoadingAlerts } = useQuery({
    queryKey: ['/api/alerts'],
    refetchInterval: autoRefresh ? refreshInterval : false,
  });
  
  const { data: traffic, isLoading: isLoadingTraffic } = useQuery<any>({
    queryKey: ['/api/traffic'],
    refetchInterval: autoRefresh ? refreshInterval : false,
  });
  
  const { data: protocols, isLoading: isLoadingProtocols } = useQuery<any[]>({
    queryKey: ['/api/protocols'],
    refetchInterval: autoRefresh ? refreshInterval : false,
  });
  
  const { data: ipAnalysis, isLoading: isLoadingIpAnalysis } = useQuery<any[]>({
    queryKey: ['/api/ip-analysis'],
    refetchInterval: autoRefresh ? refreshInterval : false,
  });

  const handleRefresh = () => {
    // invalidate all queries to refresh data
    queryClient.invalidateQueries({ queryKey: ['/api/metrics'] });
    queryClient.invalidateQueries({ queryKey: ['/api/alerts'] });
    queryClient.invalidateQueries({ queryKey: ['/api/traffic'] });
    queryClient.invalidateQueries({ queryKey: ['/api/protocols'] });
    queryClient.invalidateQueries({ queryKey: ['/api/ip-analysis'] });
  };

  return (
    <div className="space-y-6">
      {/* Dashboard Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-semibold">Dashboard</h2>
          <p className="text-muted-foreground">Overview of network status and threats</p>
        </div>
        <div className="flex space-x-2">
          <div className="flex items-center text-sm text-muted-foreground mr-2">
            <div className="h-2 w-2 rounded-full bg-green-500 mr-2 animate-pulse"></div>
            Auto-refresh aktivno
          </div>
          <Button 
            variant="outline" 
            size="sm"
            onClick={handleRefresh}
            className="flex items-center"
          >
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
          <Button 
            variant="outline" 
            size="sm"
            className="flex items-center"
          >
            <Calendar className="h-4 w-4 mr-1" />
            {timeRange}
          </Button>
        </div>
      </div>
      
      {/* Alert Panel */}
      {!isLoadingAlerts && alerts && Array.isArray(alerts) && alerts.length > 0 && (
        <AlertPanel alert={alerts[0]} />
      )}
      
      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {!isLoadingMetrics && metrics && Array.isArray(metrics) && metrics.map((metric: any) => (
          <StatusCard key={metric.id} data={metric} />
        ))}
      </div>
      
      {/* Traffic Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Traffic Volume Chart */}
        <div className="bg-card rounded-lg p-4 lg:col-span-2">
          {!isLoadingTraffic && traffic && (
            <TrafficChart data={traffic} />
          )}
        </div>
        
        {/* Protocol Distribution */}
        <div className="bg-card rounded-lg p-4">
          {!isLoadingProtocols && protocols && Array.isArray(protocols) && (
            <ProtocolChart data={protocols} />
          )}
        </div>
      </div>
      
      {/* Alert History & IP Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alert History */}
        <div className="bg-card rounded-lg p-4 lg:col-span-2">
          {!isLoadingAlerts && alerts && Array.isArray(alerts) && (
            <AlertHistory alerts={alerts} />
          )}
        </div>
        
        {/* IP Analysis */}
        <div className="bg-card rounded-lg p-4">
          {!isLoadingIpAnalysis && ipAnalysis && Array.isArray(ipAnalysis) && (
            <IpAnalysis ipAnalysis={ipAnalysis} />
          )}
        </div>
      </div>
    </div>
  );
}
