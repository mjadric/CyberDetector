import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { queryClient } from "@/lib/queryClient";
import { AlertTriangle } from "lucide-react";
import { Status, Severity, severityColors } from "@/lib/utils";

interface AlertProps {
  alert: {
    id: number;
    type: string;
    source: string;
    target: string;
    severity: Severity;
    status: Status;
  };
}

export default function AlertPanel({ alert }: AlertProps) {
  const { toast } = useToast();
  
  const handleMitigate = async () => {
    try {
      const result = await apiRequest('POST', '/api/mitigate', { alertId: alert.id });
      const response = await result.json();
      
      if (response.success) {
        toast({
          title: "Attack mitigated",
          description: `Successfully mitigated ${alert.type} attack`,
        });
        
        // Invalidate queries to refresh data
        queryClient.invalidateQueries({ queryKey: ['/api/alerts'] });
      } else {
        toast({
          variant: "destructive",
          title: "Mitigation failed",
          description: response.message,
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Mitigation failed",
        description: "An error occurred while trying to mitigate the attack",
      });
    }
  };
  
  return (
    <div className="bg-card rounded-lg p-4 border-l-4 border-destructive">
      <div className="flex items-start">
        <div className="mr-4">
          <AlertTriangle className="h-5 w-5 text-destructive" />
        </div>
        <div className="flex-1">
          <h3 className="font-semibold">Potential DDoS Attack Detected</h3>
          <p className="text-muted-foreground text-sm">
            {alert.type} attack detected from {alert.source} targeting {alert.target}. 
            Current intensity: {alert.severity === 'high' ? 'High' : alert.severity === 'medium' ? 'Medium' : 'Low'}.
          </p>
        </div>
        <div className="space-x-2 flex">
          <Button variant="secondary" size="sm">
            Details
          </Button>
          <Button variant="destructive" size="sm" onClick={handleMitigate}>
            Mitigate
          </Button>
        </div>
      </div>
    </div>
  );
}
