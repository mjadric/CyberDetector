import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { queryClient } from "@/lib/queryClient";
import { Status, statusColors } from "@/lib/utils";
import { AlertTriangle, AlertCircle } from "lucide-react";

interface IpEntry {
  ip: string;
  status: Status;
  packets: string;
  firstSeen: string;
}

interface IpAnalysisProps {
  ipAnalysis: IpEntry[];
}

export default function IpAnalysis({ ipAnalysis }: IpAnalysisProps) {
  const { toast } = useToast();
  
  const handleBlockIp = async (ip: string) => {
    try {
      const result = await apiRequest('POST', '/api/block-ip', { ip });
      const response = await result.json();
      
      if (response.success) {
        toast({
          title: "IP Blocked",
          description: `Successfully blocked IP ${ip}`,
        });
        
        // Invalidate queries to refresh data
        queryClient.invalidateQueries({ queryKey: ['/api/ip-analysis'] });
      } else {
        toast({
          variant: "destructive",
          title: "Blocking failed",
          description: response.message,
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Blocking failed",
        description: "An error occurred while trying to block the IP",
      });
    }
  };
  
  return (
    <>
      <h3 className="font-semibold mb-4">Source IP Analysis</h3>
      <div className="space-y-3">
        {ipAnalysis.map((entry, index) => (
          <div key={index} className="p-3 bg-secondary rounded-lg flex items-center">
            <div className="mr-3">
              {entry.status === 'blocked' ? (
                <AlertCircle className="h-5 w-5 text-destructive" />
              ) : (
                <AlertTriangle className="h-5 w-5 text-warning" />
              )}
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <p className="font-medium">{entry.ip}</p>
                <span className={`px-2 py-0.5 rounded-full ${statusColors[entry.status].bg} ${statusColors[entry.status].text} text-xs`}>
                  {entry.status === 'blocked' ? 'Blocked' : 'Suspicious'}
                </span>
              </div>
              <div className="flex items-center text-xs text-muted-foreground mt-1">
                <span>Packets: {entry.packets}</span>
                <span className="mx-2">•</span>
                <span>First seen: {entry.firstSeen}</span>
              </div>
            </div>
            {entry.status !== 'blocked' && (
              <Button
                size="sm"
                variant="destructive"
                className="ml-2 text-xs"
                onClick={() => handleBlockIp(entry.ip)}
              >
                Block
              </Button>
            )}
          </div>
        ))}
      </div>
      <div className="mt-3 flex justify-center">
        <Button variant="link" className="text-sm text-muted-foreground hover:text-foreground transition-all">
          Show All IP Analysis
        </Button>
      </div>
    </>
  );
}
