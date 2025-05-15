import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Status, Severity, statusColors, severityColors } from "@/lib/utils";

interface Alert {
  id: number;
  time: string;
  type: string;
  source: string;
  target: string;
  severity: Severity;
  status: Status;
}

interface AlertHistoryProps {
  alerts: Alert[];
}

export default function AlertHistory({ alerts }: AlertHistoryProps) {
  return (
    <>
      <div className="flex justify-between items-center mb-4">
        <h3 className="font-semibold">Alert History</h3>
        <Button 
          variant="outline" 
          size="sm" 
          className="text-xs flex items-center"
        >
          <span className="material-icons text-xs mr-1">filter_list</span>
          Filter
        </Button>
      </div>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="text-xs">Time</TableHead>
              <TableHead className="text-xs">Type</TableHead>
              <TableHead className="text-xs">Source</TableHead>
              <TableHead className="text-xs">Target</TableHead>
              <TableHead className="text-xs">Severity</TableHead>
              <TableHead className="text-xs">Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {alerts.map((alert) => (
              <TableRow key={alert.id} className="text-sm hover:bg-secondary/50 cursor-pointer transition-all">
                <TableCell className="py-2">{alert.time}</TableCell>
                <TableCell className="py-2">{alert.type}</TableCell>
                <TableCell className="py-2">{alert.source}</TableCell>
                <TableCell className="py-2">{alert.target}</TableCell>
                <TableCell className="py-2">
                  <span className={`${severityColors[alert.severity]} font-medium`}>
                    {alert.severity === 'high' ? 'High' : alert.severity === 'medium' ? 'Medium' : 'Low'}
                  </span>
                </TableCell>
                <TableCell className="py-2">
                  <span className={`px-2 py-1 rounded-full ${
                    statusColors[alert.status as Status]?.bg || 
                    (alert.status === 'acknowledged' ? 'bg-[#10B981] bg-opacity-20' : 'bg-[#EF4444] bg-opacity-20')
                  } ${
                    statusColors[alert.status as Status]?.text || 
                    (alert.status === 'acknowledged' ? 'text-[#10B981]' : 'text-[#EF4444]')
                  } text-xs`}>
                    {alert.status === 'active' ? 'Active' : 
                     alert.status === 'acknowledged' ? 'Acknowledged' : 
                     alert.status === 'mitigated' ? 'Mitigated' : 
                     alert.status}
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="mt-3 flex justify-center">
        <Button variant="link" className="text-sm text-muted-foreground hover:text-foreground transition-all">
          View All Alerts
        </Button>
      </div>
    </>
  );
}
