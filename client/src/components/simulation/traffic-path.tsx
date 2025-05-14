import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card } from "@/components/ui/card";
import { Status, statusColors } from "@/lib/utils";

interface TrafficPathEntry {
  id: number;
  pathId: string;
  source: string;
  destination: string;
  hops: string;
  trafficVolume: string;
  status: Status;
}

interface TrafficPathProps {
  paths: TrafficPathEntry[];
}

export default function TrafficPath({ paths }: TrafficPathProps) {
  return (
    <Card className="p-4">
      <h3 className="font-semibold mb-4">Traffic Path Analysis</h3>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="text-xs">Path ID</TableHead>
              <TableHead className="text-xs">Source</TableHead>
              <TableHead className="text-xs">Destination</TableHead>
              <TableHead className="text-xs">Hops</TableHead>
              <TableHead className="text-xs">Traffic Volume</TableHead>
              <TableHead className="text-xs">Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paths.map((path) => (
              <TableRow key={path.id} className="text-sm hover:bg-secondary/50 cursor-pointer transition-all">
                <TableCell className="py-2 font-medium">{path.pathId}</TableCell>
                <TableCell className="py-2">{path.source}</TableCell>
                <TableCell className="py-2">{path.destination}</TableCell>
                <TableCell className="py-2">{path.hops}</TableCell>
                <TableCell className="py-2">{path.trafficVolume}</TableCell>
                <TableCell className="py-2">
                  <span className={`px-2 py-1 rounded-full ${statusColors[path.status].bg} ${statusColors[path.status].text} text-xs`}>
                    {path.status === 'normal' ? 'Normal' : 
                     path.status === 'suspicious' ? 'Suspicious' : 'Anomalous'}
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
}
