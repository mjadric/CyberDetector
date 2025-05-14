import { Card } from "@/components/ui/card";

interface NetworkLayer {
  layer: string;
  devices: string;
  status: string;
}

interface AttackDetails {
  target: string;
  type: string;
  sources: string;
  status: string;
}

interface NetworkStructureProps {
  data: NetworkLayer[];
  attackDetails: AttackDetails;
}

export default function NetworkStructure({ data, attackDetails }: NetworkStructureProps) {
  return (
    <Card className="p-4 h-full">
      <h3 className="font-semibold mb-4">Network Structure</h3>
      <div className="space-y-4">
        {data.map((layer, index) => (
          <div key={index} className="p-3 bg-secondary rounded-lg">
            <p className="text-sm font-medium">{layer.layer}</p>
            <div className="text-xs text-muted-foreground mt-1">
              <p>{layer.devices}</p>
              <p className="mt-1">
                Status: 
                <span className={layer.status.includes("Attack") ? "text-[#F59E0B] ml-1" : "text-[#10B981] ml-1"}>
                  {layer.status}
                </span>
              </p>
            </div>
          </div>
        ))}
        
        <div className="p-3 bg-secondary rounded-lg border-l-2 border-[#EF4444]">
          <p className="text-sm font-medium">Attack Details</p>
          <div className="text-xs text-muted-foreground mt-1">
            <p>Target: {attackDetails.target}</p>
            <p>Attack Type: {attackDetails.type}</p>
            <p>Sources: {attackDetails.sources}</p>
            <p>
              Current Status: 
              <span className="text-[#EF4444] ml-1">{attackDetails.status}</span>
            </p>
          </div>
        </div>
      </div>
    </Card>
  );
}
