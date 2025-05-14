import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { getPercentageColor } from "@/lib/utils";

interface AttackIndicator {
  name: string;
  color: string;
}

interface Attack {
  attackType: string;
  confidence: number;
  indicators: AttackIndicator[];
  sourceProfile: string;
  recommendedAction: string;
}

interface AttackClassificationProps {
  data: Attack[];
}

export default function AttackClassification({ data }: AttackClassificationProps) {
  return (
    <>
      <h3 className="font-semibold mb-4">Attack Classification</h3>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="text-xs">Attack Type</TableHead>
              <TableHead className="text-xs">Confidence</TableHead>
              <TableHead className="text-xs">Key Indicators</TableHead>
              <TableHead className="text-xs">Source Profile</TableHead>
              <TableHead className="text-xs">Recommended Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((attack, index) => (
              <TableRow key={index} className="text-sm">
                <TableCell className="py-3 font-medium">{attack.attackType}</TableCell>
                <TableCell className="py-3">
                  <div className="flex items-center">
                    <span className="mr-2">{attack.confidence}%</span>
                    <div className="w-16 bg-secondary rounded-full h-1.5">
                      <div 
                        className={`${getPercentageColor(attack.confidence)} h-1.5 rounded-full`} 
                        style={{ width: `${attack.confidence}%` }}
                      ></div>
                    </div>
                  </div>
                </TableCell>
                <TableCell className="py-3">
                  <div className="space-y-1">
                    {attack.indicators.map((indicator, i) => (
                      <div key={i} className="flex items-center text-xs">
                        <span className={`w-3 h-3 rounded-full ${indicator.color} mr-1`}></span>
                        {indicator.name}
                      </div>
                    ))}
                  </div>
                </TableCell>
                <TableCell className="py-3">
                  <span className="px-2 py-1 rounded-full bg-secondary text-xs">
                    {attack.sourceProfile}
                  </span>
                </TableCell>
                <TableCell className="py-3">
                  <Button 
                    size="sm"
                    variant={attack.recommendedAction === "Rate Limit" ? "destructive" : "secondary"}
                    className="text-xs"
                  >
                    {attack.recommendedAction}
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </>
  );
}
