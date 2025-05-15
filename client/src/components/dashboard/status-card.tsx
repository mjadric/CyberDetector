import { Card } from "@/components/ui/card";

interface StatusCardProps {
  data: {
    id?: number;
    name: string;
    value: string;
    change: string;
    icon: string;
    color: string;
    trend?: string;
  };
}

export default function StatusCard({ data }: StatusCardProps) {
  // Determine if change is positive based on trend or text value
  const isPositiveChange = data.trend 
    ? data.trend === 'up'
    : !data.change.startsWith('-');
  
  // By default: upward red (bad), downward green (good)
  const changeColor = isPositiveChange ? "text-[#EF4444]" : "text-[#10B981]";
  
  // Special cases where upward is good and downward is bad
  const invertedMetricNames = ["Blocked Attacks"];
  const shouldInvertColors = invertedMetricNames.includes(data.name);
  
  // Apply the appropriate color based on context
  const adjustedChangeColor = shouldInvertColors
    ? (isPositiveChange ? "text-[#10B981]" : "text-[#EF4444]")
    : changeColor;
  
  return (
    <Card className="p-4 flex items-center">
      <div className={`mr-4 p-3 rounded-full bg-secondary ${data.color}`}>
        <span className="material-icons">{data.icon}</span>
      </div>
      <div>
        <p className="text-muted-foreground text-sm">{data.name}</p>
        <p className="font-semibold text-xl">{data.value}</p>
      </div>
      <div className="ml-auto">
        <span className={`${adjustedChangeColor} flex items-center text-sm`}>
          <span className="material-icons text-sm">
            {isPositiveChange ? 'arrow_upward' : 'arrow_downward'}
          </span>
          {data.change}
        </span>
      </div>
    </Card>
  );
}
