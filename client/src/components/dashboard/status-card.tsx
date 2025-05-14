import { Card } from "@/components/ui/card";

interface StatusCardProps {
  data: {
    id: number;
    name: string;
    value: string;
    change: string;
    icon: string;
    color: string;
  };
}

export default function StatusCard({ data }: StatusCardProps) {
  const isPositiveChange = !data.change.startsWith('-');
  const changeColor = isPositiveChange ? "text-[#EF4444]" : "text-[#10B981]";
  
  // For the Blocked Attacks card, we want green to be positive
  const adjustedChangeColor = data.name === "Blocked Attacks" 
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
