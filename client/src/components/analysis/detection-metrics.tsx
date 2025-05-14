import { Progress } from "@/components/ui/progress";
import { getPercentageColor } from "@/lib/utils";

interface Metric {
  name: string;
  value: number;
}

interface DetectionMetricsProps {
  metrics: Metric[];
}

export default function DetectionMetrics({ metrics }: DetectionMetricsProps) {
  return (
    <>
      <h3 className="font-semibold mb-4">Detection Metrics</h3>
      <div className="space-y-4">
        {metrics.map((metric, index) => (
          <div key={index}>
            <div className="flex justify-between mb-1">
              <span className="text-sm text-muted-foreground">{metric.name}</span>
              <span className="text-sm font-medium">{metric.value}%</span>
            </div>
            <Progress 
              value={metric.value} 
              className="h-2 bg-secondary"
              indicatorClassName={getPercentageColor(metric.value)}
            />
          </div>
        ))}
      </div>
    </>
  );
}
