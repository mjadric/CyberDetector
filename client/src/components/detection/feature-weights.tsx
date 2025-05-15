import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

interface FeatureWeightsProps {
  weights: {
    name: string;
    value: number;
    description: string;
  }[];
}

export default function FeatureWeights({ weights }: FeatureWeightsProps) {
  const maxWeight = Math.max(...weights.map(w => w.value));
  
  return (
    <Card>
      <CardHeader>
        <CardTitle>Feature Weights</CardTitle>
        <CardDescription>
          Impact of each feature on DDoS detection and mitigation decisions
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {weights.map((feature, index) => (
            <div key={index} className="space-y-1">
              <div className="flex justify-between text-sm">
                <span className="font-medium">{feature.name}</span>
                <span className="text-muted-foreground">{(feature.value * 100).toFixed(0)}%</span>
              </div>
              <Progress value={(feature.value / maxWeight) * 100} className="h-2" />
              <p className="text-xs text-muted-foreground">{feature.description}</p>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}