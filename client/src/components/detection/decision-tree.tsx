import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ArrowRight, AlertCircle, Check, X, AlertTriangle, Shield, Ban } from "lucide-react";

interface DecisionTreeProps {
  thresholds: {
    label: string;
    value: number;
    action: string;
    actionType: "monitor" | "rate-limit" | "filter" | "block";
  }[];
  currentScore?: number;
}

export default function DecisionTree({ thresholds, currentScore }: DecisionTreeProps) {
  const getActionIcon = (actionType: string) => {
    switch (actionType) {
      case "monitor":
        return <AlertCircle className="h-4 w-4 text-blue-500" />;
      case "rate-limit":
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case "filter":
        return <Shield className="h-4 w-4 text-orange-500" />;
      case "block":
        return <Ban className="h-4 w-4 text-red-500" />;
      default:
        return null;
    }
  };
  
  const getActionTextColor = (actionType: string) => {
    switch (actionType) {
      case "monitor":
        return "text-blue-500";
      case "rate-limit":
        return "text-yellow-500";
      case "filter":
        return "text-orange-500";
      case "block":
        return "text-red-500";
      default:
        return "";
    }
  };
  
  const getActionBgColor = (actionType: string) => {
    switch (actionType) {
      case "monitor":
        return "bg-blue-500/10";
      case "rate-limit":
        return "bg-yellow-500/10";
      case "filter":
        return "bg-orange-500/10";
      case "block":
        return "bg-red-500/10";
      default:
        return "";
    }
  };
  
  return (
    <Card>
      <CardHeader>
        <CardTitle>Decision Algorithm</CardTitle>
        <CardDescription>
          How the system decides on mitigation actions based on threat scoring
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {thresholds.map((threshold, index) => (
            <div 
              key={index} 
              className={`
                p-4 rounded-lg border border-border relative
                ${currentScore !== undefined && currentScore >= threshold.value 
                  ? getActionBgColor(threshold.actionType) + " border-2" 
                  : ""}
              `}
            >
              {currentScore !== undefined && currentScore >= threshold.value && (
                <div className="absolute -top-2 -right-2">
                  <Badge variant="outline" className="bg-background border-2 border-primary">
                    Current
                  </Badge>
                </div>
              )}
              
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center">
                  {getActionIcon(threshold.actionType)}
                  <span className={`ml-2 font-medium ${getActionTextColor(threshold.actionType)}`}>
                    {threshold.action}
                  </span>
                </div>
                <span className="text-sm text-muted-foreground">
                  Threshold: {(threshold.value * 100).toFixed(0)}%
                </span>
              </div>
              
              <p className="text-sm text-muted-foreground mb-2">{threshold.label}</p>
              
              {index < thresholds.length - 1 && (
                <div className="flex justify-center mt-4">
                  <ArrowRight className="text-muted-foreground" />
                </div>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}