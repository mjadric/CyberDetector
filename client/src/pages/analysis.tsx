import { useQuery } from "@tanstack/react-query";
import FeatureChart from "@/components/analysis/feature-chart";
import DetectionMetrics from "@/components/analysis/detection-metrics";
import EntropyChart from "@/components/analysis/entropy-chart";
import PatternChart from "@/components/analysis/pattern-chart";
import AttackClassification from "@/components/analysis/attack-classification";
import { Button } from "@/components/ui/button";
import { Download, Plus } from "lucide-react";

export default function Analysis() {
  const { data: featureImportance, isLoading: isLoadingFeatureImportance } = useQuery({
    queryKey: ['/api/feature-importance'],
  });
  
  const { data: detectionMetrics, isLoading: isLoadingDetectionMetrics } = useQuery({
    queryKey: ['/api/detection-metrics'],
  });
  
  const { data: entropyData, isLoading: isLoadingEntropyData } = useQuery({
    queryKey: ['/api/entropy'],
  });
  
  const { data: patternAnalysis, isLoading: isLoadingPatternAnalysis } = useQuery({
    queryKey: ['/api/pattern-analysis'],
  });
  
  const { data: attackClassification, isLoading: isLoadingAttackClassification } = useQuery({
    queryKey: ['/api/attack-classification'],
  });

  return (
    <div className="mt-8 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-semibold">Network Analysis</h2>
          <p className="text-muted-foreground">Detailed analysis of traffic patterns and anomalies</p>
        </div>
        <div className="flex space-x-3">
          <Button variant="outline" className="flex items-center">
            <Download className="h-4 w-4 mr-1" />
            Export Data
          </Button>
          <Button className="flex items-center">
            <Plus className="h-4 w-4 mr-1" />
            New Analysis
          </Button>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Feature Importance Chart */}
        <div className="bg-card rounded-lg p-4">
          {!isLoadingFeatureImportance && featureImportance && (
            <FeatureChart data={featureImportance} />
          )}
        </div>
        
        {/* Detection Metrics */}
        <div className="bg-card rounded-lg p-4">
          {!isLoadingDetectionMetrics && detectionMetrics && (
            <DetectionMetrics metrics={detectionMetrics} />
          )}
        </div>
        
        {/* Traffic Entropy */}
        <div className="bg-card rounded-lg p-4">
          {!isLoadingEntropyData && entropyData && (
            <EntropyChart data={entropyData} />
          )}
        </div>
      </div>
      
      {/* Traffic Patterns Analysis */}
      <div className="bg-card rounded-lg p-4">
        {!isLoadingPatternAnalysis && patternAnalysis && (
          <PatternChart data={patternAnalysis} />
        )}
      </div>
      
      {/* Attack Classification */}
      <div className="bg-card rounded-lg p-4">
        {!isLoadingAttackClassification && attackClassification && (
          <AttackClassification data={attackClassification} />
        )}
      </div>
    </div>
  );
}
