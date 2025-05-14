import { useEffect, useRef } from "react";
import Chart from "chart.js/auto";
import { Card, CardContent } from "@/components/ui/card";

interface EntropyChartProps {
  data: {
    labels: string[];
    sourceEntropy: number[];
    destEntropy: number[];
    currentSourceEntropy: number;
    currentDestEntropy: number;
    protocolDistribution: number;
    status: string;
  };
}

export default function EntropyChart({ data }: EntropyChartProps) {
  const chartRef = useRef<HTMLCanvasElement>(null);
  const chartInstance = useRef<Chart | null>(null);
  
  useEffect(() => {
    if (chartRef.current) {
      const ctx = chartRef.current.getContext("2d");
      
      if (ctx) {
        // Destroy existing chart instance to prevent memory leaks
        if (chartInstance.current) {
          chartInstance.current.destroy();
        }
        
        chartInstance.current = new Chart(ctx, {
          type: "line",
          data: {
            labels: data.labels,
            datasets: [
              {
                label: "Source IP Entropy",
                data: data.sourceEntropy,
                borderColor: "hsl(var(--chart-1))",
                backgroundColor: "transparent",
                tension: 0.4,
                pointRadius: 0,
                borderWidth: 2
              },
              {
                label: "Destination IP Entropy",
                data: data.destEntropy,
                borderColor: "hsl(var(--chart-2))",
                backgroundColor: "transparent",
                tension: 0.4,
                pointRadius: 0,
                borderWidth: 2
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: "top",
                labels: {
                  color: "hsl(var(--muted-foreground))"
                }
              }
            },
            scales: {
              x: {
                grid: {
                  color: "rgba(75, 85, 99, 0.2)"
                },
                ticks: {
                  color: "hsl(var(--muted-foreground))",
                  maxRotation: 0,
                  autoSkip: true,
                  maxTicksLimit: 6
                }
              },
              y: {
                grid: {
                  color: "rgba(75, 85, 99, 0.2)"
                },
                ticks: {
                  color: "hsl(var(--muted-foreground))"
                },
                min: 0,
                max: 1
              }
            }
          }
        });
      }
    }
    
    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [data]);
  
  return (
    <>
      <h3 className="font-semibold mb-4">Traffic Entropy Analysis</h3>
      <div className="chart-container">
        <canvas ref={chartRef}></canvas>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <div className="bg-secondary p-2 rounded">
          <p className="text-xs text-muted-foreground">Source Entropy</p>
          <p className="font-medium">{data.currentSourceEntropy}</p>
        </div>
        <div className="bg-secondary p-2 rounded">
          <p className="text-xs text-muted-foreground">Destination Entropy</p>
          <p className="font-medium">{data.currentDestEntropy}</p>
        </div>
        <div className="bg-secondary p-2 rounded">
          <p className="text-xs text-muted-foreground">Protocol Distribution</p>
          <p className="font-medium">{data.protocolDistribution}</p>
        </div>
        <div className="bg-secondary p-2 rounded">
          <p className="text-xs text-muted-foreground">Current Status</p>
          <p className="font-medium text-[#F59E0B]">{data.status}</p>
        </div>
      </div>
    </>
  );
}
