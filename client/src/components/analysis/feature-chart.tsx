import { useEffect, useRef } from "react";
import Chart from "chart.js/auto";

interface FeatureChartProps {
  data: {
    labels: string[];
    values: number[];
  };
}

export default function FeatureChart({ data }: FeatureChartProps) {
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
          type: "bar",
          data: {
            labels: data.labels,
            datasets: [{
              label: "Weight",
              data: data.values,
              backgroundColor: Array(data.labels.length).fill("hsl(var(--accent))"),
              borderWidth: 0
            }]
          },
          options: {
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                display: false
              }
            },
            scales: {
              x: {
                grid: {
                  color: "rgba(75, 85, 99, 0.2)"
                },
                ticks: {
                  color: "hsl(var(--muted-foreground))"
                }
              },
              y: {
                grid: {
                  display: false
                },
                ticks: {
                  color: "hsl(var(--muted-foreground))"
                }
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
      <h3 className="font-semibold mb-4">Feature Importance</h3>
      <div className="chart-container">
        <canvas ref={chartRef}></canvas>
      </div>
      <div className="mt-4 text-xs text-muted-foreground">
        <p>Based on OneR algorithm weights from the DDQN model</p>
      </div>
    </>
  );
}
