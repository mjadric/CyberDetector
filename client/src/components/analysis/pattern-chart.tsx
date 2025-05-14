import { useEffect, useRef } from "react";
import Chart from "chart.js/auto";

interface PatternInsight {
  title: string;
  description: string;
  color: string;
}

interface PatternChartProps {
  data: {
    labels: string[];
    synRatio: number[];
    trafficVolume: number[];
    insights: PatternInsight[];
  };
}

export default function PatternChart({ data }: PatternChartProps) {
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
                label: "SYN Ratio",
                data: data.synRatio,
                borderColor: "hsl(var(--chart-5))",
                backgroundColor: "rgba(239, 68, 68, 0.1)",
                fill: false,
                tension: 0.4,
                yAxisID: "y"
              },
              {
                label: "Traffic Volume (normalized)",
                data: data.trafficVolume,
                borderColor: "hsl(var(--chart-1))",
                backgroundColor: "rgba(59, 130, 246, 0.1)",
                fill: false,
                tension: 0.4,
                yAxisID: "y1"
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
                  color: "hsl(var(--muted-foreground))"
                }
              },
              y: {
                position: "left",
                grid: {
                  color: "rgba(75, 85, 99, 0.2)"
                },
                ticks: {
                  color: "hsl(var(--muted-foreground))"
                },
                min: 0,
                max: 1,
                title: {
                  display: true,
                  text: "SYN Ratio",
                  color: "hsl(var(--muted-foreground))"
                }
              },
              y1: {
                position: "right",
                grid: {
                  display: false
                },
                ticks: {
                  color: "hsl(var(--muted-foreground))"
                },
                min: 0,
                max: 5,
                title: {
                  display: true,
                  text: "Traffic Volume",
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
      <h3 className="font-semibold mb-4">Traffic Pattern Analysis</h3>
      <div className="flex flex-col lg:flex-row lg:space-x-4">
        <div className="lg:w-2/3">
          <div className="chart-container h-64">
            <canvas ref={chartRef}></canvas>
          </div>
        </div>
        <div className="lg:w-1/3 mt-4 lg:mt-0">
          <div className="bg-secondary p-4 rounded-lg h-full">
            <h4 className="font-medium mb-2">Pattern Insights</h4>
            <div className="space-y-3 text-sm">
              {data.insights.map((insight, index) => (
                <div key={index} className={`p-2 border-l-2 ${insight.color}`}>
                  <p className="font-medium">{insight.title}</p>
                  <p className="text-muted-foreground text-xs">{insight.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
