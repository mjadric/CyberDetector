import { useEffect, useRef, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import Chart from "chart.js/auto";
import { chartColors } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";

interface TrafficChartProps {
  data?: {
    labels: string[];
    normalData: number[];
    attackData: number[];
  };
}

export default function TrafficChart({ data }: TrafficChartProps) {
  const chartRef = useRef<HTMLCanvasElement>(null);
  const chartInstance = useRef<Chart | null>(null);
  const [selectedProtocol, setSelectedProtocol] = useState("all");
  
  // Fetch data from API with auto-refresh
  const { data: trafficData } = useQuery({
    queryKey: ['/api/traffic'],
    refetchInterval: 3000 // Refresh every 3 seconds
  });
  
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
            labels: chartData.labels,
            datasets: [
              {
                label: "Normal Traffic",
                data: chartData.normalData,
                borderColor: chartColors.normalTraffic,
                backgroundColor: `${chartColors.normalTraffic.replace('1)', '0.1)')}`,
                fill: true,
                tension: 0.4
              },
              {
                label: "Attack Traffic",
                data: chartData.attackData,
                borderColor: chartColors.attackTraffic,
                backgroundColor: `${chartColors.attackTraffic.replace('1)', '0.1)')}`,
                fill: true,
                tension: 0.4
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
                  color: "#94A3B8"
                }
              }
            },
            scales: {
              x: {
                grid: {
                  color: "rgba(75, 85, 99, 0.2)"
                },
                ticks: {
                  color: "#94A3B8"
                }
              },
              y: {
                grid: {
                  color: "rgba(75, 85, 99, 0.2)"
                },
                ticks: {
                  color: "#94A3B8"
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
  }, [data, selectedProtocol]);
  
  return (
    <>
      <div className="mb-4">
        <div className="flex justify-between items-center mb-2">
          <div>
            <h3 className="font-semibold text-lg">Network Traffic Volume</h3>
            <p className="text-sm text-muted-foreground">
              Praćenje količine mrežnog prometa u stvarnom vremenu sa prikazom normalnog i napadačkog prometa
            </p>
          </div>
          <div className="flex space-x-2">
            <Button 
              size="sm" 
              variant={selectedProtocol === "all" ? "default" : "secondary"} 
              className="text-xs" 
              onClick={() => setSelectedProtocol("all")}
            >
              All
            </Button>
            <Button 
              size="sm" 
              variant={selectedProtocol === "http" ? "default" : "secondary"} 
              className="text-xs" 
              onClick={() => setSelectedProtocol("http")}
            >
              HTTP/S
            </Button>
            <Button 
              size="sm" 
              variant={selectedProtocol === "dns" ? "default" : "secondary"} 
              className="text-xs" 
              onClick={() => setSelectedProtocol("dns")}
            >
              DNS
            </Button>
            <Button 
              size="sm" 
              variant={selectedProtocol === "other" ? "default" : "secondary"} 
              className="text-xs" 
              onClick={() => setSelectedProtocol("other")}
            >
              Other
            </Button>
          </div>
        </div>
        <div className="bg-blue-950/30 border border-blue-800/30 p-3 rounded-lg mb-2">
          <div className="flex items-center">
            <div className="h-3 w-3 rounded-full bg-blue-500 mr-2"></div>
            <span className="text-sm">Normal Traffic: Regular network activities</span>
          </div>
          <div className="flex items-center mt-1">
            <div className="h-3 w-3 rounded-full bg-red-500 mr-2"></div>
            <span className="text-sm">Attack Traffic: Potential DDoS and other anomalies</span>
          </div>
        </div>
      </div>
      <div className="chart-container">
        <canvas ref={chartRef}></canvas>
      </div>
    </>
  );
}
