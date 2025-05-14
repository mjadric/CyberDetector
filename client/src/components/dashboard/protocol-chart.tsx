import { useEffect, useRef } from "react";
import Chart from "chart.js/auto";
import { chartColors } from "@/lib/utils";

interface ProtocolChartProps {
  data: {
    protocol: string;
    percentage: number;
    color: string;
  }[];
}

export default function ProtocolChart({ data }: ProtocolChartProps) {
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
          type: "doughnut",
          data: {
            labels: data.map(item => item.protocol),
            datasets: [{
              data: data.map(item => item.percentage),
              backgroundColor: [
                chartColors.http,
                chartColors.https,
                chartColors.dns,
                chartColors.ftp,
                chartColors.voip
              ],
              borderWidth: 0
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                display: false
              }
            },
            cutout: "70%"
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
      <h3 className="font-semibold mb-4">Protocol Distribution</h3>
      <div className="chart-container">
        <canvas ref={chartRef}></canvas>
      </div>
      <div className="mt-4 space-y-2">
        {data.map((protocol, index) => (
          <div key={index} className="flex items-center text-sm">
            <div className={`w-3 h-3 rounded-full ${protocol.color} mr-2`}></div>
            <span className="text-muted-foreground">{protocol.protocol}</span>
            <span className="ml-auto font-medium">{protocol.percentage}%</span>
          </div>
        ))}
      </div>
    </>
  );
}
