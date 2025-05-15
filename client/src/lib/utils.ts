import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(num: number): string {
  if (num >= 1000) {
    return `${(num / 1000).toFixed(1)}K`;
  }
  return num.toString();
}

export function formatTime(date: Date): string {
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

export const severityColors = {
  high: "text-[#EF4444]",
  medium: "text-[#F59E0B]",
  low: "text-[#3B82F6]",
};

export const statusColors = {
  active: {
    bg: "bg-[#EF4444] bg-opacity-20",
    text: "text-[#EF4444]",
  },
  mitigated: {
    bg: "bg-[#10B981] bg-opacity-20",
    text: "text-[#10B981]",
  },
  acknowledged: {
    bg: "bg-[#10B981] bg-opacity-20",
    text: "text-[#10B981]",
  },
  suspicious: {
    bg: "bg-[#F59E0B] bg-opacity-20",
    text: "text-[#F59E0B]",
  },
  normal: {
    bg: "bg-[#10B981] bg-opacity-20",
    text: "text-[#10B981]",
  },
  anomalous: {
    bg: "bg-[#EF4444] bg-opacity-20",
    text: "text-[#EF4444]",
  },
  blocked: {
    bg: "bg-[#EF4444] bg-opacity-20",
    text: "text-[#EF4444]",
  },
};

export type Status = keyof typeof statusColors;
export type Severity = keyof typeof severityColors;

export const chartColors = {
  normalTraffic: "rgba(59, 130, 246, 1)",
  attackTraffic: "rgba(239, 68, 68, 1)",
  http: "rgba(59, 130, 246, 1)",
  https: "rgba(16, 185, 129, 1)",
  dns: "rgba(245, 158, 11, 1)",
  ftp: "rgba(93, 63, 211, 1)",
  voip: "rgba(239, 68, 68, 1)",
};

export const getPercentageColor = (percentage: number): string => {
  if (percentage >= 90) return "bg-[#10B981]";
  if (percentage >= 70) return "bg-[#10B981]";
  if (percentage >= 50) return "bg-[#F59E0B]";
  return "bg-[#EF4444]";
};

export function generateTimeLabels(hours: number = 24): string[] {
  const timeLabels = [];
  for (let i = hours - 1; i >= 0; i--) {
    const hour = new Date();
    hour.setHours(hour.getHours() - i);
    timeLabels.push(`${hour.getHours()}:00`);
  }
  return timeLabels;
}
