import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { useState } from "react";

interface SidebarProps {
  isExpanded: boolean;
  onToggle: () => void;
}

export default function Sidebar({ isExpanded, onToggle }: SidebarProps) {
  const [location] = useLocation();
  
  const isActive = (path: string) => location === path;

  const menuItems = [
    { path: "/", icon: "dashboard", label: "Dashboard" },
    { path: "/analysis", icon: "analytics", label: "Analysis" },
    { path: "/simulation", icon: "hub", label: "Simulation" },
    { path: "/detection", icon: "security", label: "Detection" },
    { path: "/database", icon: "storage", label: "Database" },
    { path: "/settings", icon: "settings", label: "Settings" }
  ];
  
  return (
    <div className={cn(
      "flex flex-col py-4 bg-card shadow-md transition-all duration-300 ease-in-out h-full",
      isExpanded ? "w-56" : "w-16"
    )}>
      <button 
        onClick={onToggle}
        className="self-end mr-4 mb-4 text-muted-foreground hover:text-foreground"
      >
        <span className="material-icons">
          {isExpanded ? "chevron_left" : "chevron_right"}
        </span>
      </button>
      
      <div className="flex flex-col items-center">
        {menuItems.map((item) => (
          <Link href={item.path} key={item.path}>
            <div 
              className={cn(
                "flex items-center p-3 rounded-md mb-2 cursor-pointer transition-colors w-full",
                isExpanded ? "mx-3 px-4 justify-start" : "justify-center",
                isActive(item.path) 
                  ? "text-white bg-primary" 
                  : "text-muted-foreground hover:text-foreground hover:bg-accent"
              )}
            >
              <span className="material-icons">
                {item.icon}
              </span>
              {isExpanded && (
                <span className="ml-3">{item.label}</span>
              )}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
