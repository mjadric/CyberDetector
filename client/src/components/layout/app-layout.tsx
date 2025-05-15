import { ReactNode, useState, useEffect } from "react";
import Header from "./header";
import Sidebar from "./sidebar";
import { useLocation } from "wouter";

interface AppLayoutProps {
  children: ReactNode;
}

export default function AppLayout({ children }: AppLayoutProps) {
  const [location] = useLocation();
  const [sidebarExpanded, setSidebarExpanded] = useState(false);
  
  // Load sidebar preference from localStorage if available
  useEffect(() => {
    const savedState = localStorage.getItem('sidebarExpanded');
    if (savedState !== null) {
      setSidebarExpanded(savedState === 'true');
    }
  }, []);
  
  // Toggle sidebar and save preference
  const toggleSidebar = () => {
    const newState = !sidebarExpanded;
    setSidebarExpanded(newState);
    localStorage.setItem('sidebarExpanded', String(newState));
  };
  
  return (
    <div className="flex flex-col h-screen overflow-hidden">
      <Header />
      
      <main className="flex-1 overflow-hidden flex">
        <Sidebar 
          isExpanded={sidebarExpanded} 
          onToggle={toggleSidebar} 
        />
        
        <div className="flex-1 overflow-auto p-4">
          {children}
        </div>
      </main>
    </div>
  );
}
