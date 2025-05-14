import { ReactNode } from "react";
import Header from "./header";
import Sidebar from "./sidebar";
import { useLocation } from "wouter";

interface AppLayoutProps {
  children: ReactNode;
}

export default function AppLayout({ children }: AppLayoutProps) {
  const [location] = useLocation();
  
  return (
    <div className="flex flex-col h-screen overflow-hidden">
      <Header />
      
      <main className="flex-1 overflow-hidden flex">
        <Sidebar />
        
        <div className="flex-1 overflow-auto p-4">
          {children}
        </div>
      </main>
    </div>
  );
}
