import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";

export default function Sidebar() {
  const [location] = useLocation();
  
  const isActive = (path: string) => location === path;
  
  return (
    <div className="w-16 flex flex-col items-center py-4 bg-card">
      <Link href="/">
        <div className={cn(
          "p-3 rounded-md mb-2 cursor-pointer",
          isActive("/") ? "text-white bg-primary" : "text-muted-foreground hover:text-foreground"
        )}>
          <span className="material-icons">dashboard</span>
        </div>
      </Link>
      
      <Link href="/analysis">
        <div className={cn(
          "p-3 rounded-md mb-2 cursor-pointer",
          isActive("/analysis") ? "text-white bg-primary" : "text-muted-foreground hover:text-foreground"
        )}>
          <span className="material-icons">analytics</span>
        </div>
      </Link>
      
      <Link href="/simulation">
        <div className={cn(
          "p-3 rounded-md mb-2 cursor-pointer",
          isActive("/simulation") ? "text-white bg-primary" : "text-muted-foreground hover:text-foreground"
        )}>
          <span className="material-icons">hub</span>
        </div>
      </Link>
      
      <Link href="/detection">
        <div className={cn(
          "p-3 rounded-md mb-2 cursor-pointer",
          isActive("/detection") ? "text-white bg-primary" : "text-muted-foreground hover:text-foreground"
        )}>
          <span className="material-icons">security</span>
        </div>
      </Link>
      
      <Link href="/database">
        <div className={cn(
          "p-3 rounded-md mb-2 cursor-pointer",
          isActive("/database") ? "text-white bg-primary" : "text-muted-foreground hover:text-foreground"
        )}>
          <span className="material-icons">storage</span>
        </div>
      </Link>
      
      <Link href="/settings">
        <div className={cn(
          "p-3 rounded-md mb-2 cursor-pointer",
          isActive("/settings") ? "text-white bg-primary" : "text-muted-foreground hover:text-foreground"
        )}>
          <span className="material-icons">settings</span>
        </div>
      </Link>
    </div>
  );
}
