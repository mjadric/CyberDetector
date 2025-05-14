import { Link, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Shield } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { BellIcon, User } from "lucide-react";
import { useTheme } from "@/hooks/use-theme";

export default function Header() {
  const { theme, setTheme } = useTheme();
  const [location] = useLocation();
  
  return (
    <header className="bg-card shadow-md py-2 px-4 flex items-center justify-between">
      <div className="flex items-center space-x-4">
        <div className="flex items-center">
          <Shield className="mr-2 h-5 w-5 text-accent" />
          <h1 className="text-xl font-semibold">DDoS Defender</h1>
        </div>
        
        <nav className="hidden md:flex space-x-4">
          <Link href="/">
            <div className={`py-2 px-3 text-sm font-medium rounded-md ${
              location === "/" ? "bg-secondary text-secondary-foreground" : "hover:bg-secondary/50 transition-all"
            } flex items-center cursor-pointer`}>
              <span className="material-icons text-sm mr-1">dashboard</span>
              Dashboard
            </div>
          </Link>
          
          <Link href="/analysis">
            <div className={`py-2 px-3 text-sm font-medium rounded-md ${
              location === "/analysis" ? "bg-secondary text-secondary-foreground" : "hover:bg-secondary/50 transition-all"
            } flex items-center cursor-pointer`}>
              <span className="material-icons text-sm mr-1">analytics</span>
              Analysis
            </div>
          </Link>
          
          <Link href="/simulation">
            <div className={`py-2 px-3 text-sm font-medium rounded-md ${
              location === "/simulation" ? "bg-secondary text-secondary-foreground" : "hover:bg-secondary/50 transition-all"
            } flex items-center cursor-pointer`}>
              <span className="material-icons text-sm mr-1">hub</span>
              Simulation
            </div>
          </Link>
          
          <Link href="/settings">
            <div className={`py-2 px-3 text-sm font-medium rounded-md ${
              location === "/settings" ? "bg-secondary text-secondary-foreground" : "hover:bg-secondary/50 transition-all"
            } flex items-center cursor-pointer`}>
              <span className="material-icons text-sm mr-1">settings</span>
              Settings
            </div>
          </Link>
        </nav>
      </div>
      
      <div className="flex items-center space-x-4">
        <div className="relative">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="relative">
                <BellIcon className="h-5 w-5" />
                <span className="absolute top-0 right-0 w-2 h-2 bg-destructive rounded-full"></span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Notifications</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                <div className="flex flex-col">
                  <span className="font-medium">DDoS Attack Detected</span>
                  <span className="text-xs text-muted-foreground">1 minute ago</span>
                </div>
              </DropdownMenuItem>
              <DropdownMenuItem>
                <div className="flex flex-col">
                  <span className="font-medium">Traffic Anomaly Detected</span>
                  <span className="text-xs text-muted-foreground">10 minutes ago</span>
                </div>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="justify-center">
                View all notifications
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        
        <div className="relative">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button 
                variant="ghost" 
                size="icon"
                className="h-8 w-8 rounded-full bg-secondary flex items-center justify-center"
              >
                <User className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>My Account</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem>Profile</DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link href="/settings">
                  <div className="w-full cursor-pointer">Settings</div>
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
                {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem>Log out</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}
