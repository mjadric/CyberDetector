import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import AppLayout from "@/components/layout/app-layout";
import Dashboard from "@/pages/dashboard";
import Analysis from "@/pages/analysis";
import Simulation from "@/pages/simulation";
import Detection from "@/pages/detection";
import Settings from "@/pages/settings";
import DatabaseExplorer from "@/pages/database-explorer";

function Router() {
  return (
    <AppLayout>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route path="/analysis" component={Analysis} />
        <Route path="/simulation" component={Simulation} />
        <Route path="/detection" component={Detection} />
        <Route path="/database" component={DatabaseExplorer} />
        <Route path="/settings" component={Settings} />
        <Route component={NotFound} />
      </Switch>
    </AppLayout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
