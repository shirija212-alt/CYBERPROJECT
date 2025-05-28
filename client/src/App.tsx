import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Navbar from "@/components/navbar";
import Home from "@/pages/home";
import Scan from "@/pages/scan";
import Learn from "@/pages/learn";
import Report from "@/pages/report";
import Analytics from "@/pages/analytics";
import ThreatIntelligence from "@/pages/threat-intelligence";
import AILearning from "@/pages/ai-learning";
import MobileApp from "@/pages/mobile-app";
import NotFound from "@/pages/not-found";

function Router() {
  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/scan" component={Scan} />
        <Route path="/learn" component={Learn} />
        <Route path="/report" component={Report} />
        <Route path="/analytics" component={Analytics} />
        <Route path="/threat-intelligence" component={ThreatIntelligence} />
        <Route path="/ai-learning" component={AILearning} />
        <Route path="/mobile-app" component={MobileApp} />
        <Route component={NotFound} />
      </Switch>
    </div>
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
