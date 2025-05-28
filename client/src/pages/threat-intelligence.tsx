import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Shield, Database, Clock, CheckCircle, AlertTriangle, Activity } from "lucide-react";

interface ThreatSource {
  name: string;
  url: string;
  priority: number;
  lastSync: string;
  isActive: boolean;
}

interface ThreatIntelligenceStatus {
  isActive: boolean;
  sourcesCount: number;
  activeSources: number;
  lastUpdate: string;
  sources: ThreatSource[];
}

export default function ThreatIntelligence() {
  const { data: status, isLoading } = useQuery<ThreatIntelligenceStatus>({
    queryKey: ['/api/threat-intelligence/status'],
    refetchInterval: 30000, // Refresh every 30 seconds for real-time updates
  });

  if (isLoading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-1/3"></div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-32 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2 flex items-center gap-3">
          <Shield className="h-8 w-8 text-blue-600" />
          Real-Time Threat Intelligence
        </h1>
        <p className="text-gray-600">
          Monitor live threat data from multiple sources including government databases and community reports
        </p>
      </div>

      {/* Status Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">System Status</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className={`w-2 h-2 rounded-full ${status?.isActive ? 'bg-green-500' : 'bg-red-500'}`} />
                  <span className="font-semibold">
                    {status?.isActive ? 'Active' : 'Offline'}
                  </span>
                </div>
              </div>
              <Activity className="h-8 w-8 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Sources</p>
                <p className="text-2xl font-bold">{status?.sourcesCount || 0}</p>
              </div>
              <Database className="h-8 w-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Sources</p>
                <p className="text-2xl font-bold text-green-600">{status?.activeSources || 0}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Last Update</p>
                <p className="text-sm font-semibold">
                  {status?.lastUpdate ? new Date(status.lastUpdate).toLocaleTimeString() : 'Never'}
                </p>
              </div>
              <Clock className="h-8 w-8 text-orange-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Threat Sources Details */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Threat Intelligence Sources
          </CardTitle>
          <CardDescription>
            Real-time monitoring of threat databases and intelligence feeds
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {status?.sources.map((source, index) => (
            <div key={index} className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <div className="flex items-center gap-3">
                    <h3 className="font-semibold text-lg">{source.name}</h3>
                    <Badge variant={source.isActive ? "default" : "secondary"}>
                      {source.isActive ? "Active" : "Inactive"}
                    </Badge>
                    <Badge variant="outline" className="text-xs">
                      Priority: {source.priority}/10
                    </Badge>
                  </div>
                  <p className="text-sm text-gray-600">{source.url}</p>
                  <p className="text-xs text-gray-500">
                    Last sync: {new Date(source.lastSync).toLocaleString()}
                  </p>
                </div>
                
                <div className="text-right">
                  {source.isActive ? (
                    <CheckCircle className="h-6 w-6 text-green-500" />
                  ) : (
                    <AlertTriangle className="h-6 w-6 text-yellow-500" />
                  )}
                </div>
              </div>
              
              {/* Priority Progress Bar */}
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Threat Source Priority</span>
                  <span>{source.priority}/10</span>
                </div>
                <Progress value={source.priority * 10} className="h-2" />
              </div>
              
              {index < (status?.sources.length || 0) - 1 && <Separator />}
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Integration Guide */}
      <Card className="mt-8">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Integration Status
          </CardTitle>
          <CardDescription>
            Current integration with official Indian cybersecurity authorities
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-3">
              <h4 className="font-semibold">Government Sources</h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>India Cyber Crime Portal (Simulated)</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>RBI Fraud Database (Simulated)</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>Telecom Regulatory Authority (Simulated)</span>
                </div>
              </div>
            </div>
            
            <div className="space-y-3">
              <h4 className="font-semibold">Community Sources</h4>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>INSAFE Community Reports</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>Real-time Crowd-sourced Intelligence</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span>Cross-verified Threat Patterns</span>
                </div>
              </div>
            </div>
          </div>
          
          <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
            <p className="text-sm text-blue-800">
              <strong>🔒 Data Security Note:</strong> All threat intelligence data is processed securely and complies with Indian data protection regulations. External API integrations can be configured with proper authentication credentials.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}