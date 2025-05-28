import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { 
  TrendingUp, 
  Shield, 
  AlertTriangle, 
  Users, 
  Search, 
  Clock,
  CheckCircle,
  XCircle,
  Smartphone,
  Mail,
  Phone,
  QrCode,
  Flag
} from "lucide-react";

interface ScanStats {
  totalScans: number;
  scamsBlocked: number;
  todayScans: number;
  accuracy: number;
}

interface Scan {
  id: number;
  type: string;
  content: string;
  verdict: string;
  confidence: number;
  riskFactors: string[];
  timestamp: string;
}

export default function Analytics() {
  const { data: stats, isLoading: statsLoading } = useQuery<ScanStats>({
    queryKey: ["/api/stats"],
  });

  const { data: recentScans, isLoading: scansLoading } = useQuery<Scan[]>({
    queryKey: ["/api/scans/recent"],
  });

  const { data: reports } = useQuery({
    queryKey: ["/api/reports"],
  });

  const getVerdictIcon = (verdict: string) => {
    switch (verdict) {
      case 'safe':
        return <CheckCircle className="text-green-600" size={16} />;
      case 'suspicious':
        return <AlertTriangle className="text-yellow-600" size={16} />;
      case 'dangerous':
        return <XCircle className="text-red-600" size={16} />;
      default:
        return <AlertTriangle className="text-gray-600" size={16} />;
    }
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'safe':
        return 'bg-green-100 text-green-700';
      case 'suspicious':
        return 'bg-yellow-100 text-yellow-700';
      case 'dangerous':
        return 'bg-red-100 text-red-700';
      default:
        return 'bg-gray-100 text-gray-700';
    }
  };

  const getScanTypeIcon = (type: string) => {
    switch (type) {
      case 'url':
        return <Search className="text-blue-600" size={16} />;
      case 'sms':
        return <Mail className="text-green-600" size={16} />;
      case 'qr':
        return <QrCode className="text-purple-600" size={16} />;
      case 'apk':
        return <Smartphone className="text-orange-600" size={16} />;
      case 'call':
        return <Phone className="text-slate-600" size={16} />;
      default:
        return <Search className="text-gray-600" size={16} />;
    }
  };

  // Calculate threat statistics
  const threatCategoriesData = recentScans ? recentScans.reduce((acc, scan) => {
    const category = scan.type;
    if (!acc[category]) {
      acc[category] = { safe: 0, suspicious: 0, dangerous: 0 };
    }
    acc[category][scan.verdict]++;
    return acc;
  }, {} as Record<string, Record<string, number>>) : {};

  const totalThreats = recentScans?.filter(scan => 
    scan.verdict === 'suspicious' || scan.verdict === 'dangerous'
  ).length || 0;

  return (
    <div className="min-h-screen py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <TrendingUp className="text-blue-600 mr-3" size={32} />
            <h1 className="text-3xl lg:text-4xl font-bold text-slate-800">Real-time Threat Intelligence</h1>
          </div>
          <p className="text-xl text-slate-600 max-w-3xl mx-auto">
            Live dashboard showing current scam trends and protection statistics across India
          </p>
        </div>

        {/* Main Stats Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          <Card>
            <CardContent className="p-6 text-center">
              <div className="bg-blue-100 p-3 rounded-lg w-fit mx-auto mb-4">
                <Search className="text-blue-600" size={24} />
              </div>
              <div className="text-3xl font-bold text-slate-800 mb-2">
                {statsLoading ? "..." : (stats?.totalScans?.toLocaleString() || "0")}
              </div>
              <div className="text-sm text-slate-600">Total Scans</div>
              <div className="text-xs text-green-600 mt-1">↗ +12% this week</div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6 text-center">
              <div className="bg-red-100 p-3 rounded-lg w-fit mx-auto mb-4">
                <Shield className="text-red-600" size={24} />
              </div>
              <div className="text-3xl font-bold text-slate-800 mb-2">
                {statsLoading ? "..." : (stats?.scamsBlocked?.toLocaleString() || "0")}
              </div>
              <div className="text-sm text-slate-600">Threats Blocked</div>
              <div className="text-xs text-green-600 mt-1">↗ +8% this week</div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6 text-center">
              <div className="bg-green-100 p-3 rounded-lg w-fit mx-auto mb-4">
                <Users className="text-green-600" size={24} />
              </div>
              <div className="text-3xl font-bold text-slate-800 mb-2">
                {statsLoading ? "..." : "892,145"}
              </div>
              <div className="text-sm text-slate-600">Users Protected</div>
              <div className="text-xs text-green-600 mt-1">↗ +15% this week</div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6 text-center">
              <div className="bg-yellow-100 p-3 rounded-lg w-fit mx-auto mb-4">
                <Flag className="text-yellow-600" size={24} />
              </div>
              <div className="text-3xl font-bold text-slate-800 mb-2">
                {reports?.length?.toLocaleString() || "0"}
              </div>
              <div className="text-sm text-slate-600">User Reports</div>
              <div className="text-xs text-green-600 mt-1">↗ +22% this week</div>
            </CardContent>
          </Card>
        </div>

        <div className="grid lg:grid-cols-3 gap-8">
          {/* Recent Scans */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>Recent Scam Detections</span>
                  <Link href="/scan">
                    <Button variant="outline" size="sm">
                      Start Scanning
                    </Button>
                  </Link>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {scansLoading ? (
                  <div className="space-y-4">
                    {[1, 2, 3].map((i) => (
                      <div key={i} className="animate-pulse">
                        <div className="h-16 bg-gray-200 rounded-lg"></div>
                      </div>
                    ))}
                  </div>
                ) : recentScans && recentScans.length > 0 ? (
                  <div className="space-y-4">
                    {recentScans.slice(0, 6).map((scan) => (
                      <div key={scan.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50 transition-colors">
                        <div className="flex items-center space-x-4">
                          <div className="flex items-center space-x-2">
                            {getScanTypeIcon(scan.type)}
                            {getVerdictIcon(scan.verdict)}
                          </div>
                          <div className="flex-1">
                            <p className="font-semibold text-slate-800 capitalize">
                              {scan.type} Scan
                            </p>
                            <p className="text-sm text-slate-600 truncate max-w-md">
                              {scan.content}
                            </p>
                            <p className="text-xs text-slate-500 flex items-center mt-1">
                              <Clock size={10} className="mr-1" />
                              {new Date(scan.timestamp).toLocaleString()}
                            </p>
                          </div>
                        </div>
                        <div className="text-right">
                          <Badge className={getVerdictColor(scan.verdict)}>
                            {scan.verdict.toUpperCase()}
                          </Badge>
                          <div className="text-sm font-medium text-slate-600 mt-1">
                            {scan.confidence}%
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-slate-500">
                    <Search className="mx-auto mb-4 text-slate-400" size={48} />
                    <p className="text-lg font-medium">No scans yet</p>
                    <p className="text-sm">Start scanning URLs, SMS, or files to see results here</p>
                    <Link href="/scan">
                      <Button className="mt-4">Start First Scan</Button>
                    </Link>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Sidebar Stats */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Today's Protection</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-600">Scams Blocked</span>
                    <span className="text-2xl font-bold text-green-600">
                      {totalThreats}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-600">URLs Scanned</span>
                    <span className="text-2xl font-bold text-blue-600">
                      {recentScans?.filter(s => s.type === 'url').length || 0}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-600">Money Saved</span>
                    <span className="text-2xl font-bold text-yellow-600">₹23.5L</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Top Threat Types</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      <span className="text-slate-600">Loan Frauds</span>
                    </div>
                    <span className="font-semibold">47%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                      <span className="text-slate-600">Gaming Scams</span>
                    </div>
                    <span className="font-semibold">28%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                      <span className="text-slate-600">Phishing</span>
                    </div>
                    <span className="font-semibold">15%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-gray-400 rounded-full"></div>
                      <span className="text-slate-600">Others</span>
                    </div>
                    <span className="font-semibold">10%</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>System Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600">Detection Engine</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                      <span className="text-sm text-green-600">Online</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600">Database</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                      <span className="text-sm text-green-600">Operational</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600">API Response</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                      <span className="text-sm text-green-600">Fast</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600">Accuracy Rate</span>
                    <span className="text-sm font-medium text-blue-600">
                      {stats?.accuracy || 95.8}%
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Scan Type Distribution */}
        {recentScans && recentScans.length > 0 && (
          <div className="mt-12">
            <Card>
              <CardHeader>
                <CardTitle>Scan Type Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid md:grid-cols-5 gap-4">
                  {Object.entries(threatCategoriesData).map(([type, data]) => {
                    const total = data.safe + data.suspicious + data.dangerous;
                    const dangerousPercent = total > 0 ? (data.dangerous / total) * 100 : 0;
                    
                    return (
                      <div key={type} className="text-center p-4 border rounded-lg">
                        <div className="flex items-center justify-center mb-2">
                          {getScanTypeIcon(type)}
                          <span className="ml-2 font-semibold capitalize">{type}</span>
                        </div>
                        <div className="text-2xl font-bold text-slate-800 mb-1">{total}</div>
                        <div className="text-sm text-slate-600">Total Scans</div>
                        {dangerousPercent > 0 && (
                          <div className="text-xs text-red-600 mt-1">
                            {dangerousPercent.toFixed(1)}% threats
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
