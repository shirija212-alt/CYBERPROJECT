import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Shield, Search, GraduationCap, TrendingUp, Users, AlertTriangle, CheckCircle, Clock } from "lucide-react";

export default function Home() {
  const { data: stats } = useQuery({
    queryKey: ["/api/stats"],
  });

  const { data: recentScans } = useQuery({
    queryKey: ["/api/scans/recent"],
  });

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="bg-gradient-to-br from-blue-600 via-blue-800 to-slate-800 text-white py-16 lg:py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <div className="inline-flex items-center bg-white/10 backdrop-blur rounded-full px-4 py-2 mb-6">
                <Shield className="text-green-400 mr-2" size={16} />
                <span className="text-sm font-medium">Protecting 10M+ Indians from cyber fraud</span>
              </div>
              
              <h1 className="text-4xl lg:text-6xl font-bold mb-6 leading-tight">
                Stop Scams <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-green-400 to-yellow-400">
                  Before They Start
                </span>
              </h1>
              
              <p className="text-xl text-blue-100 mb-8 leading-relaxed">
                Advanced AI-powered protection against loan scams, rummy frauds, phishing attacks, and UPI scams targeting Indians. Get instant verdicts with 95%+ accuracy.
              </p>
              
              <div className="flex flex-col sm:flex-row gap-4">
                <Link href="/scan">
                  <Button size="lg" className="bg-green-600 hover:bg-green-700 text-white px-8 py-4 text-lg">
                    <Search className="mr-3" size={20} />
                    Start Quick Scan
                  </Button>
                </Link>
                <Link href="/learn">
                  <Button size="lg" variant="outline" className="border-white/30 hover:bg-white/10 text-white px-8 py-4 text-lg">
                    <GraduationCap className="mr-3" size={20} />
                    Learn More
                  </Button>
                </Link>
              </div>
              
              <div className="mt-8 flex flex-wrap gap-6 text-blue-100">
                <div className="flex items-center">
                  <CheckCircle className="text-green-400 mr-2" size={16} />
                  <span>Real-time scanning</span>
                </div>
                <div className="flex items-center">
                  <CheckCircle className="text-green-400 mr-2" size={16} />
                  <span>Indian scam database</span>
                </div>
                <div className="flex items-center">
                  <CheckCircle className="text-green-400 mr-2" size={16} />
                  <span>Mobile optimized</span>
                </div>
              </div>
            </div>
            
            <div className="relative">
              <Card className="transform rotate-3 hover:rotate-0 transition-transform duration-500">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                      <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                    </div>
                    <span className="text-slate-600 text-sm font-mono">insafe.gov.in</span>
                  </div>
                  
                  <div className="space-y-4">
                    <div className="bg-gradient-to-r from-red-100 to-red-200 border border-red-300 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-red-700 font-semibold">DANGEROUS SCAM DETECTED</p>
                          <p className="text-slate-600 text-sm font-mono">loanapproval.online</p>
                        </div>
                        <div className="text-right">
                          <div className="text-2xl font-bold text-red-600">97%</div>
                          <div className="text-xs text-red-600">Confidence</div>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-gradient-to-r from-green-100 to-green-200 border border-green-300 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-green-700 font-semibold">SAFE TO PROCEED</p>
                          <p className="text-slate-600 text-sm font-mono">sbi.co.in</p>
                        </div>
                        <div className="text-right">
                          <div className="text-2xl font-bold text-green-600">99%</div>
                          <div className="text-xs text-green-600">Confidence</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="text-center">
              <div className="text-4xl font-bold text-blue-600 mb-2">
                {stats?.totalScans?.toLocaleString() || "2.1M+"}
              </div>
              <div className="text-slate-600">Scans Performed</div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-green-600 mb-2">
                {stats?.scamsBlocked?.toLocaleString() || "89K+"}
              </div>
              <div className="text-slate-600">Scams Blocked</div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-yellow-600 mb-2">
                {stats?.accuracy || "95.8"}%
              </div>
              <div className="text-slate-600">Accuracy Rate</div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-blue-800 mb-2">₹45Cr+</div>
              <div className="text-slate-600">Money Saved</div>
            </div>
          </div>
        </div>
      </section>

      {/* Quick Access Tools */}
      <section className="py-16 bg-slate-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl lg:text-4xl font-bold text-slate-800 mb-4">Quick Protection Tools</h2>
            <p className="text-xl text-slate-600 max-w-3xl mx-auto">
              Access our most popular security tools with a single click
            </p>
          </div>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Link href="/scan?tab=url">
              <Card className="hover:shadow-lg transition-all cursor-pointer group">
                <CardContent className="p-6 text-center">
                  <div className="bg-blue-100 p-3 rounded-lg w-fit mx-auto mb-4 group-hover:scale-110 transition-transform">
                    <Search className="text-blue-600" size={24} />
                  </div>
                  <h3 className="font-semibold text-slate-800 mb-2">URL Scanner</h3>
                  <p className="text-sm text-slate-600">Check suspicious links instantly</p>
                </CardContent>
              </Card>
            </Link>

            <Link href="/scan?tab=sms">
              <Card className="hover:shadow-lg transition-all cursor-pointer group">
                <CardContent className="p-6 text-center">
                  <div className="bg-green-100 p-3 rounded-lg w-fit mx-auto mb-4 group-hover:scale-110 transition-transform">
                    <AlertTriangle className="text-green-600" size={24} />
                  </div>
                  <h3 className="font-semibold text-slate-800 mb-2">SMS Analyzer</h3>
                  <p className="text-sm text-slate-600">Detect scam messages</p>
                </CardContent>
              </Card>
            </Link>

            <Link href="/report">
              <Card className="hover:shadow-lg transition-all cursor-pointer group">
                <CardContent className="p-6 text-center">
                  <div className="bg-orange-100 p-3 rounded-lg w-fit mx-auto mb-4 group-hover:scale-110 transition-transform">
                    <AlertTriangle className="text-orange-600" size={24} />
                  </div>
                  <h3 className="font-semibold text-slate-800 mb-2">Report Scam</h3>
                  <p className="text-sm text-slate-600">Help protect others</p>
                </CardContent>
              </Card>
            </Link>

            <Link href="/analytics">
              <Card className="hover:shadow-lg transition-all cursor-pointer group">
                <CardContent className="p-6 text-center">
                  <div className="bg-purple-100 p-3 rounded-lg w-fit mx-auto mb-4 group-hover:scale-110 transition-transform">
                    <TrendingUp className="text-purple-600" size={24} />
                  </div>
                  <h3 className="font-semibold text-slate-800 mb-2">View Analytics</h3>
                  <p className="text-sm text-slate-600">Real-time threat data</p>
                </CardContent>
              </Card>
            </Link>
          </div>
        </div>
      </section>

      {/* Recent Activity */}
      {recentScans && recentScans.length > 0 && (
        <section className="py-16 bg-white">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between mb-8">
              <h2 className="text-3xl font-bold text-slate-800">Recent Scan Results</h2>
              <Link href="/analytics">
                <Button variant="outline">View All</Button>
              </Link>
            </div>

            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {recentScans.slice(0, 3).map((scan: any) => (
                <Card key={scan.id}>
                  <CardContent className="p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                          scan.verdict === 'safe' ? 'bg-green-100' :
                          scan.verdict === 'suspicious' ? 'bg-yellow-100' : 'bg-red-100'
                        }`}>
                          {scan.verdict === 'safe' ? 
                            <CheckCircle className="text-green-600" size={20} /> :
                            scan.verdict === 'suspicious' ?
                            <AlertTriangle className="text-yellow-600" size={20} /> :
                            <AlertTriangle className="text-red-600" size={20} />
                          }
                        </div>
                        <div>
                          <h3 className="font-semibold text-slate-800 capitalize">{scan.type} Scan</h3>
                          <p className="text-sm text-slate-500 flex items-center">
                            <Clock size={12} className="mr-1" />
                            {new Date(scan.timestamp).toLocaleTimeString()}
                          </p>
                        </div>
                      </div>
                      <span className={`px-2 py-1 text-sm font-medium rounded capitalize ${
                        scan.verdict === 'safe' ? 'bg-green-100 text-green-700' :
                        scan.verdict === 'suspicious' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-red-100 text-red-700'
                      }`}>
                        {scan.verdict}
                      </span>
                    </div>
                    <p className="text-sm text-slate-600 mb-3 truncate">{scan.content}</p>
                    <div className="flex items-center space-x-2">
                      <div className="flex-1 bg-gray-200 rounded-full h-2">
                        <div 
                          className={`h-2 rounded-full ${
                            scan.verdict === 'safe' ? 'bg-green-500' :
                            scan.verdict === 'suspicious' ? 'bg-yellow-500' : 'bg-red-500'
                          }`}
                          style={{ width: `${scan.confidence}%` }}
                        ></div>
                      </div>
                      <span className={`text-sm font-medium ${
                        scan.verdict === 'safe' ? 'text-green-600' :
                        scan.verdict === 'suspicious' ? 'text-yellow-600' : 'text-red-600'
                      }`}>
                        {scan.confidence}%
                      </span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* CTA Section */}
      <section className="py-16 bg-gradient-to-r from-blue-600 via-blue-800 to-slate-800 text-white">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl lg:text-4xl font-bold mb-6">
            Don't Let Scammers Win
          </h2>
          <p className="text-xl text-blue-100 mb-8 leading-relaxed">
            Join millions of Indians in the fight against cyber fraud. Start protecting yourself and your loved ones today.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link href="/scan">
              <Button size="lg" className="bg-green-600 hover:bg-green-700 px-8 py-4 text-lg">
                <Shield className="mr-3" size={20} />
                Start Protection Now
              </Button>
            </Link>
            <Link href="/learn">
              <Button size="lg" variant="outline" className="border-white/30 hover:bg-white/10 text-white px-8 py-4 text-lg">
                <Users className="mr-3" size={20} />
                Learn About Scams
              </Button>
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}
