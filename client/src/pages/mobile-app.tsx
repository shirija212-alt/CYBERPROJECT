import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Smartphone, Shield, Download, PlayCircle, Apple, AlertTriangle, CheckCircle, Users, Globe } from "lucide-react";

export default function MobileApp() {
  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8 text-center">
        <h1 className="text-4xl font-bold text-gray-900 mb-4 flex items-center justify-center gap-3">
          <Smartphone className="h-10 w-10 text-blue-600" />
          INSAFE Mobile App
        </h1>
        <p className="text-xl text-gray-600 max-w-3xl mx-auto">
          Native Android & iOS protection against Indian cyber threats. Real-time call screening, SMS filtering, and AI-powered scam detection in your pocket.
        </p>
      </div>

      {/* App Preview Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
        <Card className="p-8">
          <div className="text-center space-y-6">
            <div className="w-32 h-32 bg-gradient-to-br from-blue-500 to-purple-600 rounded-3xl mx-auto flex items-center justify-center">
              <Shield className="h-16 w-16 text-white" />
            </div>
            <div>
              <h2 className="text-2xl font-bold mb-2">INSAFE Mobile</h2>
              <p className="text-gray-600">Your personal cybersecurity guardian</p>
            </div>
            <div className="flex justify-center gap-4">
              <Button className="flex items-center gap-2">
                <PlayCircle className="h-5 w-5" />
                Google Play
              </Button>
              <Button variant="outline" className="flex items-center gap-2">
                <Apple className="h-5 w-5" />
                App Store
              </Button>
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-orange-500" />
              Live Threat Protection
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
                <span className="font-semibold text-red-800">Incoming Call Alert</span>
              </div>
              <p className="text-sm text-red-700">+91-9876543210</p>
              <p className="text-xs text-red-600">⚠️ SCAMMER - 342 reports for Loan Fraud</p>
              <Button size="sm" className="mt-2 bg-red-600 hover:bg-red-700">
                Block & Report
              </Button>
            </div>
            
            <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span className="font-semibold text-green-800">SMS Filtered</span>
              </div>
              <p className="text-sm text-green-700">Suspicious message quarantined</p>
              <p className="text-xs text-green-600">AI detected: KBC lottery scam pattern</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Features Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Shield className="h-5 w-5 text-blue-600" />
              Real-Time Call Screening
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-gray-600">
              <li>• Instant lookup against government databases</li>
              <li>• Auto-block known scammer numbers</li>
              <li>• Caller ID enhancement with threat data</li>
              <li>• Community-powered fraud alerts</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <AlertTriangle className="h-5 w-5 text-orange-600" />
              AI SMS Filtering
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-gray-600">
              <li>• Machine learning scam detection</li>
              <li>• Indian fraud pattern recognition</li>
              <li>• Auto-quarantine suspicious messages</li>
              <li>• Learns from your feedback</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Globe className="h-5 w-5 text-purple-600" />
              Offline Protection
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-gray-600">
              <li>• Works without internet connection</li>
              <li>• Local threat database caching</li>
              <li>• Background sync when online</li>
              <li>• Emergency mode for critical protection</li>
            </ul>
          </CardContent>
        </Card>
      </div>

      {/* Technical Specifications */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <PlayCircle className="h-5 w-5 text-green-600" />
              Android App Features
            </CardTitle>
            <CardDescription>Native Kotlin development with Jetpack Compose</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="font-semibold mb-2">Core Features</h4>
                <ul className="text-sm space-y-1">
                  <li>• Call screening integration</li>
                  <li>• SMS app replacement</li>
                  <li>• Background protection</li>
                  <li>• Contact backup</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2">Security</h4>
                <ul className="text-sm space-y-1">
                  <li>• Android Keystore</li>
                  <li>• Encrypted local DB</li>
                  <li>• Secure API calls</li>
                  <li>• Privacy controls</li>
                </ul>
              </div>
            </div>
            <div className="p-3 bg-green-50 rounded-lg">
              <p className="text-sm text-green-800">
                <strong>Requirements:</strong> Android 8.0+ (API 26), 100MB storage, Phone & SMS permissions
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Apple className="h-5 w-5 text-gray-800" />
              iOS App Features
            </CardTitle>
            <CardDescription>Native Swift development with SwiftUI</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="font-semibold mb-2">Core Features</h4>
                <ul className="text-sm space-y-1">
                  <li>• Call directory extension</li>
                  <li>• Message filter extension</li>
                  <li>• Background app refresh</li>
                  <li>• iCloud sync</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2">Security</h4>
                <ul className="text-sm space-y-1">
                  <li>• iOS Keychain</li>
                  <li>• App Transport Security</li>
                  <li>• Face ID/Touch ID</li>
                  <li>• Privacy dashboard</li>
                </ul>
              </div>
            </div>
            <div className="p-3 bg-blue-50 rounded-lg">
              <p className="text-sm text-blue-800">
                <strong>Requirements:</strong> iOS 14.0+, 100MB storage, Phone & Messages access
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Integration with INSAFE Platform */}
      <Card className="mb-12">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            Seamless Platform Integration
          </CardTitle>
          <CardDescription>
            Mobile app connects directly to your INSAFE threat intelligence platform
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center p-4">
              <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-3">
                <Shield className="h-8 w-8 text-blue-600" />
              </div>
              <h4 className="font-semibold mb-2">Real-Time Sync</h4>
              <p className="text-sm text-gray-600">
                Instant access to threat intelligence updates from government sources and community reports
              </p>
            </div>
            
            <div className="text-center p-4">
              <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-3">
                <AlertTriangle className="h-8 w-8 text-purple-600" />
              </div>
              <h4 className="font-semibold mb-2">AI Learning</h4>
              <p className="text-sm text-gray-600">
                Mobile usage patterns enhance AI models for better threat detection across all platforms
              </p>
            </div>
            
            <div className="text-center p-4">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-3">
                <Globe className="h-8 w-8 text-green-600" />
              </div>
              <h4 className="font-semibold mb-2">Cross-Platform</h4>
              <p className="text-sm text-gray-600">
                View mobile protection activity on web dashboard, sync settings across devices
              </p>
            </div>
          </div>

          <div className="mt-6 p-4 bg-gradient-to-r from-blue-50 to-purple-50 rounded-lg border border-blue-200">
            <h4 className="font-semibold text-blue-800 mb-2">🚀 API Integration Endpoints</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <strong>Real-time Protection:</strong>
                <ul className="mt-1 space-y-1 text-blue-700">
                  <li>• Phone verification API</li>
                  <li>• Official sources integration</li>
                  <li>• WebSocket threat updates</li>
                </ul>
              </div>
              <div>
                <strong>AI Enhancement:</strong>
                <ul className="mt-1 space-y-1 text-blue-700">
                  <li>• Pattern learning sync</li>
                  <li>• Model updates</li>
                  <li>• Feedback integration</li>
                </ul>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Development Status */}
      <Card>
        <CardHeader>
          <CardTitle>📱 Mobile App Development Status</CardTitle>
          <CardDescription>Current progress and next steps for native app development</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                <span className="font-medium">Backend API Integration</span>
              </div>
              <Badge variant="default">Complete</Badge>
            </div>
            
            <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                <span className="font-medium">Threat Intelligence Platform</span>
              </div>
              <Badge variant="default">Complete</Badge>
            </div>
            
            <div className="flex items-center justify-between p-3 bg-yellow-50 rounded-lg">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-yellow-600" />
                <span className="font-medium">Native App Development</span>
              </div>
              <Badge variant="secondary">Ready to Start</Badge>
            </div>
            
            <div className="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
              <div className="flex items-center gap-2">
                <Download className="h-5 w-5 text-blue-600" />
                <span className="font-medium">App Store Deployment</span>
              </div>
              <Badge variant="outline">Planned</Badge>
            </div>
          </div>

          <div className="mt-6 p-4 bg-gradient-to-r from-orange-50 to-red-50 rounded-lg border border-orange-200">
            <h4 className="font-semibold text-orange-800 mb-2">🎯 Next Steps</h4>
            <ol className="text-sm text-orange-700 space-y-1">
              <li>1. Set up native development environments (Android Studio / Xcode)</li>
              <li>2. Implement call screening and SMS filtering core functionality</li>
              <li>3. Integrate with INSAFE API endpoints for real-time protection</li>
              <li>4. Add offline caching and background sync capabilities</li>
              <li>5. Implement UI/UX for threat alerts and user interactions</li>
              <li>6. Beta testing with select users for feedback and refinement</li>
              <li>7. Submit to Google Play Store and Apple App Store</li>
            </ol>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}