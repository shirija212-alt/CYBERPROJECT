import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import URLScanner from "@/components/scan-tools/url-scanner";
import SMSScanner from "@/components/scan-tools/sms-scanner";
import QRScanner from "@/components/scan-tools/qr-scanner";
import APKScanner from "@/components/scan-tools/apk-scanner";
import CallScanner from "@/components/scan-tools/call-scanner";
import { Shield, Search, MessageSquare, QrCode, Smartphone, Phone } from "lucide-react";

export default function Scan() {
  const [activeTab, setActiveTab] = useState("url");

  const scanTools = [
    {
      id: "url",
      label: "URL Scanner",
      icon: Search,
      description: "Check if a website or link is safe",
      component: URLScanner,
    },
    {
      id: "sms",
      label: "SMS Analyzer",
      icon: MessageSquare,
      description: "Analyze text messages for scam patterns",
      component: SMSScanner,
    },
    {
      id: "qr",
      label: "QR Scanner",
      icon: QrCode,
      description: "Scan QR codes for malicious content",
      component: QRScanner,
    },
    {
      id: "apk",
      label: "APK Analyzer",
      icon: Smartphone,
      description: "Check Android apps for malicious behavior",
      component: APKScanner,
    },
    {
      id: "call",
      label: "Call Analyzer",
      icon: Phone,
      description: "Analyze call transcripts for scam attempts",
      component: CallScanner,
    },
  ];

  return (
    <div className="min-h-screen py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <Shield className="text-blue-600 mr-3" size={32} />
            <h1 className="text-3xl lg:text-4xl font-bold text-slate-800">Comprehensive Scan Tools</h1>
          </div>
          <p className="text-xl text-slate-600 max-w-3xl mx-auto">
            Multiple layers of protection to detect various types of scams before they can harm you
          </p>
        </div>

        {/* Scan Tools Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-2 lg:grid-cols-5 mb-8">
            {scanTools.map((tool) => {
              const IconComponent = tool.icon;
              return (
                <TabsTrigger
                  key={tool.id}
                  value={tool.id}
                  className="flex items-center space-x-2 p-3"
                >
                  <IconComponent size={16} />
                  <span className="hidden sm:inline">{tool.label}</span>
                </TabsTrigger>
              );
            })}
          </TabsList>

          {scanTools.map((tool) => {
            const ComponentToRender = tool.component;
            return (
              <TabsContent key={tool.id} value={tool.id} className="mt-8">
                <div className="max-w-4xl mx-auto">
                  <div className="text-center mb-8">
                    <div className="flex items-center justify-center mb-4">
                      <tool.icon className="text-blue-600 mr-3" size={28} />
                      <h2 className="text-2xl font-bold text-slate-800">{tool.label}</h2>
                    </div>
                    <p className="text-slate-600">{tool.description}</p>
                  </div>
                  <ComponentToRender />
                </div>
              </TabsContent>
            );
          })}
        </Tabs>

        {/* Security Tips */}
        <div className="mt-16 bg-gradient-to-r from-red-50 to-orange-50 rounded-2xl p-8">
          <h3 className="text-2xl font-bold text-slate-800 mb-6 text-center">
            ⚠️ Common Scam Warning Signs
          </h3>
          <div className="grid md:grid-cols-2 gap-8">
            <div>
              <h4 className="font-semibold text-slate-800 mb-4 flex items-center">
                <span className="text-red-600 mr-2">⚠️</span>
                Suspicious Messages
              </h4>
              <ul className="space-y-2 text-slate-700">
                <li className="flex items-start space-x-2">
                  <span className="text-red-600 mt-1">•</span>
                  <span>"Congratulations! You've won ₹25 lakh in KBC lottery"</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-red-600 mt-1">•</span>
                  <span>"Instant loan approval without documents"</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-red-600 mt-1">•</span>
                  <span>"Your UPI account will be blocked, verify immediately"</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-red-600 mt-1">•</span>
                  <span>"Earn ₹5000 daily by playing rummy"</span>
                </li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold text-slate-800 mb-4 flex items-center">
                <Shield className="text-green-600 mr-2" size={20} />
                Protection Tips
              </h4>
              <ul className="space-y-2 text-slate-700">
                <li className="flex items-start space-x-2">
                  <span className="text-green-600 mt-1">✓</span>
                  <span>Never share OTP or PIN with anyone</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-green-600 mt-1">✓</span>
                  <span>Verify app authenticity before downloading</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-green-600 mt-1">✓</span>
                  <span>Check URLs carefully before clicking</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-green-600 mt-1">✓</span>
                  <span>Report suspicious activities immediately</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
