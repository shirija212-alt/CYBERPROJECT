import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Phone, Loader2, AlertTriangle, Shield, Search, PhoneCall } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import ResultCard from "./result-card";

export default function CallScanner() {
  const [transcript, setTranscript] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [result, setResult] = useState(null);
  const [phoneResult, setPhoneResult] = useState(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const scanMutation = useMutation({
    mutationFn: async (transcript: string) => {
      const response = await apiRequest("POST", "/api/scan/call", { transcript });
      return response.json();
    },
    onSuccess: (data) => {
      setResult(data);
      queryClient.invalidateQueries({ queryKey: ["/api/scans/recent"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
    },
    onError: (error: any) => {
      toast({
        title: "Scan Failed",
        description: error.message || "Unable to analyze call transcript. Please try again.",
        variant: "destructive",
      });
    },
  });

  const phoneCheckMutation = useMutation({
    mutationFn: async (phone: string) => {
      const response = await apiRequest("POST", "/api/scan/phone", { phoneNumber: phone });
      return response.json();
    },
    onSuccess: (data) => {
      setPhoneResult(data);
      queryClient.invalidateQueries({ queryKey: ["/api/scans/recent"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
    },
    onError: (error: any) => {
      toast({
        title: "Phone Check Failed",
        description: error.message || "Unable to check phone number. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleScan = () => {
    if (!transcript.trim()) {
      toast({
        title: "Transcript Required",
        description: "Please enter call transcript to analyze.",
        variant: "destructive",
      });
      return;
    }

    setResult(null);
    scanMutation.mutate(transcript);
  };

  const handlePhoneCheck = () => {
    if (!phoneNumber.trim()) {
      toast({
        title: "Phone Number Required",
        description: "Please enter a phone number to check.",
        variant: "destructive",
      });
      return;
    }

    // Basic phone number validation
    const cleanedNumber = phoneNumber.replace(/\D/g, '');
    if (cleanedNumber.length < 10) {
      toast({
        title: "Invalid Phone Number",
        description: "Please enter a valid phone number.",
        variant: "destructive",
      });
      return;
    }

    setPhoneResult(null);
    phoneCheckMutation.mutate(phoneNumber);
  };

  const sampleTranscripts = [
    "Sir, I am calling from RBI headquarters. Your account has been compromised. Please share your OTP to verify your identity and secure your account immediately.",
    "Congratulations! You have been selected for an instant loan of ₹5 lakh. No documents required. Just share your Aadhaar and PAN details to process immediately.",
    "Hello sir, this is from SBI security department. There has been suspicious activity on your account. Please provide your ATM PIN to block unauthorized transactions."
  ];

  const knownScamNumbers = [
    { number: "+91-9876543210", type: "Loan Fraud", reports: 342, lastSeen: "2 hours ago" },
    { number: "+91-8765432109", type: "KBC Lottery Scam", reports: 187, lastSeen: "5 hours ago" },
    { number: "+91-7654321098", type: "Bank Impersonation", reports: 251, lastSeen: "1 day ago" },
    { number: "+91-6543210987", type: "Investment Fraud", reports: 89, lastSeen: "3 hours ago" },
    { number: "+91-5432109876", type: "UPI Fraud", reports: 156, lastSeen: "30 minutes ago" }
  ];

  // Danger Banner Component (Truecaller-style)
  const DangerBanner = ({ phoneData }: { phoneData: any }) => (
    <div className="mb-6 p-4 bg-gradient-to-r from-red-600 to-red-700 text-white rounded-lg border-l-4 border-red-800 animate-pulse">
      <div className="flex items-center space-x-3">
        <div className="bg-white/20 p-2 rounded-full">
          <AlertTriangle className="text-white" size={24} />
        </div>
        <div className="flex-1">
          <h3 className="text-lg font-bold">🚨 DANGER - KNOWN SCAMMER</h3>
          <p className="text-red-100">This number has been reported {phoneData.reports} times for {phoneData.type}</p>
          <p className="text-xs text-red-200 mt-1">Last reported: {phoneData.lastSeen} • Block immediately</p>
        </div>
        <div className="text-right">
          <div className="text-2xl font-bold">⚠️</div>
          <div className="text-xs">HIGH RISK</div>
        </div>
      </div>
    </div>
  );

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center space-x-3 mb-6">
          <div className="bg-slate-100 p-3 rounded-lg">
            <Phone className="text-slate-600" size={24} />
          </div>
          <div>
            <h3 className="text-xl font-semibold text-slate-800">Call Protection Center</h3>
            <p className="text-slate-600">Real-time scammer detection and call transcript analysis</p>
          </div>
        </div>

        <Tabs defaultValue="phone-check" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="phone-check" className="flex items-center space-x-2">
              <PhoneCall size={16} />
              <span>Phone Lookup</span>
            </TabsTrigger>
            <TabsTrigger value="transcript" className="flex items-center space-x-2">
              <Search size={16} />
              <span>Call Analysis</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="phone-check" className="space-y-4 mt-6">
            <div>
              <h4 className="font-semibold text-slate-800 mb-3 flex items-center">
                <Shield className="mr-2 text-blue-600" size={18} />
                Live Caller ID Protection (Like Truecaller)
              </h4>
              <div className="space-y-3">
                <Input
                  type="tel"
                  placeholder="Enter phone number (e.g., +91-9876543210)"
                  value={phoneNumber}
                  onChange={(e) => setPhoneNumber(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handlePhoneCheck()}
                  className="font-mono"
                />
                <Button 
                  onClick={handlePhoneCheck}
                  disabled={phoneCheckMutation.isPending}
                  className="w-full bg-blue-600 hover:bg-blue-700"
                >
                  {phoneCheckMutation.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Search className="mr-2 h-4 w-4" />
                  )}
                  Check Number
                </Button>
              </div>
              
              {phoneResult && <ResultCard result={phoneResult} type="Phone Number" />}
            </div>

            <div className="mt-6 p-4 bg-red-50 rounded-lg border border-red-200">
              <h4 className="font-semibold text-red-800 mb-3">🔥 Live Scammer Database (Top Reported)</h4>
              <div className="space-y-2">
                {knownScamNumbers.slice(0, 3).map((scammer, index) => (
                  <button
                    key={index}
                    onClick={() => setPhoneNumber(scammer.number)}
                    className="text-left w-full p-3 rounded bg-red-100 hover:bg-red-200 transition-colors border border-red-300"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-mono text-red-800 font-semibold">{scammer.number}</p>
                        <p className="text-sm text-red-600">{scammer.type} • {scammer.reports} reports</p>
                      </div>
                      <div className="text-red-600">
                        <AlertTriangle size={16} />
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </TabsContent>

          <TabsContent value="transcript" className="space-y-4 mt-6">
            <div>
              <h4 className="font-semibold text-slate-800 mb-3">Analyze Suspicious Call Content</h4>
              <Textarea
                placeholder="Enter call transcript or conversation details..."
                value={transcript}
                onChange={(e) => setTranscript(e.target.value)}
                rows={6}
                className="resize-none"
              />
              
              <Button 
                onClick={handleScan}
                disabled={scanMutation.isPending}
                className="w-full mt-3 bg-slate-600 hover:bg-slate-700"
              >
                {scanMutation.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Phone className="mr-2 h-4 w-4" />
                )}
                Analyze Call Content
              </Button>

              {result && <ResultCard result={result} type="Call" />}
            </div>

            <div className="mt-6 p-4 bg-red-50 rounded-lg border border-red-200">
              <h4 className="font-semibold text-red-800 mb-2">📞 Sample scam call transcripts to try:</h4>
              <div className="space-y-2">
                {sampleTranscripts.map((sample, index) => (
                  <button
                    key={index}
                    onClick={() => setTranscript(sample)}
                    className="text-left text-sm text-red-700 hover:text-red-900 block w-full p-2 rounded bg-red-100 hover:bg-red-200 transition-colors"
                  >
                    "{sample.substring(0, 100)}..."
                  </button>
                ))}
              </div>
            </div>
          </TabsContent>
        </Tabs>

        <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <h4 className="font-semibold text-blue-800 mb-2">🛡️ How Call Protection Works:</h4>
          <ul className="text-sm text-blue-700 space-y-1">
            <li>• Real-time phone number verification against scammer database</li>
            <li>• Community-powered reporting system</li>
            <li>• AI analysis of call patterns and fraud indicators</li>
            <li>• Instant alerts for known fraudulent numbers</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
