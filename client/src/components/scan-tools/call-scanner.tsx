import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { Phone, Loader2 } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import ResultCard from "./result-card";

export default function CallScanner() {
  const [transcript, setTranscript] = useState("");
  const [result, setResult] = useState(null);
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

  const sampleTranscripts = [
    "Sir, I am calling from RBI headquarters. Your account has been compromised. Please share your OTP to verify your identity and secure your account immediately.",
    "Congratulations! You have been selected for an instant loan of ₹5 lakh. No documents required. Just share your Aadhaar and PAN details to process immediately.",
    "Hello sir, this is from SBI security department. There has been suspicious activity on your account. Please provide your ATM PIN to block unauthorized transactions."
  ];

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center space-x-3 mb-6">
          <div className="bg-slate-100 p-3 rounded-lg">
            <Phone className="text-slate-600" size={24} />
          </div>
          <div>
            <h3 className="text-xl font-semibold text-slate-800">Call Analyzer</h3>
            <p className="text-slate-600">Analyze call transcripts to detect scam attempts and fraudulent calls</p>
          </div>
        </div>

        <div className="space-y-4">
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
            className="w-full bg-slate-600 hover:bg-slate-700"
          >
            {scanMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Phone className="mr-2 h-4 w-4" />
            )}
            Analyze Call
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

        <div className="mt-4 p-4 bg-slate-50 rounded-lg border border-slate-200">
          <h4 className="font-semibold text-slate-800 mb-2">🔍 What we detect:</h4>
          <ul className="text-sm text-slate-700 space-y-1">
            <li>• Fake authority impersonation (RBI, banks)</li>
            <li>• OTP and PIN theft attempts</li>
            <li>• Urgent account blocking threats</li>
            <li>• Instant loan fraud calls</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
