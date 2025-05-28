import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { MessageSquare, Loader2 } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import ResultCard from "./result-card";

export default function SMSScanner() {
  const [smsText, setSmsText] = useState("");
  const [result, setResult] = useState(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const scanMutation = useMutation({
    mutationFn: async (text: string) => {
      const response = await apiRequest("POST", "/api/scan/sms", { text });
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
        description: error.message || "Unable to analyze SMS. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleScan = () => {
    if (!smsText.trim()) {
      toast({
        title: "SMS Text Required",
        description: "Please enter SMS text to analyze.",
        variant: "destructive",
      });
      return;
    }

    setResult(null);
    scanMutation.mutate(smsText);
  };

  const sampleTexts = [
    "Congratulations! You've won ₹25 lakh in KBC lottery. Click link to claim: bit.ly/kbc-winner",
    "URGENT: Your UPI account will be blocked. Verify immediately: verify-upi.com",
    "Get instant loan up to ₹5 lakh without documents. Apply now: instantloan.xyz"
  ];

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center space-x-3 mb-6">
          <div className="bg-green-100 p-3 rounded-lg">
            <MessageSquare className="text-green-600" size={24} />
          </div>
          <div>
            <h3 className="text-xl font-semibold text-slate-800">SMS Analyzer</h3>
            <p className="text-slate-600">Identify scam messages including fake lottery wins and loan offers</p>
          </div>
        </div>

        <div className="space-y-4">
          <Textarea
            placeholder="Paste suspicious SMS text here..."
            value={smsText}
            onChange={(e) => setSmsText(e.target.value)}
            rows={4}
            className="resize-none"
          />
          
          <Button 
            onClick={handleScan}
            disabled={scanMutation.isPending}
            className="w-full bg-green-600 hover:bg-green-700"
          >
            {scanMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <MessageSquare className="mr-2 h-4 w-4" />
            )}
            Analyze SMS
          </Button>

          {result && <ResultCard result={result} type="SMS" />}
        </div>

        <div className="mt-6 p-4 bg-yellow-50 rounded-lg border border-yellow-200">
          <h4 className="font-semibold text-yellow-800 mb-2">📱 Sample scam messages to try:</h4>
          <div className="space-y-2">
            {sampleTexts.map((sample, index) => (
              <button
                key={index}
                onClick={() => setSmsText(sample)}
                className="text-left text-sm text-yellow-700 hover:text-yellow-900 block w-full p-2 rounded bg-yellow-100 hover:bg-yellow-200 transition-colors"
              >
                "{sample}"
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 p-4 bg-green-50 rounded-lg border border-green-200">
          <h4 className="font-semibold text-green-800 mb-2">🔍 What we detect:</h4>
          <ul className="text-sm text-green-700 space-y-1">
            <li>• KBC lottery and prize scams</li>
            <li>• Instant loan fraud messages</li>
            <li>• UPI and banking phishing</li>
            <li>• OTP and PIN theft attempts</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
