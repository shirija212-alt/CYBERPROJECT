import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { QrCode, Upload, Loader2 } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import ResultCard from "./result-card";

export default function QRScanner() {
  const [qrText, setQrText] = useState("");
  const [result, setResult] = useState(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const scanMutation = useMutation({
    mutationFn: async (decodedText: string) => {
      const response = await apiRequest("POST", "/api/scan/qr", { decodedText });
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
        description: error.message || "Unable to scan QR code. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleScan = () => {
    if (!qrText.trim()) {
      toast({
        title: "QR Content Required",
        description: "Please enter QR code content to analyze.",
        variant: "destructive",
      });
      return;
    }

    setResult(null);
    scanMutation.mutate(qrText);
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      // In a real implementation, this would decode the QR code from the image
      // For now, we'll show a placeholder message
      toast({
        title: "QR Code Processing",
        description: "QR code image processing is not yet implemented. Please enter the decoded text manually.",
      });
    }
  };

  const sampleQRCodes = [
    "upi://pay?pa=scammer@paytm&pn=FakeStore&am=100",
    "https://loanapproval-instant.com/apply?ref=qr123",
    "https://rummy-win-cash.xyz/download"
  ];

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center space-x-3 mb-6">
          <div className="bg-purple-100 p-3 rounded-lg">
            <QrCode className="text-purple-600" size={24} />
          </div>
          <div>
            <h3 className="text-xl font-semibold text-slate-800">QR Code Scanner</h3>
            <p className="text-slate-600">Upload QR code images to check if they lead to malicious websites</p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="border-2 border-dashed border-slate-300 rounded-lg p-6 text-center hover:border-purple-400 transition-colors">
            <Upload className="mx-auto text-slate-400 mb-2" size={32} />
            <p className="text-slate-600 mb-2">Drop QR image or click to upload</p>
            <p className="text-slate-400 text-sm">PNG, JPG up to 5MB</p>
            <input
              type="file"
              accept="image/*"
              onChange={handleFileUpload}
              className="hidden"
              id="qr-upload"
            />
            <Button
              variant="outline"
              className="mt-2"
              onClick={() => document.getElementById('qr-upload')?.click()}
            >
              Choose File
            </Button>
          </div>

          <div className="text-center text-slate-500">or</div>

          <div className="space-y-2">
            <Input
              placeholder="Enter decoded QR code text manually"
              value={qrText}
              onChange={(e) => setQrText(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleScan()}
            />
            <Button 
              onClick={handleScan}
              disabled={scanMutation.isPending}
              className="w-full bg-purple-600 hover:bg-purple-700"
            >
              {scanMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <QrCode className="mr-2 h-4 w-4" />
              )}
              Scan QR Code
            </Button>
          </div>

          {result && <ResultCard result={result} type="QR Code" />}
        </div>

        <div className="mt-6 p-4 bg-orange-50 rounded-lg border border-orange-200">
          <h4 className="font-semibold text-orange-800 mb-2">📱 Sample malicious QR codes to try:</h4>
          <div className="space-y-2">
            {sampleQRCodes.map((sample, index) => (
              <button
                key={index}
                onClick={() => setQrText(sample)}
                className="text-left text-sm text-orange-700 hover:text-orange-900 block w-full p-2 rounded bg-orange-100 hover:bg-orange-200 transition-colors font-mono"
              >
                {sample}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 p-4 bg-purple-50 rounded-lg border border-purple-200">
          <h4 className="font-semibold text-purple-800 mb-2">🔍 What we check:</h4>
          <ul className="text-sm text-purple-700 space-y-1">
            <li>• Malicious payment QR codes</li>
            <li>• Fraudulent app download links</li>
            <li>• Phishing website redirects</li>
            <li>• Suspicious UPI payment requests</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
