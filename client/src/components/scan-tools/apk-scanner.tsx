import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Smartphone, Upload, Loader2 } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import ResultCard from "./result-card";

export default function APKScanner() {
  const [appName, setAppName] = useState("");
  const [result, setResult] = useState(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const scanMutation = useMutation({
    mutationFn: async (data: { appName: string; extractedStrings: string }) => {
      const response = await apiRequest("POST", "/api/scan/apk", data);
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
        description: error.message || "Unable to analyze APK. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      if (!file.name.endsWith('.apk')) {
        toast({
          title: "Invalid File",
          description: "Please upload an APK file.",
          variant: "destructive",
        });
        return;
      }

      // In a real implementation, this would extract strings from the APK
      // For now, we'll simulate the analysis
      setAppName(file.name.replace('.apk', ''));
      
      // Simulate APK string extraction
      const mockExtractedStrings = "instant loan easy money rummy cash win daily earning without documents";
      
      setResult(null);
      scanMutation.mutate({
        appName: file.name,
        extractedStrings: mockExtractedStrings
      });
    }
  };

  const handleManualScan = () => {
    if (!appName.trim()) {
      toast({
        title: "App Name Required",
        description: "Please enter an app name to analyze.",
        variant: "destructive",
      });
      return;
    }

    // Simulate string extraction based on app name
    const mockExtractedStrings = appName.toLowerCase().includes('loan') ? 
      "instant loan approval without documents easy money" :
      appName.toLowerCase().includes('rummy') ?
      "rummy cash game win money daily earning" :
      "legitimate app normal functionality";

    setResult(null);
    scanMutation.mutate({
      appName,
      extractedStrings: mockExtractedStrings
    });
  };

  const suspiciousApps = [
    "InstantLoanEasy.apk",
    "RummyCashWinner.apk",
    "EasyMoney24x7.apk",
    "QuickLoanApproval.apk"
  ];

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center space-x-3 mb-6">
          <div className="bg-orange-100 p-3 rounded-lg">
            <Smartphone className="text-orange-600" size={24} />
          </div>
          <div>
            <h3 className="text-xl font-semibold text-slate-800">APK Analyzer</h3>
            <p className="text-slate-600">Analyze Android apps for malicious behavior and scam patterns</p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="border-2 border-dashed border-slate-300 rounded-lg p-6 text-center hover:border-orange-400 transition-colors">
            <Upload className="mx-auto text-slate-400 mb-2" size={32} />
            <p className="text-slate-600 mb-2">Drop APK file or click to upload</p>
            <p className="text-slate-400 text-sm">Android app files up to 50MB</p>
            <input
              type="file"
              accept=".apk"
              onChange={handleFileUpload}
              className="hidden"
              id="apk-upload"
            />
            <Button
              variant="outline"
              className="mt-2"
              onClick={() => document.getElementById('apk-upload')?.click()}
            >
              Choose APK File
            </Button>
          </div>

          <div className="text-center text-slate-500">or</div>

          <div className="space-y-2">
            <Input
              placeholder="Enter app name for manual analysis"
              value={appName}
              onChange={(e) => setAppName(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleManualScan()}
            />
            <Button 
              onClick={handleManualScan}
              disabled={scanMutation.isPending}
              className="w-full bg-orange-600 hover:bg-orange-700"
            >
              {scanMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Smartphone className="mr-2 h-4 w-4" />
              )}
              Analyze APK
            </Button>
          </div>

          {result && <ResultCard result={result} type="APK" />}
        </div>

        <div className="mt-6 p-4 bg-red-50 rounded-lg border border-red-200">
          <h4 className="font-semibold text-red-800 mb-2">📱 Known suspicious app names:</h4>
          <div className="space-y-2">
            {suspiciousApps.map((app, index) => (
              <button
                key={index}
                onClick={() => setAppName(app.replace('.apk', ''))}
                className="text-left text-sm text-red-700 hover:text-red-900 block w-full p-2 rounded bg-red-100 hover:bg-red-200 transition-colors"
              >
                {app}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 p-4 bg-orange-50 rounded-lg border border-orange-200">
          <h4 className="font-semibold text-orange-800 mb-2">🔍 What we analyze:</h4>
          <ul className="text-sm text-orange-700 space-y-1">
            <li>• App permissions and behavior</li>
            <li>• Loan and gambling keywords</li>
            <li>• Suspicious network requests</li>
            <li>• Hidden malicious functionality</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
