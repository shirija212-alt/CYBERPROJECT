import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Link, Loader2 } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import ResultCard from "./result-card";

export default function URLScanner() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const scanMutation = useMutation({
    mutationFn: async (url: string) => {
      const response = await apiRequest("POST", "/api/scan/url", { url });
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
        description: error.message || "Unable to scan URL. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleScan = () => {
    if (!url.trim()) {
      toast({
        title: "URL Required",
        description: "Please enter a URL to scan.",
        variant: "destructive",
      });
      return;
    }

    // Basic URL validation
    try {
      new URL(url.startsWith('http') ? url : `https://${url}`);
    } catch {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid URL.",
        variant: "destructive",
      });
      return;
    }

    setResult(null);
    scanMutation.mutate(url);
  };

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center space-x-3 mb-6">
          <div className="bg-blue-100 p-3 rounded-lg">
            <Link className="text-blue-600" size={24} />
          </div>
          <div>
            <h3 className="text-xl font-semibold text-slate-800">URL Scanner</h3>
            <p className="text-slate-600">Check if a website or link is safe before clicking</p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex space-x-2">
            <Input
              type="url"
              placeholder="Enter URL to scan (e.g., https://suspicious-site.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleScan()}
              className="font-mono text-sm"
            />
            <Button 
              onClick={handleScan}
              disabled={scanMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700"
            >
              {scanMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Link className="mr-2 h-4 w-4" />
              )}
              Scan URL
            </Button>
          </div>

          {result && <ResultCard result={result} type="URL" />}
        </div>

        <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <h4 className="font-semibold text-blue-800 mb-2">🔍 What we check:</h4>
          <ul className="text-sm text-blue-700 space-y-1">
            <li>• Domain reputation and age</li>
            <li>• Known scam URL patterns</li>
            <li>• Loan fraud and phishing indicators</li>
            <li>• SSL certificate validity</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
