import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Flag, Send, Loader2, CheckCircle } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export default function Report() {
  const [formData, setFormData] = useState({
    type: "",
    content: "",
    description: ""
  });
  const [isSubmitted, setIsSubmitted] = useState(false);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const submitMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const response = await apiRequest("POST", "/api/report", data);
      return response.json();
    },
    onSuccess: () => {
      setIsSubmitted(true);
      setFormData({ type: "", content: "", description: "" });
      queryClient.invalidateQueries({ queryKey: ["/api/reports"] });
      toast({
        title: "Report Submitted",
        description: "Thank you for helping protect the community!",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Submission Failed",
        description: error.message || "Unable to submit report. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.type || !formData.content) {
      toast({
        title: "Missing Information",
        description: "Please fill in all required fields.",
        variant: "destructive",
      });
      return;
    }

    submitMutation.mutate(formData);
  };

  const scamTypes = [
    { value: "loan_fraud", label: "Loan Fraud App" },
    { value: "rummy_scam", label: "Rummy/Gaming Scam" },
    { value: "phishing", label: "Phishing Website" },
    { value: "fake_lottery", label: "Fake Lottery SMS" },
    { value: "upi_fraud", label: "UPI Fraud" },
    { value: "fake_call", label: "Fake Authority Call" },
    { value: "other", label: "Other" }
  ];

  if (isSubmitted) {
    return (
      <div className="min-h-screen py-8">
        <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8">
          <Card className="bg-green-50 border-green-200">
            <CardContent className="p-8 text-center">
              <CheckCircle className="mx-auto text-green-600 mb-4" size={64} />
              <h1 className="text-2xl font-bold text-green-800 mb-4">Report Submitted Successfully!</h1>
              <p className="text-green-700 mb-6">
                Thank you for helping protect the community. Your report has been received and will be reviewed by our security team.
              </p>
              <div className="space-y-3">
                <Button 
                  onClick={() => setIsSubmitted(false)}
                  className="bg-green-600 hover:bg-green-700"
                >
                  Submit Another Report
                </Button>
                <Button 
                  variant="outline"
                  onClick={() => window.location.href = '/'}
                >
                  Return to Home
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <Flag className="text-orange-600 mr-3" size={32} />
            <h1 className="text-3xl lg:text-4xl font-bold text-slate-800">Report Scam</h1>
          </div>
          <p className="text-xl text-slate-600 max-w-3xl mx-auto">
            Help protect the community by reporting new scams, suspicious apps, or fraudulent websites
          </p>
        </div>

        <div className="grid lg:grid-cols-3 gap-8">
          {/* Report Form */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Flag className="mr-2" size={20} />
                  Submit Scam Report
                </CardTitle>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                  <div>
                    <Label htmlFor="type">Scam Type *</Label>
                    <Select value={formData.type} onValueChange={(value) => setFormData({...formData, type: value})}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select scam type" />
                      </SelectTrigger>
                      <SelectContent>
                        {scamTypes.map((type) => (
                          <SelectItem key={type.value} value={type.value}>
                            {type.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label htmlFor="content">Scam Content *</Label>
                    <Textarea
                      id="content"
                      placeholder="Enter the scam URL, app name, SMS text, or phone number..."
                      value={formData.content}
                      onChange={(e) => setFormData({...formData, content: e.target.value})}
                      rows={4}
                      className="resize-none"
                    />
                  </div>

                  <div>
                    <Label htmlFor="description">Additional Details</Label>
                    <Textarea
                      id="description"
                      placeholder="Provide additional context, how you encountered this scam, or any other relevant information..."
                      value={formData.description}
                      onChange={(e) => setFormData({...formData, description: e.target.value})}
                      rows={4}
                      className="resize-none"
                    />
                  </div>

                  <Button
                    type="submit"
                    disabled={submitMutation.isPending}
                    className="w-full bg-orange-600 hover:bg-orange-700"
                  >
                    {submitMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Send className="mr-2 h-4 w-4" />
                    )}
                    Submit Report
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar Info */}
          <div className="space-y-6">
            <Card className="bg-blue-50 border-blue-200">
              <CardContent className="p-6">
                <h3 className="font-semibold text-blue-800 mb-3">Why Report Scams?</h3>
                <ul className="text-sm text-blue-700 space-y-2">
                  <li className="flex items-start space-x-2">
                    <span className="text-blue-600 mt-1">•</span>
                    <span>Help protect millions of users</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-blue-600 mt-1">•</span>
                    <span>Improve our detection algorithms</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-blue-600 mt-1">•</span>
                    <span>Build a stronger defense network</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-blue-600 mt-1">•</span>
                    <span>Prevent financial losses</span>
                  </li>
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-green-50 border-green-200">
              <CardContent className="p-6">
                <h3 className="font-semibold text-green-800 mb-3">What Happens Next?</h3>
                <div className="space-y-3 text-sm text-green-700">
                  <div className="flex items-start space-x-2">
                    <span className="bg-green-200 text-green-800 rounded-full w-5 h-5 flex items-center justify-center text-xs font-bold">1</span>
                    <span>Report reviewed by security team</span>
                  </div>
                  <div className="flex items-start space-x-2">
                    <span className="bg-green-200 text-green-800 rounded-full w-5 h-5 flex items-center justify-center text-xs font-bold">2</span>
                    <span>Scam patterns analyzed and verified</span>
                  </div>
                  <div className="flex items-start space-x-2">
                    <span className="bg-green-200 text-green-800 rounded-full w-5 h-5 flex items-center justify-center text-xs font-bold">3</span>
                    <span>Database updated for protection</span>
                  </div>
                  <div className="flex items-start space-x-2">
                    <span className="bg-green-200 text-green-800 rounded-full w-5 h-5 flex items-center justify-center text-xs font-bold">4</span>
                    <span>Community alerted if verified</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-red-50 border-red-200">
              <CardContent className="p-6">
                <h3 className="font-semibold text-red-800 mb-3">🚨 Immediate Threats</h3>
                <p className="text-sm text-red-700 mb-3">
                  If you've been victimized or suspect immediate financial fraud:
                </p>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center justify-between bg-red-100 p-2 rounded">
                    <span className="text-red-700">Cyber Crime Helpline</span>
                    <span className="font-bold text-red-800">1930</span>
                  </div>
                  <div className="flex items-center justify-between bg-red-100 p-2 rounded">
                    <span className="text-red-700">Banking Fraud</span>
                    <span className="font-bold text-red-800">14416</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
