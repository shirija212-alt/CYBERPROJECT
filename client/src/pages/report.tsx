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
  const [submissionResult, setSubmissionResult] = useState<any>(null);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const submitMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const response = await apiRequest("POST", "/api/report", data);
      return response.json();
    },
    onSuccess: (response) => {
      setIsSubmitted(true);
      setSubmissionResult(response);
      setFormData({ type: "", content: "", description: "" });
      queryClient.invalidateQueries({ queryKey: ["/api/reports"] });
      
      // Show enhanced toast based on AI verification and submission status
      if (response.cyberCrimeSubmission?.submitted) {
        toast({
          title: "🚨 Report Verified & Submitted to Authorities",
          description: `AI verified with ${response.aiVerification.confidence}% confidence. Reference: ${response.cyberCrimeSubmission.referenceNumber}`
        });
      } else if (response.aiVerification?.isGenuine) {
        toast({
          title: "✅ Report Verified by AI",
          description: `${response.aiVerification.confidence}% confidence. Under review by security team.`
        });
      } else {
        toast({
          title: "📝 Report Received",
          description: "Your report is being analyzed and will be reviewed shortly."
        });
      }
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

  if (isSubmitted && submissionResult) {
    const { aiVerification, cyberCrimeSubmission, nextSteps, fraudPatterns } = submissionResult;
    
    return (
      <div className="min-h-screen py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          {/* Main Success Card */}
          <Card className={`mb-6 ${cyberCrimeSubmission?.submitted ? 'bg-red-50 border-red-200' : 'bg-green-50 border-green-200'}`}>
            <CardContent className="p-8 text-center">
              <CheckCircle className={`mx-auto mb-4 ${cyberCrimeSubmission?.submitted ? 'text-red-600' : 'text-green-600'}`} size={64} />
              
              {cyberCrimeSubmission?.submitted ? (
                <div>
                  <h1 className="text-2xl font-bold text-red-800 mb-4">🚨 Report Submitted to Indian Cyber Crime Portal!</h1>
                  <div className="bg-white rounded-lg p-6 mb-6 border border-red-200">
                    <div className="grid md:grid-cols-2 gap-4 text-left">
                      <div>
                        <p className="text-sm text-red-600 font-medium">Official Reference Number</p>
                        <p className="text-lg font-bold text-red-800">{cyberCrimeSubmission.referenceNumber}</p>
                      </div>
                      <div>
                        <p className="text-sm text-red-600 font-medium">AI Confidence Score</p>
                        <p className="text-lg font-bold text-red-800">{aiVerification.confidence}% Verified</p>
                      </div>
                    </div>
                    {cyberCrimeSubmission.trackingUrl && (
                      <div className="mt-4 pt-4 border-t border-red-200">
                        <p className="text-sm text-red-600 mb-2">Track Your Complaint:</p>
                        <a 
                          href={cyberCrimeSubmission.trackingUrl} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-red-700 hover:text-red-900 underline font-medium"
                        >
                          {cyberCrimeSubmission.trackingUrl}
                        </a>
                      </div>
                    )}
                  </div>
                  <p className="text-red-700 mb-6">
                    Your report has been verified by AI and automatically submitted to authorities. 
                    Investigation will begin within 24 hours.
                  </p>
                </div>
              ) : (
                <div>
                  <h1 className="text-2xl font-bold text-green-800 mb-4">✅ Report Verified & Under Review</h1>
                  <div className="bg-white rounded-lg p-6 mb-6 border border-green-200">
                    <div className="grid md:grid-cols-2 gap-4 text-left">
                      <div>
                        <p className="text-sm text-green-600 font-medium">AI Verification Status</p>
                        <p className="text-lg font-bold text-green-800">
                          {aiVerification?.isGenuine ? 'Genuine Threat Detected' : 'Under Analysis'}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-green-600 font-medium">Confidence Score</p>
                        <p className="text-lg font-bold text-green-800">{aiVerification?.confidence || 0}%</p>
                      </div>
                    </div>
                  </div>
                  <p className="text-green-700 mb-6">
                    Thank you for helping protect the community. Our AI has analyzed your report and it's being reviewed by our security team.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid lg:grid-cols-2 gap-6">
            {/* AI Analysis Results */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  🤖 AI Analysis Results
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-slate-600">Risk Level:</span>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    aiVerification?.riskLevel === 'HIGH' ? 'bg-red-100 text-red-800' :
                    aiVerification?.riskLevel === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-green-100 text-green-800'
                  }`}>
                    {aiVerification?.riskLevel || 'LOW'}
                  </span>
                </div>
                
                {fraudPatterns?.length > 0 && (
                  <div>
                    <p className="text-sm text-slate-600 mb-2">Detected Fraud Patterns:</p>
                    <div className="flex flex-wrap gap-2">
                      {fraudPatterns.map((pattern: string, index: number) => (
                        <span key={index} className="px-2 py-1 bg-orange-100 text-orange-800 text-xs rounded-full">
                          {pattern}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="bg-slate-50 p-4 rounded-lg">
                  <p className="text-sm text-slate-600 mb-2">AI Recommendation:</p>
                  <p className="text-sm font-medium">
                    {aiVerification?.isGenuine 
                      ? "Genuine threat detected - Recommended for official investigation"
                      : "Report requires additional verification before escalation"
                    }
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Next Steps */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  📋 What Happens Next
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {nextSteps?.map((step: string, index: number) => (
                    <div key={index} className="flex items-start space-x-3">
                      <span className="bg-blue-100 text-blue-800 rounded-full w-6 h-6 flex items-center justify-center text-xs font-bold mt-0.5">
                        {index + 1}
                      </span>
                      <span className="text-sm text-slate-700">{step}</span>
                    </div>
                  ))}
                </div>

                {cyberCrimeSubmission?.submitted && (
                  <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-lg">
                    <h4 className="font-medium text-red-800 mb-2">🚨 Emergency Contacts</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-red-700">Cyber Crime Helpline:</span>
                        <span className="font-bold text-red-800">1930</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-red-700">Emergency Services:</span>
                        <span className="font-bold text-red-800">112</span>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <div className="mt-8 text-center space-y-3">
            <Button 
              onClick={() => {
                setIsSubmitted(false);
                setSubmissionResult(null);
              }}
              className="bg-blue-600 hover:bg-blue-700 mr-4"
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
