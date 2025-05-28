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

interface ReportFormProps {
  onSuccess?: () => void;
  compact?: boolean;
}

export default function ReportForm({ onSuccess, compact = false }: ReportFormProps) {
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
      onSuccess?.();
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

  if (isSubmitted && !compact) {
    return (
      <Card className="bg-green-50 border-green-200">
        <CardContent className="p-8 text-center">
          <CheckCircle className="mx-auto text-green-600 mb-4" size={64} />
          <h2 className="text-2xl font-bold text-green-800 mb-4">Report Submitted Successfully!</h2>
          <p className="text-green-700 mb-6">
            Thank you for helping protect the community. Your report has been received and will be reviewed by our security team.
          </p>
          <Button 
            onClick={() => setIsSubmitted(false)}
            className="bg-green-600 hover:bg-green-700"
          >
            Submit Another Report
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (isSubmitted && compact) {
    return (
      <div className="text-center py-4">
        <CheckCircle className="mx-auto text-green-600 mb-2" size={32} />
        <p className="text-sm text-green-700 font-medium">Report submitted successfully!</p>
        <Button 
          size="sm"
          variant="outline"
          onClick={() => setIsSubmitted(false)}
          className="mt-2"
        >
          Submit Another
        </Button>
      </div>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center">
          <Flag className="mr-2" size={20} />
          {compact ? "Quick Report" : "Submit Scam Report"}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
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
              rows={compact ? 2 : 3}
              className="resize-none"
            />
          </div>

          {!compact && (
            <div>
              <Label htmlFor="description">Additional Details</Label>
              <Textarea
                id="description"
                placeholder="Provide additional context..."
                value={formData.description}
                onChange={(e) => setFormData({...formData, description: e.target.value})}
                rows={3}
                className="resize-none"
              />
            </div>
          )}

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
  );
}
