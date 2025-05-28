import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Brain, TrendingUp, Target, Zap, BookOpen, Activity, AlertCircle } from "lucide-react";

interface AIModel {
  type: string;
  accuracy: number;
  trainingCount: number;
  patternsLearned: number;
  vocabularySize: number;
  learningRate: number;
}

interface AILearningStatus {
  isActive: boolean;
  isTraining: boolean;
  lastTraining: string;
  totalTrainingData: number;
  models: AIModel[];
  averageAccuracy: number;
}

export default function AILearning() {
  const { data: status, isLoading } = useQuery<AILearningStatus>({
    queryKey: ['/api/ai-learning/status'],
    refetchInterval: 15000, // Refresh every 15 seconds for real-time updates
  });

  if (isLoading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-1/3"></div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-32 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const getAccuracyColor = (accuracy: number) => {
    if (accuracy >= 0.9) return "text-green-600";
    if (accuracy >= 0.8) return "text-blue-600";
    if (accuracy >= 0.7) return "text-yellow-600";
    return "text-red-600";
  };

  const getAccuracyBadge = (accuracy: number) => {
    if (accuracy >= 0.9) return "default";
    if (accuracy >= 0.8) return "secondary";
    if (accuracy >= 0.7) return "outline";
    return "destructive";
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2 flex items-center gap-3">
          <Brain className="h-8 w-8 text-purple-600" />
          AI Pattern Learning Engine
        </h1>
        <p className="text-gray-600">
          Advanced machine learning system that continuously learns from scam patterns to improve detection accuracy
        </p>
      </div>

      {/* AI Status Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">AI Status</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className={`w-2 h-2 rounded-full ${status?.isActive ? 'bg-green-500' : 'bg-red-500'}`} />
                  <span className="font-semibold">
                    {status?.isActive ? 'Learning' : 'Offline'}
                  </span>
                  {status?.isTraining && (
                    <Badge variant="secondary" className="text-xs">Training</Badge>
                  )}
                </div>
              </div>
              <Activity className="h-8 w-8 text-purple-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Average Accuracy</p>
                <p className={`text-2xl font-bold ${getAccuracyColor(status?.averageAccuracy || 0)}`}>
                  {((status?.averageAccuracy || 0) * 100).toFixed(1)}%
                </p>
              </div>
              <Target className="h-8 w-8 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Training Data</p>
                <p className="text-2xl font-bold">{status?.totalTrainingData || 0}</p>
              </div>
              <BookOpen className="h-8 w-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Last Training</p>
                <p className="text-sm font-semibold">
                  {status?.lastTraining ? new Date(status.lastTraining).toLocaleTimeString() : 'Never'}
                </p>
              </div>
              <TrendingUp className="h-8 w-8 text-orange-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* AI Models Performance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Brain className="h-5 w-5" />
              AI Model Performance
            </CardTitle>
            <CardDescription>
              Real-time accuracy metrics for each content type
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {status?.models.map((model, index) => (
              <div key={index} className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <h3 className="font-semibold capitalize">{model.type} Detector</h3>
                    <Badge variant={getAccuracyBadge(model.accuracy)}>
                      {(model.accuracy * 100).toFixed(1)}% Accuracy
                    </Badge>
                  </div>
                  <div className="text-sm text-gray-500">
                    {model.trainingCount} samples
                  </div>
                </div>
                
                <Progress value={model.accuracy * 100} className="h-3" />
                
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-600">Patterns: </span>
                    <span className="font-medium">{model.patternsLearned}</span>
                  </div>
                  <div>
                    <span className="text-gray-600">Vocabulary: </span>
                    <span className="font-medium">{model.vocabularySize}</span>
                  </div>
                </div>
                
                {index < (status?.models.length || 0) - 1 && <Separator />}
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="h-5 w-5" />
              Learning Insights
            </CardTitle>
            <CardDescription>
              How AI improves INSAFE's threat detection
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-4 bg-purple-50 rounded-lg border border-purple-200">
              <h4 className="font-semibold text-purple-800 mb-2 flex items-center gap-2">
                <Brain className="h-4 w-4" />
                Adaptive Learning
              </h4>
              <p className="text-sm text-purple-700">
                AI models automatically adapt to new scam patterns and improve detection accuracy with each scan.
              </p>
            </div>

            <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
              <h4 className="font-semibold text-blue-800 mb-2 flex items-center gap-2">
                <Target className="h-4 w-4" />
                Pattern Recognition
              </h4>
              <p className="text-sm text-blue-700">
                Advanced algorithms identify subtle patterns in fraudulent content that traditional methods might miss.
              </p>
            </div>

            <div className="p-4 bg-green-50 rounded-lg border border-green-200">
              <h4 className="font-semibold text-green-800 mb-2 flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                Continuous Improvement
              </h4>
              <p className="text-sm text-green-700">
                Models retrain hourly with new data, ensuring protection against evolving scam techniques.
              </p>
            </div>

            <div className="p-4 bg-orange-50 rounded-lg border border-orange-200">
              <h4 className="font-semibold text-orange-800 mb-2 flex items-center gap-2">
                <BookOpen className="h-4 w-4" />
                Knowledge Base
              </h4>
              <p className="text-sm text-orange-700">
                Growing vocabulary of {status?.models.reduce((sum, model) => sum + model.vocabularySize, 0)} unique terms from Indian scam patterns.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* AI Features Explanation */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            How AI Enhances INSAFE
          </CardTitle>
          <CardDescription>
            Understanding the intelligence behind scam detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <h4 className="font-semibold text-lg">🧠 Machine Learning Features</h4>
              <div className="space-y-3 text-sm">
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-purple-500 rounded-full mt-2"></div>
                  <div>
                    <strong>Natural Language Processing:</strong> Analyzes text patterns, urgency language, and suspicious keywords specific to Indian scam tactics.
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                  <div>
                    <strong>Behavioral Pattern Learning:</strong> Recognizes common fraud behaviors like urgent payment requests and fake authority claims.
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full mt-2"></div>
                  <div>
                    <strong>Multi-Factor Analysis:</strong> Combines phone numbers, URLs, money mentions, and personal info requests for comprehensive scoring.
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-orange-500 rounded-full mt-2"></div>
                  <div>
                    <strong>Adaptive Learning Rate:</strong> Models adjust learning speed based on performance to optimize accuracy.
                  </div>
                </div>
              </div>
            </div>
            
            <div className="space-y-4">
              <h4 className="font-semibold text-lg">📊 Real-Time Intelligence</h4>
              <div className="space-y-3 text-sm">
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2"></div>
                  <div>
                    <strong>Continuous Training:</strong> Models retrain automatically with new scam data to stay ahead of evolving threats.
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mt-2"></div>
                  <div>
                    <strong>User Feedback Integration:</strong> Learns from user corrections to improve future predictions.
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-indigo-500 rounded-full mt-2"></div>
                  <div>
                    <strong>Indian Context Awareness:</strong> Specialized for KBC lottery, UPI fraud, loan scams, and other India-specific threats.
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <div className="w-2 h-2 bg-pink-500 rounded-full mt-2"></div>
                  <div>
                    <strong>Performance Monitoring:</strong> Real-time accuracy tracking and model optimization.
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="mt-6 p-4 bg-gradient-to-r from-purple-50 to-blue-50 rounded-lg border border-purple-200">
            <div className="flex items-center gap-2 mb-2">
              <AlertCircle className="h-5 w-5 text-purple-600" />
              <h4 className="font-semibold text-purple-800">AI Ethics & Privacy</h4>
            </div>
            <p className="text-sm text-purple-700">
              All AI processing happens locally on INSAFE servers. Personal data is anonymized for learning, 
              and models are designed to protect user privacy while maximizing threat detection effectiveness.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}