import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle, AlertTriangle, XCircle, Clock } from "lucide-react";

interface ResultCardProps {
  result: {
    id: number;
    verdict: string;
    confidence: number;
    riskFactors: string[];
    timestamp: string;
  };
  type: string;
}

export default function ResultCard({ result, type }: ResultCardProps) {
  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'safe':
        return {
          bg: 'bg-green-50 border-green-200',
          text: 'text-green-700',
          badge: 'bg-green-100 text-green-700',
          icon: CheckCircle,
          iconColor: 'text-green-600'
        };
      case 'suspicious':
        return {
          bg: 'bg-yellow-50 border-yellow-200',
          text: 'text-yellow-700',
          badge: 'bg-yellow-100 text-yellow-700',
          icon: AlertTriangle,
          iconColor: 'text-yellow-600'
        };
      case 'dangerous':
        return {
          bg: 'bg-red-50 border-red-200',
          text: 'text-red-700',
          badge: 'bg-red-100 text-red-700',
          icon: XCircle,
          iconColor: 'text-red-600'
        };
      default:
        return {
          bg: 'bg-gray-50 border-gray-200',
          text: 'text-gray-700',
          badge: 'bg-gray-100 text-gray-700',
          icon: AlertTriangle,
          iconColor: 'text-gray-600'
        };
    }
  };

  const verdictStyle = getVerdictColor(result.verdict);
  const IconComponent = verdictStyle.icon;

  const getProgressBarColor = (verdict: string) => {
    switch (verdict) {
      case 'safe': return 'bg-green-500';
      case 'suspicious': return 'bg-yellow-500';
      case 'dangerous': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getVerdictText = (verdict: string) => {
    switch (verdict) {
      case 'safe': return '✅ SAFE';
      case 'suspicious': return '⚠️ SUSPICIOUS';
      case 'dangerous': return '🚨 DANGEROUS';
      default: return '❓ UNKNOWN';
    }
  };

  return (
    <Card className={`mt-4 ${verdictStyle.bg} border`}>
      <CardContent className="p-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center space-x-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${verdictStyle.bg}`}>
              <IconComponent className={verdictStyle.iconColor} size={20} />
            </div>
            <div>
              <h3 className={`font-semibold ${verdictStyle.text}`}>
                {getVerdictText(result.verdict)}
              </h3>
              <p className="text-sm text-gray-600 flex items-center">
                <Clock size={12} className="mr-1" />
                Scanned {new Date(result.timestamp).toLocaleString()}
              </p>
            </div>
          </div>
          <Badge className={verdictStyle.badge}>
            {result.verdict ? result.verdict.toUpperCase() : "UNKNOWN"}
          </Badge>
        </div>

        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-700">Confidence Score</span>
              <span className={`text-sm font-bold ${verdictStyle.text}`}>
                {result.confidence}%
              </span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className={`h-2 rounded-full ${getProgressBarColor(result.verdict)}`}
                style={{ width: `${result.confidence}%` }}
              ></div>
            </div>
          </div>

          {result.riskFactors && result.riskFactors.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-700 mb-2">Detected Risk Factors:</h4>
              <div className="space-y-1">
                {result.riskFactors.map((factor, index) => (
                  <div key={index} className="flex items-center space-x-2">
                    <span className={`text-xs ${verdictStyle.iconColor}`}>•</span>
                    <span className="text-sm text-gray-600">{factor}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className={`p-3 rounded-lg ${verdictStyle.bg} border ${verdictStyle.bg.includes('green') ? 'border-green-200' : verdictStyle.bg.includes('yellow') ? 'border-yellow-200' : 'border-red-200'}`}>
            <p className={`text-sm ${verdictStyle.text} font-medium`}>
              {result.verdict === 'safe' && '✅ This appears to be safe. No suspicious patterns detected.'}
              {result.verdict === 'suspicious' && '⚠️ This shows suspicious patterns. Exercise caution and verify authenticity.'}
              {result.verdict === 'dangerous' && '🚨 This is likely a scam! Do not proceed or share any personal information.'}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
