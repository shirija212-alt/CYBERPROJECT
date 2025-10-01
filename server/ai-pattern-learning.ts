import { storage } from "./storage";

// AI-Powered Pattern Learning Service
export class AIPatternLearningService {
  private static instance: AIPatternLearningService;
  private learningModels: Map<string, ScamLearningModel> = new Map();
  private trainingData: TrainingData[] = [];
  private isTraining: boolean = false;
  private lastTraining: Date = new Date(0);

  static getInstance(): AIPatternLearningService {
    if (!AIPatternLearningService.instance) {
      AIPatternLearningService.instance = new AIPatternLearningService();
    }
    return AIPatternLearningService.instance;
  }

  constructor() {
    this.initializeLearningModels();
    this.startContinuousLearning();
  }

  private initializeLearningModels() {
    // SMS/Message Pattern Learning Model
    this.learningModels.set('sms', {
      type: 'sms',
      confidence: 0.75,
      patterns: new Map(),
      vocabulary: new Set(),
      suspiciousKeywords: new Map(),
      learningRate: 0.1,
      trainingCount: 0,
      accuracy: 0.75
    });

    // Phone Number Pattern Learning Model
    this.learningModels.set('phone', {
      type: 'phone',
      confidence: 0.80,
      patterns: new Map(),
      vocabulary: new Set(),
      suspiciousKeywords: new Map(),
      learningRate: 0.15,
      trainingCount: 0,
      accuracy: 0.80
    });

    // URL Pattern Learning Model
    this.learningModels.set('url', {
      type: 'url',
      confidence: 0.85,
      patterns: new Map(),
      vocabulary: new Set(),
      suspiciousKeywords: new Map(),
      learningRate: 0.12,
      trainingCount: 0,
      accuracy: 0.85
    });

    // Call Transcript Learning Model
    this.learningModels.set('call', {
      type: 'call',
      confidence: 0.70,
      patterns: new Map(),
      vocabulary: new Set(),
      suspiciousKeywords: new Map(),
      learningRate: 0.08,
      trainingCount: 0,
      accuracy: 0.70
    });

    console.log('🧠 AI Pattern Learning models initialized');
  }

  // Learn from new scam data
  async learnFromScan(scanData: {
    type: string;
    content: string;
    verdict: string;
    confidence: number;
    userFeedback?: 'correct' | 'incorrect';
  }): Promise<LearningResult> {
    const model = this.learningModels.get(scanData.type);
    if (!model) {
      return { success: false, message: 'Unknown scan type' };
    }

    try {
      // Extract features from the content
      const features = this.extractFeatures(scanData.content, scanData.type);
      
      // Create training data point
      const trainingPoint: TrainingData = {
        id: Date.now(),
        type: scanData.type,
        content: scanData.content,
        features,
        actualVerdict: scanData.verdict,
        userFeedback: scanData.userFeedback,
        confidence: scanData.confidence,
        timestamp: new Date()
      };

      this.trainingData.push(trainingPoint);

      // Update model with new learning
      await this.updateModel(model, trainingPoint);

      // Trigger retraining if enough new data
      if (this.trainingData.length % 10 === 0) {
        await this.retrainModels();
      }

      return {
        success: true,
        message: 'Pattern learned successfully',
        modelAccuracy: model.accuracy,
        patternsLearned: model.patterns.size
      };
    } catch (error) {
      console.error('Error in pattern learning:', error);
      return { success: false, message: 'Learning failed' };
    }
  }

  // Enhanced prediction using AI learning
  async predictThreat(content: string, type: string): Promise<AIPrediction> {
    const model = this.learningModels.get(type);
    if (!model) {
      return {
        verdict: 'safe',
        confidence: 0,
        riskFactors: ['Unknown content type'],
        aiInsights: []
      };
    }

    const features = this.extractFeatures(content, type);
    const prediction = await this.runPrediction(model, features, content);

    return prediction;
  }

  private extractFeatures(content: string, type: string): ContentFeatures {
    const features: ContentFeatures = {
      wordCount: 0,
      suspiciousKeywords: [],
      urgencyScore: 0,
      phoneNumbers: [],
      urls: [],
      moneyMentions: [],
      timeReferences: [],
      personalInfoRequests: []
    };

    const words = content.toLowerCase().split(/\s+/);
    features.wordCount = words.length;

    // Common suspicious keywords across Indian scams
    const suspiciousPatterns = [
      // Financial scams
      'urgent payment', 'immediate action', 'account blocked', 'verify account',
      'last chance', 'expires today', 'limited time', 'act now',
      'congratulations', 'winner', 'lottery', 'prize', 'lucky draw',
      'kbc', 'kaun banega crorepati', 'big boss', 'reality show',
      
      // Banking/UPI scams
      'bank details', 'otp', 'pin number', 'cvv', 'net banking',
      'paytm', 'phonepe', 'google pay', 'upi id', 'transaction failed',
      'refund', 'cashback', 'reward points', 'kyc update',
      
      // Investment scams
      'guaranteed returns', 'double money', 'investment opportunity',
      'stock market', 'crypto', 'bitcoin', 'trading', 'forex',
      'fixed deposit', 'mutual fund', 'insurance policy',
      
      // Tech support scams
      'microsoft', 'google', 'amazon', 'technical support',
      'virus detected', 'computer infected', 'security alert',
      'suspicious activity', 'unauthorized access',
      
      // Romance/relationship scams
      'lonely', 'looking for love', 'single', 'widow', 'army officer',
      'doctor abroad', 'business trip', 'need help', 'emergency',
      
      // Job/loan scams
      'work from home', 'part time job', 'easy money', 'no experience',
      'personal loan', 'instant approval', 'no documents', 'bad credit ok'
    ];

    // Check for suspicious keywords
    for (const pattern of suspiciousPatterns) {
      if (content.toLowerCase().includes(pattern)) {
        features.suspiciousKeywords.push(pattern);
      }
    }

    // Urgency score calculation
    const urgencyWords = ['urgent', 'immediate', 'asap', 'quickly', 'hurry', 'fast', 'now', 'today'];
    features.urgencyScore = urgencyWords.filter(word => 
      content.toLowerCase().includes(word)
    ).length / urgencyWords.length;

    // Extract phone numbers
    const phoneRegex = /(\+91|91)?[6-9]\d{9}/g;
    features.phoneNumbers = content.match(phoneRegex) || [];

    // Extract URLs
    const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+)/g;
    features.urls = content.match(urlRegex) || [];

    // Money mentions
    const moneyRegex = /(\₹|rs\.?|rupees?)\s*\d+/gi;
    features.moneyMentions = content.match(moneyRegex) || [];

    // Time references
    const timeWords = ['today', 'tomorrow', 'within 24 hours', 'expires', 'deadline'];
    features.timeReferences = timeWords.filter(word => 
      content.toLowerCase().includes(word)
    );

    // Personal info requests
    const personalInfoWords = ['aadhar', 'pan card', 'passport', 'bank account', 'password', 'otp'];
    features.personalInfoRequests = personalInfoWords.filter(word => 
      content.toLowerCase().includes(word)
    );

    return features;
  }

  private async updateModel(model: ScamLearningModel, trainingPoint: TrainingData): Promise<void> {
    // Update vocabulary
    const words = trainingPoint.content.toLowerCase().split(/\s+/);
    words.forEach(word => model.vocabulary.add(word));

    // Update suspicious keyword weights
    if (trainingPoint.actualVerdict === 'dangerous' || trainingPoint.actualVerdict === 'suspicious') {
      trainingPoint.features.suspiciousKeywords.forEach(keyword => {
        const currentWeight = model.suspiciousKeywords.get(keyword) || 0;
        model.suspiciousKeywords.set(keyword, currentWeight + model.learningRate);
      });
    }

    // Update pattern recognition
    const patternKey = this.generatePatternKey(trainingPoint.features);
    const existingPattern = model.patterns.get(patternKey) || {
      count: 0,
      threatScore: 0,
      examples: []
    };

    existingPattern.count++;
    if (trainingPoint.actualVerdict === 'dangerous') {
      existingPattern.threatScore += 0.9;
    } else if (trainingPoint.actualVerdict === 'suspicious') {
      existingPattern.threatScore += 0.6;
    } else {
      existingPattern.threatScore += 0.1;
    }

    existingPattern.examples.push({
      content: trainingPoint.content.substring(0, 100),
      verdict: trainingPoint.actualVerdict,
      timestamp: trainingPoint.timestamp
    });

    // Keep only recent examples
    if (existingPattern.examples.length > 5) {
      existingPattern.examples = existingPattern.examples.slice(-5);
    }

    model.patterns.set(patternKey, existingPattern);
    model.trainingCount++;

    // Update model accuracy based on user feedback
    if (trainingPoint.userFeedback) {
      if (trainingPoint.userFeedback === 'correct') {
        model.accuracy = Math.min(0.99, model.accuracy + 0.01);
      } else {
        model.accuracy = Math.max(0.50, model.accuracy - 0.02);
      }
    }
  }

  private async runPrediction(model: ScamLearningModel, features: ContentFeatures, content: string): Promise<AIPrediction> {
    let threatScore = 0;
    const riskFactors: string[] = [];
    const aiInsights: string[] = [];

    // Base scoring from learned patterns
    const patternKey = this.generatePatternKey(features);
    const matchingPattern = model.patterns.get(patternKey);
    
    if (matchingPattern) {
      const patternThreatScore = matchingPattern.threatScore / matchingPattern.count;
      threatScore += patternThreatScore * 0.4;
      aiInsights.push(`Pattern matches ${matchingPattern.count} previous cases (${(patternThreatScore * 100).toFixed(0)}% threat rate)`);
    }

    // Suspicious keyword scoring
    let keywordScore = 0;
    features.suspiciousKeywords.forEach(keyword => {
      const weight = model.suspiciousKeywords.get(keyword) || 0.1;
      keywordScore += weight;
      riskFactors.push(`AI detected suspicious keyword: "${keyword}"`);
    });
    threatScore += Math.min(keywordScore * 0.3, 0.5);

    // Urgency scoring
    if (features.urgencyScore > 0.3) {
      threatScore += features.urgencyScore * 0.2;
      riskFactors.push(`High urgency language detected (${(features.urgencyScore * 100).toFixed(0)}% urgency score)`);
    }

    // Multi-factor analysis
    let multiFactorScore = 0;
    if (features.phoneNumbers.length > 0) multiFactorScore += 0.1;
    if (features.urls.length > 0) multiFactorScore += 0.15;
    if (features.moneyMentions.length > 0) multiFactorScore += 0.2;
    if (features.personalInfoRequests.length > 0) multiFactorScore += 0.25;

    threatScore += multiFactorScore;

    // AI confidence adjustment based on model accuracy
    const confidence = Math.min(95, threatScore * 100 * model.accuracy);

    // Determine verdict
    let verdict: 'safe' | 'suspicious' | 'dangerous';
    if (threatScore >= 0.7) {
      verdict = 'dangerous';
      aiInsights.push(`AI model confidence: ${model.accuracy * 100}% - High threat detected`);
    } else if (threatScore >= 0.4) {
      verdict = 'suspicious';
      aiInsights.push(`AI model confidence: ${model.accuracy * 100}% - Moderate threat detected`);
    } else {
      verdict = 'safe';
      aiInsights.push(`AI analysis suggests content is likely safe`);
    }

    // Add model insights
    aiInsights.push(`Learned from ${model.trainingCount} previous scam cases`);
    aiInsights.push(`Vocabulary contains ${model.vocabulary.size} unique words`);

    return {
      verdict,
      confidence,
      riskFactors,
      aiInsights
    };
  }

  private generatePatternKey(features: ContentFeatures): string {
    // Create a pattern signature based on features
    const keywordHash = features.suspiciousKeywords.sort().join('|');
    const structureHash = [
      features.phoneNumbers.length > 0 ? 'P' : '',
      features.urls.length > 0 ? 'U' : '',
      features.moneyMentions.length > 0 ? 'M' : '',
      features.urgencyScore > 0.5 ? 'URG' : '',
      features.personalInfoRequests.length > 0 ? 'PII' : ''
    ].filter(Boolean).join('');

    return `${keywordHash}:${structureHash}`.substring(0, 100);
  }

  private async retrainModels(): Promise<void> {
    if (this.isTraining) return;

    this.isTraining = true;
    console.log('🔄 Starting AI model retraining...');

    try {
      // Get recent training data for each model type
      for (const [type, model] of Array.from(this.learningModels)) {
        const recentData = this.trainingData
          .filter(data => data.type === type)
          .slice(-50); // Use last 50 training examples

        if (recentData.length >= 10) {
          await this.performModelRetraining(model, recentData);
        }
      }

      this.lastTraining = new Date();
      console.log('✅ AI model retraining completed');
    } catch (error) {
      console.error('❌ Error during model retraining:', error);
    } finally {
      this.isTraining = false;
    }
  }

  private async performModelRetraining(model: ScamLearningModel, trainingData: TrainingData[]): Promise<void> {
    // Calculate new accuracy based on recent performance
    const correctPredictions = trainingData.filter(data => {
      if (!data.userFeedback) return true; // No feedback assumed correct
      return data.userFeedback === 'correct';
    }).length;

    const newAccuracy = correctPredictions / trainingData.length;
    
    // Weighted average with previous accuracy
    model.accuracy = (model.accuracy * 0.7) + (newAccuracy * 0.3);

    // Adjust learning rate based on performance
    if (newAccuracy > 0.8) {
      model.learningRate *= 0.95; // Slow down learning if performing well
    } else {
      model.learningRate *= 1.05; // Speed up learning if struggling
    }

    model.learningRate = Math.max(0.01, Math.min(0.3, model.learningRate));
  }

  private startContinuousLearning(): void {
    // Retrain models every hour with new data
    setInterval(async () => {
      if (this.trainingData.length > this.learningModels.size * 5) {
        await this.retrainModels();
      }
    }, 60 * 60 * 1000); // 1 hour

    console.log('🔄 Continuous learning started - models will retrain hourly');
  }

  // Get AI learning status
  getAIStatus(): AILearningStatus {
    const modelStats = Array.from(this.learningModels.entries()).map(([type, model]) => ({
      type,
      accuracy: model.accuracy,
      trainingCount: model.trainingCount,
      patternsLearned: model.patterns.size,
      vocabularySize: model.vocabulary.size,
      learningRate: model.learningRate
    }));

    return {
      isActive: true,
      isTraining: this.isTraining,
      lastTraining: this.lastTraining,
      totalTrainingData: this.trainingData.length,
      models: modelStats,
      averageAccuracy: modelStats.reduce((sum, model) => sum + model.accuracy, 0) / modelStats.length
    };
  }

  // Provide user feedback for learning
  async provideFeedback(scanId: string, feedback: 'correct' | 'incorrect', actualThreat?: string): Promise<void> {
    // Find the corresponding training data and update
    const trainingPoint = this.trainingData.find(data => data.id.toString() === scanId);
    if (trainingPoint) {
      trainingPoint.userFeedback = feedback;
      if (actualThreat) {
        trainingPoint.actualVerdict = actualThreat;
      }

      // Immediately update the model with this feedback
      const model = this.learningModels.get(trainingPoint.type);
      if (model) {
        await this.updateModel(model, trainingPoint);
      }
    }
  }
}

// Types
interface ScamLearningModel {
  type: string;
  confidence: number;
  patterns: Map<string, PatternData>;
  vocabulary: Set<string>;
  suspiciousKeywords: Map<string, number>;
  learningRate: number;
  trainingCount: number;
  accuracy: number;
}

interface PatternData {
  count: number;
  threatScore: number;
  examples: Array<{
    content: string;
    verdict: string;
    timestamp: Date;
  }>;
}

interface TrainingData {
  id: number;
  type: string;
  content: string;
  features: ContentFeatures;
  actualVerdict: string;
  userFeedback?: 'correct' | 'incorrect';
  confidence: number;
  timestamp: Date;
}

interface ContentFeatures {
  wordCount: number;
  suspiciousKeywords: string[];
  urgencyScore: number;
  phoneNumbers: string[];
  urls: string[];
  moneyMentions: string[];
  timeReferences: string[];
  personalInfoRequests: string[];
}

interface AIPrediction {
  verdict: 'safe' | 'suspicious' | 'dangerous';
  confidence: number;
  riskFactors: string[];
  aiInsights: string[];
}

interface LearningResult {
  success: boolean;
  message: string;
  modelAccuracy?: number;
  patternsLearned?: number;
}

interface AILearningStatus {
  isActive: boolean;
  isTraining: boolean;
  lastTraining: Date;
  totalTrainingData: number;
  models: Array<{
    type: string;
    accuracy: number;
    trainingCount: number;
    patternsLearned: number;
    vocabularySize: number;
    learningRate: number;
  }>;
  averageAccuracy: number;
}

// Export singleton instance
export const aiPatternLearning = AIPatternLearningService.getInstance();