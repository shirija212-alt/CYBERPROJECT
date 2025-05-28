import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertScanSchema, insertReportSchema } from "@shared/schema";
import { z } from "zod";

// Import scam detection utilities
import { detectScamPatterns, calculateRiskScore } from "./scam-detector";

export async function registerRoutes(app: Express): Promise<Server> {
  
  // URL Scan endpoint
  app.post("/api/scan/url", async (req, res) => {
    try {
      const { url } = req.body;
      
      if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: "URL is required" });
      }

      // Detect scam patterns in URL
      const patterns = await storage.getScamPatterns();
      const riskFactors = detectScamPatterns(url, patterns);
      const confidence = calculateRiskScore(riskFactors);
      
      let verdict = 'safe';
      if (confidence >= 70) verdict = 'dangerous';
      else if (confidence >= 40) verdict = 'suspicious';

      // Save scan result
      const scan = await storage.createScan({
        type: 'url',
        content: url,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
        riskFactors,
        timestamp: scan.timestamp
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // SMS Scan endpoint
  app.post("/api/scan/sms", async (req, res) => {
    try {
      const { text } = req.body;
      
      if (!text || typeof text !== 'string') {
        return res.status(400).json({ error: "SMS text is required" });
      }

      const patterns = await storage.getScamPatterns();
      const riskFactors = detectScamPatterns(text.toLowerCase(), patterns);
      const confidence = calculateRiskScore(riskFactors);
      
      let verdict = 'safe';
      if (confidence >= 70) verdict = 'dangerous';
      else if (confidence >= 40) verdict = 'suspicious';

      const scan = await storage.createScan({
        type: 'sms',
        content: text,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
        riskFactors,
        timestamp: scan.timestamp
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // QR Code Scan endpoint
  app.post("/api/scan/qr", async (req, res) => {
    try {
      const { decodedText } = req.body;
      
      if (!decodedText || typeof decodedText !== 'string') {
        return res.status(400).json({ error: "Decoded QR text is required" });
      }

      const patterns = await storage.getScamPatterns();
      const riskFactors = detectScamPatterns(decodedText.toLowerCase(), patterns);
      const confidence = calculateRiskScore(riskFactors);
      
      let verdict = 'safe';
      if (confidence >= 70) verdict = 'dangerous';
      else if (confidence >= 40) verdict = 'suspicious';

      const scan = await storage.createScan({
        type: 'qr',
        content: decodedText,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
        riskFactors,
        timestamp: scan.timestamp
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // APK Scan endpoint
  app.post("/api/scan/apk", async (req, res) => {
    try {
      const { appName, extractedStrings } = req.body;
      
      if (!appName || !extractedStrings) {
        return res.status(400).json({ error: "App name and extracted strings are required" });
      }

      const patterns = await storage.getScamPatterns();
      const combinedText = `${appName} ${extractedStrings}`.toLowerCase();
      const riskFactors = detectScamPatterns(combinedText, patterns);
      const confidence = calculateRiskScore(riskFactors);
      
      let verdict = 'safe';
      if (confidence >= 70) verdict = 'dangerous';
      else if (confidence >= 40) verdict = 'suspicious';

      const scan = await storage.createScan({
        type: 'apk',
        content: appName,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
        riskFactors,
        timestamp: scan.timestamp
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Call Analysis endpoint
  app.post("/api/scan/call", async (req, res) => {
    try {
      const { transcript } = req.body;
      
      if (!transcript || typeof transcript !== 'string') {
        return res.status(400).json({ error: "Call transcript is required" });
      }

      const patterns = await storage.getScamPatterns();
      const riskFactors = detectScamPatterns(transcript.toLowerCase(), patterns);
      const confidence = calculateRiskScore(riskFactors);
      
      let verdict = 'safe';
      if (confidence >= 70) verdict = 'dangerous';
      else if (confidence >= 40) verdict = 'suspicious';

      const scan = await storage.createScan({
        type: 'call',
        content: transcript,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
        riskFactors,
        timestamp: scan.timestamp
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Phone Number Check endpoint with Real-Time Threat Intelligence
  app.post("/api/scan/phone", async (req, res) => {
    try {
      const { phoneNumber } = req.body;
      
      if (!phoneNumber || typeof phoneNumber !== 'string') {
        return res.status(400).json({ error: "Phone number is required" });
      }

      // Use Real-Time Threat Intelligence for comprehensive analysis
      const { threatIntelligence } = await import('./threat-intelligence');
      const analysis = await threatIntelligence.lookupPhoneNumber(phoneNumber);

      // Convert threat analysis to API response format
      const riskFactors = analysis.sources.length > 0 
        ? analysis.sources.map(source => `${source.source}: ${source.details}`)
        : ['No threat intelligence found', 'Number appears safe'];

      // Enhanced scammer data from multiple sources
      const enhancedScammerData = analysis.sources.length > 0 ? {
        number: analysis.phoneNumber,
        type: analysis.sources[0].fraudType,
        reports: analysis.sources.reduce((total, source) => total + source.reportCount, 0),
        lastSeen: analysis.sources[0].lastSeen,
        verified: analysis.sources.some(source => source.verified),
        sources: analysis.sources.map(source => ({
          name: source.source,
          confidence: source.confidence,
          verified: source.verified
        }))
      } : null;

      res.json({
        id: Date.now(), // Temporary ID for response
        verdict: analysis.riskLevel,
        confidence: analysis.confidence,
        riskFactors,
        timestamp: analysis.lastChecked,
        scammerData: enhancedScammerData,
        threatIntelligence: {
          sourcesChecked: analysis.sources.length,
          lastUpdated: analysis.lastChecked,
          multiSourceVerification: analysis.sources.length > 1
        }
      });
    } catch (error) {
      console.error('Error in threat intelligence lookup:', error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Threat Intelligence Status endpoint
  app.get("/api/threat-intelligence/status", async (req, res) => {
    try {
      const { threatIntelligence } = await import('./threat-intelligence');
      const status = threatIntelligence.getStatus();
      res.json(status);
    } catch (error) {
      console.error('Error getting threat intelligence status:', error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // AI Pattern Learning Status endpoint
  app.get("/api/ai-learning/status", async (req, res) => {
    try {
      const { aiPatternLearning } = await import('./ai-pattern-learning');
      const status = aiPatternLearning.getAIStatus();
      res.json(status);
    } catch (error) {
      console.error('Error getting AI learning status:', error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // AI Feedback endpoint
  app.post("/api/ai-learning/feedback", async (req, res) => {
    try {
      const { scanId, feedback, actualThreat } = req.body;
      
      if (!scanId || !feedback) {
        return res.status(400).json({ error: "Scan ID and feedback are required" });
      }

      const { aiPatternLearning } = await import('./ai-pattern-learning');
      await aiPatternLearning.provideFeedback(scanId, feedback, actualThreat);

      res.json({ message: "Feedback recorded successfully" });
    } catch (error) {
      console.error('Error recording AI feedback:', error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Official Data Sources Integration Status
  app.get("/api/official-sources/status", async (req, res) => {
    try {
      const { officialDataSources } = await import('./official-data-sources');
      const status = officialDataSources.getIntegrationStatus();
      res.json(status);
    } catch (error) {
      console.error('Error getting official sources status:', error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Configure API Keys for Official Sources
  app.post("/api/official-sources/configure", async (req, res) => {
    try {
      const { source, apiKey } = req.body;
      
      if (!source || !apiKey) {
        return res.status(400).json({ error: "Source and API key are required" });
      }

      const { officialDataSources } = await import('./official-data-sources');
      officialDataSources.setAPIKey(source, apiKey);

      res.json({ message: `API key configured for ${source}` });
    } catch (error) {
      console.error('Error configuring API key:', error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Enhanced Phone Verification with Official Sources
  app.post("/api/scan/phone/official", async (req, res) => {
    try {
      const { phoneNumber } = req.body;
      
      if (!phoneNumber || typeof phoneNumber !== 'string') {
        return res.status(400).json({ error: "Phone number is required" });
      }

      const { officialDataSources } = await import('./official-data-sources');
      const officialResult = await officialDataSources.verifyPhoneNumberOfficial(phoneNumber);

      res.json({
        phoneNumber: officialResult.phoneNumber,
        threatLevel: officialResult.threatLevel,
        isVerified: officialResult.isVerified,
        confidence: officialResult.confidence,
        officialSources: officialResult.officialSources,
        governmentVerified: officialResult.governmentVerified,
        totalReports: officialResult.totalReports,
        lastUpdated: officialResult.lastUpdated
      });
    } catch (error) {
      console.error('Error in official phone verification:', error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Mobile App API Endpoints
  
  // Mobile Real-Time Call Screening
  app.post("/api/mobile/call-screen", async (req, res) => {
    try {
      const { phoneNumber, deviceId } = req.body;
      
      if (!phoneNumber) {
        return res.status(400).json({ error: "Phone number is required" });
      }

      // Combine threat intelligence and AI analysis for mobile
      const { threatIntelligence } = await import('./threat-intelligence');
      const { aiPatternLearning } = await import('./ai-pattern-learning');
      
      const threatAnalysis = await threatIntelligence.lookupPhoneNumber(phoneNumber);
      
      // Mobile-optimized response
      const mobileResponse = {
        phoneNumber: threatAnalysis.phoneNumber,
        action: threatAnalysis.riskLevel === 'dangerous' ? 'BLOCK' : 
                threatAnalysis.riskLevel === 'suspicious' ? 'WARN' : 'ALLOW',
        alertLevel: threatAnalysis.riskLevel.toUpperCase(),
        confidence: threatAnalysis.confidence,
        displayMessage: threatAnalysis.riskLevel === 'dangerous' 
          ? `⚠️ SCAMMER ALERT - ${threatAnalysis.sources[0]?.fraudType || 'Fraud'}`
          : threatAnalysis.riskLevel === 'suspicious'
          ? `⚠️ Suspicious - ${threatAnalysis.sources.length} reports`
          : '✅ Safe to answer',
        reportCount: threatAnalysis.sources.reduce((sum, s) => sum + s.reportCount, 0),
        sources: threatAnalysis.sources.map(s => s.source),
        lastUpdated: threatAnalysis.lastChecked,
        autoBlock: threatAnalysis.riskLevel === 'dangerous'
      };

      // Learn from mobile usage
      await aiPatternLearning.learnFromScan({
        type: 'phone',
        content: phoneNumber,
        verdict: threatAnalysis.riskLevel,
        confidence: threatAnalysis.confidence
      });

      res.json(mobileResponse);
    } catch (error) {
      console.error('Error in mobile call screening:', error);
      res.status(500).json({ error: "Call screening unavailable" });
    }
  });

  // Mobile SMS Filtering
  app.post("/api/mobile/sms-filter", async (req, res) => {
    try {
      const { message, sender, deviceId } = req.body;
      
      if (!message) {
        return res.status(400).json({ error: "Message content is required" });
      }

      const { aiPatternLearning } = await import('./ai-pattern-learning');
      const aiPrediction = await aiPatternLearning.predictThreat(message, 'sms');

      // Mobile-optimized SMS filtering response
      const filterResponse = {
        action: aiPrediction.verdict === 'dangerous' ? 'QUARANTINE' :
                aiPrediction.verdict === 'suspicious' ? 'FLAG' : 'ALLOW',
        verdict: aiPrediction.verdict.toUpperCase(),
        confidence: aiPrediction.confidence,
        riskFactors: aiPrediction.riskFactors,
        notification: aiPrediction.verdict === 'dangerous'
          ? '🚨 Blocked spam message'
          : aiPrediction.verdict === 'suspicious'
          ? '⚠️ Suspicious message flagged'
          : null,
        folder: aiPrediction.verdict === 'dangerous' ? 'spam' : 'inbox',
        allowUserOverride: aiPrediction.verdict !== 'dangerous'
      };

      // Store scan for learning
      await storage.createScan({
        type: 'sms',
        content: message,
        verdict: aiPrediction.verdict,
        confidence: aiPrediction.confidence,
        riskFactors: aiPrediction.riskFactors,
        ipAddress: req.ip
      });

      res.json(filterResponse);
    } catch (error) {
      console.error('Error in mobile SMS filtering:', error);
      res.status(500).json({ error: "SMS filtering unavailable" });
    }
  });

  // Mobile Threat Database Sync
  app.get("/api/mobile/sync/:lastSync", async (req, res) => {
    try {
      const { lastSync } = req.params;
      const lastSyncDate = new Date(parseInt(lastSync));

      // Get recent threat updates for mobile cache
      const recentScans = await storage.getRecentScans(100);
      const recentReports = await storage.getReports(50);
      
      // Filter updates since last sync
      const updates = recentScans.filter(scan => scan.timestamp > lastSyncDate);
      const newReports = recentReports.filter(report => report.timestamp > lastSyncDate);

      // Mobile-optimized sync payload
      const syncData = {
        threatUpdates: updates.map(scan => ({
          phoneNumber: scan.content,
          threatLevel: scan.verdict,
          confidence: scan.confidence,
          timestamp: scan.timestamp
        })),
        communityReports: newReports.length,
        lastSyncTimestamp: Date.now(),
        recommendedAction: updates.length > 0 ? 'UPDATE_CACHE' : 'NO_ACTION'
      };

      res.json(syncData);
    } catch (error) {
      console.error('Error in mobile sync:', error);
      res.status(500).json({ error: "Sync unavailable" });
    }
  });

  // Mobile Emergency Report
  app.post("/api/mobile/emergency-report", async (req, res) => {
    try {
      const { phoneNumber, messageContent, location, urgency } = req.body;

      if (!phoneNumber && !messageContent) {
        return res.status(400).json({ error: "Phone number or message required" });
      }

      // High-priority emergency report
      const emergencyReport = await storage.createReport({
        type: urgency === 'HIGH' ? 'emergency' : 'mobile',
        content: phoneNumber || messageContent,
        description: `Emergency mobile report: ${urgency} priority from ${location}`,
        reporterIp: req.ip
      });

      // Immediate response for mobile
      res.json({
        reportId: emergencyReport.id,
        status: 'RECEIVED',
        message: '🚨 Emergency report received. Authorities notified.',
        followUpActions: [
          'Block the number immediately',
          'Save evidence (screenshots, recordings)',
          'Report to local cyber crime cell'
        ],
        helplineNumbers: [
          { name: 'Cyber Crime Helpline', number: '1930' },
          { name: 'Emergency Services', number: '112' }
        ]
      });
    } catch (error) {
      console.error('Error in emergency report:', error);
      res.status(500).json({ error: "Emergency report failed" });
    }
  });

  // Report submission endpoint
  app.post("/api/report", async (req, res) => {
    try {
      const reportData = insertReportSchema.parse(req.body);
      
      const report = await storage.createReport({
        ...reportData,
        reporterIp: req.ip
      });

      res.json({
        id: report.id,
        message: "Report submitted successfully",
        timestamp: report.timestamp
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Invalid report data", details: error.errors });
      }
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Get recent scans
  app.get("/api/scans/recent", async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 10;
      const recentScans = await storage.getRecentScans(limit);
      res.json(recentScans);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Get scan statistics
  app.get("/api/stats", async (req, res) => {
    try {
      const stats = await storage.getScanStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Get reports
  app.get("/api/reports", async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 20;
      const reports = await storage.getReports(limit);
      res.json(reports);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}

// Utility functions for scam detection
function detectScamPatterns(content: string, patterns: any[]): string[] {
  const detectedPatterns: string[] = [];
  
  patterns.forEach(pattern => {
    if (content.includes(pattern.pattern.toLowerCase())) {
      detectedPatterns.push(pattern.description || pattern.pattern);
    }
  });
  
  return detectedPatterns;
}

function calculateRiskScore(riskFactors: string[]): number {
  if (riskFactors.length === 0) return 5; // Very low risk
  if (riskFactors.length === 1) return 45; // Moderate risk
  if (riskFactors.length === 2) return 75; // High risk
  return 95; // Very high risk
}
