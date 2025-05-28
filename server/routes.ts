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
