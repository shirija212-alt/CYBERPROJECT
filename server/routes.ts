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
