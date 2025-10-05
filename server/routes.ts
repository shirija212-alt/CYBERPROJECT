import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertScanSchema, insertReportSchema } from "@shared/schema";
import { z } from "zod";
import {
  analyzeURL,
  analyzeSMS,
  analyzeCall,
  analyzeAPK,
  analyzePhoneNumber,
} from "./scam-detector";
import { getMLVerdict } from "./ml-service";

export async function registerRoutes(app: Express): Promise<Server> {
  // URL Scan endpoint
  app.post("/api/scan/url", async (req, res) => {
    try {
      const { url } = req.body;

      if (!url || typeof url !== "string") {
        return res.status(400).json({ error: "URL is required" });
      }

      const { riskFactors, confidence } = analyzeURL(url);
      const mlResult = await getMLVerdict(url, ["safe", "phishing", "malware", "scam"]);

      let mlConfidence = 0;
      if (mlResult) {
        if (mlResult.label !== "safe") {
          mlConfidence = mlResult.score * 100;
        }
      }

      const combinedConfidence = (confidence + mlConfidence) / 2;

      let verdict = "safe";
      if (combinedConfidence >= 70) verdict = "dangerous";
      else if (combinedConfidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "url",
        content: url,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        timestamp: scan.timestamp,
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // SMS Scan endpoint
  app.post("/api/scan/sms", async (req, res) => {
    try {
      const { text } = req.body;

      if (!text || typeof text !== "string") {
        return res.status(400).json({ error: "SMS text is required" });
      }

      const { riskFactors, confidence } = analyzeSMS(text);
      const mlResult = await getMLVerdict(text, ["scam", "spam", "safe"]);

      let mlConfidence = 0;
      if (mlResult) {
        if (mlResult.label === "scam") {
          mlConfidence = mlResult.score * 100;
        } else if (mlResult.label === "spam") {
          mlConfidence = mlResult.score * 50;
        }
      }

      const combinedConfidence = (confidence + mlConfidence) / 2;

      let verdict = "safe";
      if (combinedConfidence >= 70) verdict = "dangerous";
      else if (combinedConfidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "sms",
        content: text,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        timestamp: scan.timestamp,
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // QR Code Scan endpoint
  app.post("/api/scan/qr", async (req, res) => {
    try {
      const { decodedText } = req.body;

      if (!decodedText || typeof decodedText !== "string") {
        return res
          .status(400)
          .json({ error: "Decoded QR text is required" });
      }

      // Assume QR codes contain URLs for now
      const { riskFactors, confidence } = analyzeURL(decodedText);
      const mlResult = await getMLVerdict(decodedText, ["safe", "phishing", "malware", "scam"]);

      let mlConfidence = 0;
      if (mlResult) {
        if (mlResult.label !== "safe") {
          mlConfidence = mlResult.score * 100;
        }
      }

      const combinedConfidence = (confidence + mlConfidence) / 2;

      let verdict = "safe";
      if (combinedConfidence >= 70) verdict = "dangerous";
      else if (combinedConfidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "qr",
        content: decodedText,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        timestamp: scan.timestamp,
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
        return res
          .status(400)
          .json({ error: "App name and extracted strings are required" });
      }

      const { riskFactors, confidence } = analyzeAPK(
        appName,
        extractedStrings
      );
      const mlResult = await getMLVerdict(extractedStrings, ["safe", "malware", "adware", "spyware"]);

      let mlConfidence = 0;
      if (mlResult) {
        if (mlResult.label !== "safe") {
          mlConfidence = mlResult.score * 100;
        }
      }

      const combinedConfidence = (confidence + mlConfidence) / 2;

      let verdict = "safe";
      if (combinedConfidence >= 70) verdict = "dangerous";
      else if (combinedConfidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "apk",
        content: appName,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        timestamp: scan.timestamp,
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Call Analysis endpoint
  app.post("/api/scan/call", async (req, res) => {
    try {
      const { transcript } = req.body;

      if (!transcript || typeof transcript !== "string") {
        return res.status(400).json({ error: "Call transcript is required" });
      }

      const { riskFactors, confidence } = analyzeCall(transcript);
      const mlResult = await getMLVerdict(transcript, ["scam", "spam", "safe"]);

      let mlConfidence = 0;
      if (mlResult) {
        if (mlResult.label === "scam") {
          mlConfidence = mlResult.score * 100;
        } else if (mlResult.label === "spam") {
          mlConfidence = mlResult.score * 50;
        }
      }

      const combinedConfidence = (confidence + mlConfidence) / 2;

      let verdict = "safe";
      if (combinedConfidence >= 70) verdict = "dangerous";
      else if (combinedConfidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "call",
        content: transcript,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        timestamp: scan.timestamp,
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/scan/phone", async (req, res) => {
    try {
      const { phoneNumber } = req.body;

      if (!phoneNumber || typeof phoneNumber !== "string") {
        return res.status(400).json({ error: "Phone number is required" });
      }

      const { riskFactors, confidence } = analyzePhoneNumber(phoneNumber);
      const mlResult = await getMLVerdict(phoneNumber, ["safe", "spam", "scam"]);

      let mlConfidence = 0;
      if (mlResult) {
        if (mlResult.label === "scam") {
          mlConfidence = mlResult.score * 100;
        } else if (mlResult.label === "spam") {
          mlConfidence = mlResult.score * 50;
        }
      }

      const combinedConfidence = (confidence + mlConfidence) / 2;

      let verdict = "safe";
      if (combinedConfidence >= 70) verdict = "dangerous";
      else if (combinedConfidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "phone",
        content: phoneNumber,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence: combinedConfidence,
        riskFactors,
        timestamp: scan.timestamp,
      });
    } catch (error) {
      console.error("Error in phone number scan:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
