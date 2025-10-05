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

export async function registerRoutes(app: Express): Promise<Server> {
  // URL Scan endpoint
  app.post("/api/scan/url", async (req, res) => {
    try {
      const { url } = req.body;

      if (!url || typeof url !== "string") {
        return res.status(400).json({ error: "URL is required" });
      }

      const { riskFactors, confidence } = analyzeURL(url);

      let verdict = "safe";
      if (confidence >= 70) verdict = "dangerous";
      else if (confidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "url",
        content: url,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
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

      let verdict = "safe";
      if (confidence >= 70) verdict = "dangerous";
      else if (confidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "sms",
        content: text,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
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

      let verdict = "safe";
      if (confidence >= 70) verdict = "dangerous";
      else if (confidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "qr",
        content: decodedText,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
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

      let verdict = "safe";
      if (confidence >= 70) verdict = "dangerous";
      else if (confidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "apk",
        content: appName,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
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

      let verdict = "safe";
      if (confidence >= 70) verdict = "dangerous";
      else if (confidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "call",
        content: transcript,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
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

      let verdict = "safe";
      if (confidence >= 70) verdict = "dangerous";
      else if (confidence >= 40) verdict = "suspicious";

      const scan = await storage.createScan({
        type: "phone",
        content: phoneNumber,
        verdict,
        confidence,
        riskFactors,
        ipAddress: req.ip,
      });

      res.json({
        id: scan.id,
        verdict,
        confidence,
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
