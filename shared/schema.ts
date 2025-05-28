import { pgTable, text, serial, integer, boolean, timestamp, json, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const scans = pgTable("scans", {
  id: serial("id").primaryKey(),
  type: text("type").notNull(), // 'url', 'sms', 'qr', 'apk', 'call'
  content: text("content").notNull(),
  verdict: text("verdict").notNull(), // 'safe', 'suspicious', 'dangerous'
  confidence: integer("confidence").notNull(), // 0-100
  riskFactors: json("risk_factors"), // array of detected patterns
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  ipAddress: text("ip_address"),
});

export const reports = pgTable("reports", {
  id: serial("id").primaryKey(),
  type: text("type").notNull(), // 'loan_fraud', 'rummy_scam', 'phishing', etc.
  content: text("content").notNull(),
  description: text("description"),
  reporterIp: text("reporter_ip"),
  verified: boolean("verified").default(false),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
});

export const scamPatterns = pgTable("scam_patterns", {
  id: serial("id").primaryKey(),
  category: text("category").notNull(), // 'loan', 'rummy', 'phishing', 'upi'
  pattern: text("pattern").notNull(),
  weight: integer("weight").notNull(), // importance of this pattern (1-100)
  description: text("description"),
});

export const insertScanSchema = createInsertSchema(scans).omit({
  id: true,
  timestamp: true,
});

export const insertReportSchema = createInsertSchema(reports).omit({
  id: true,
  timestamp: true,
  verified: true,
});

export const insertScamPatternSchema = createInsertSchema(scamPatterns).omit({
  id: true,
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scans.$inferSelect;
export type InsertReport = z.infer<typeof insertReportSchema>;
export type Report = typeof reports.$inferSelect;
export type InsertScamPattern = z.infer<typeof insertScamPatternSchema>;
export type ScamPattern = typeof scamPatterns.$inferSelect;
