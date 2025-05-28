import { users, scans, reports, scamPatterns, type User, type InsertUser, type Scan, type InsertScan, type Report, type InsertReport, type ScamPattern, type InsertScamPattern } from "@shared/schema";
import { db } from "./db";
import { eq, desc, sql } from "drizzle-orm";
import { IStorage } from "./storage";

export class DatabaseStorage implements IStorage {
  // User operations
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  // Scan operations
  async createScan(insertScan: InsertScan): Promise<Scan> {
    const [scan] = await db
      .insert(scans)
      .values({
        ...insertScan,
        riskFactors: insertScan.riskFactors || [],
        ipAddress: insertScan.ipAddress || null,
        timestamp: new Date()
      })
      .returning();
    return scan;
  }

  async getRecentScans(limit: number = 10): Promise<Scan[]> {
    return await db
      .select()
      .from(scans)
      .orderBy(desc(scans.timestamp))
      .limit(limit);
  }

  async getScansByType(type: string, limit: number = 10): Promise<Scan[]> {
    return await db
      .select()
      .from(scans)
      .where(eq(scans.type, type))
      .orderBy(desc(scans.timestamp))
      .limit(limit);
  }

  async getScanStats(): Promise<{
    totalScans: number;
    scamsBlocked: number;
    todayScans: number;
    accuracy: number;
  }> {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const [totalScansResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(scans);

    const [scamsBlockedResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(scans)
      .where(sql`verdict IN ('suspicious', 'dangerous')`);

    const [todayScansResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(scans)
      .where(sql`timestamp >= ${today}`);

    const totalScans = totalScansResult?.count || 0;
    const scamsBlocked = scamsBlockedResult?.count || 0;
    const todayScans = todayScansResult?.count || 0;
    const accuracy = totalScans > 0 ? Math.round((scamsBlocked / totalScans) * 100) : 0;

    return {
      totalScans,
      scamsBlocked,
      todayScans,
      accuracy
    };
  }

  // Report operations
  async createReport(insertReport: InsertReport): Promise<Report> {
    const [report] = await db
      .insert(reports)
      .values({
        ...insertReport,
        description: insertReport.description || null,
        reporterIp: insertReport.reporterIp || null,
        verified: false,
        timestamp: new Date()
      })
      .returning();
    return report;
  }

  async getReports(limit: number = 20): Promise<Report[]> {
    return await db
      .select()
      .from(reports)
      .orderBy(desc(reports.timestamp))
      .limit(limit);
  }

  async getReportsByType(type: string): Promise<Report[]> {
    return await db
      .select()
      .from(reports)
      .where(eq(reports.type, type))
      .orderBy(desc(reports.timestamp));
  }

  // Scam pattern operations
  async getScamPatterns(category?: string): Promise<ScamPattern[]> {
    if (category) {
      return await db
        .select()
        .from(scamPatterns)
        .where(eq(scamPatterns.category, category));
    }
    return await db.select().from(scamPatterns);
  }

  async createScamPattern(insertPattern: InsertScamPattern): Promise<ScamPattern> {
    const [pattern] = await db
      .insert(scamPatterns)
      .values({
        ...insertPattern,
        description: insertPattern.description || null
      })
      .returning();
    return pattern;
  }

  // Initialize with default scam patterns
  async initializeDefaultPatterns(): Promise<void> {
    const existingPatterns = await this.getScamPatterns();
    if (existingPatterns.length > 0) {
      return; // Already initialized
    }

    const defaultPatterns = [
      { category: "phishing", pattern: "verify your account", weight: 0.8, description: "Account verification scam" },
      { category: "phishing", pattern: "click here to claim", weight: 0.7, description: "Prize claim scam" },
      { category: "financial", pattern: "send money", weight: 0.9, description: "Money transfer scam" },
      { category: "financial", pattern: "urgent payment", weight: 0.8, description: "Urgent payment scam" },
      { category: "lottery", pattern: "congratulations you won", weight: 0.9, description: "Lottery winner scam" },
      { category: "lottery", pattern: "kbc winner", weight: 0.95, description: "KBC lottery scam" },
      { category: "tech_support", pattern: "microsoft support", weight: 0.85, description: "Fake Microsoft support" },
      { category: "tech_support", pattern: "computer virus", weight: 0.7, description: "Fake virus alert" },
      { category: "romance", pattern: "lonely and looking", weight: 0.6, description: "Romance scam indicator" },
      { category: "investment", pattern: "guaranteed returns", weight: 0.8, description: "Investment fraud" }
    ];

    for (const pattern of defaultPatterns) {
      await this.createScamPattern(pattern);
    }
  }
}