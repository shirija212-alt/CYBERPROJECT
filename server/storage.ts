import { 
  users, scans, reports, scamPatterns,
  type User, type InsertUser,
  type Scan, type InsertScan,
  type Report, type InsertReport,
  type ScamPattern, type InsertScamPattern
} from "@shared/schema";

export interface IStorage {
  // User operations
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Scan operations
  createScan(scan: InsertScan): Promise<Scan>;
  getRecentScans(limit?: number): Promise<Scan[]>;
  getScansByType(type: string, limit?: number): Promise<Scan[]>;
  getScanStats(): Promise<{
    totalScans: number;
    scamsBlocked: number;
    todayScans: number;
    accuracy: number;
  }>;
  
  // Report operations
  createReport(report: InsertReport): Promise<Report>;
  getReports(limit?: number): Promise<Report[]>;
  getReportsByType(type: string): Promise<Report[]>;
  
  // Scam pattern operations
  getScamPatterns(category?: string): Promise<ScamPattern[]>;
  createScamPattern(pattern: InsertScamPattern): Promise<ScamPattern>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private scans: Map<number, Scan>;
  private reports: Map<number, Report>;
  private scamPatterns: Map<number, ScamPattern>;
  private currentUserId: number;
  private currentScanId: number;
  private currentReportId: number;
  private currentPatternId: number;

  constructor() {
    this.users = new Map();
    this.scans = new Map();
    this.reports = new Map();
    this.scamPatterns = new Map();
    this.currentUserId = 1;
    this.currentScanId = 1;
    this.currentReportId = 1;
    this.currentPatternId = 1;
    
    this.initializeScamPatterns();
  }

  private initializeScamPatterns() {
    const defaultPatterns: InsertScamPattern[] = [
      // Loan fraud patterns
      { category: 'loan', pattern: 'instant loan', weight: 90, description: 'Instant loan promises' },
      { category: 'loan', pattern: 'loan approval', weight: 85, description: 'Guaranteed loan approval' },
      { category: 'loan', pattern: 'without documents', weight: 95, description: 'No document loans' },
      { category: 'loan', pattern: 'immediate fund', weight: 80, description: 'Immediate fund transfer' },
      
      // Rummy/Gaming patterns
      { category: 'rummy', pattern: 'earn money playing', weight: 90, description: 'Earn money playing games' },
      { category: 'rummy', pattern: 'guaranteed win', weight: 95, description: 'Guaranteed winning' },
      { category: 'rummy', pattern: 'daily earning', weight: 85, description: 'Daily earning promises' },
      { category: 'rummy', pattern: 'cash game', weight: 70, description: 'Cash game references' },
      
      // Phishing patterns
      { category: 'phishing', pattern: 'verify account', weight: 80, description: 'Account verification scam' },
      { category: 'phishing', pattern: 'suspended account', weight: 85, description: 'Account suspension threat' },
      { category: 'phishing', pattern: 'click here now', weight: 75, description: 'Urgent action required' },
      { category: 'phishing', pattern: 'update kyc', weight: 80, description: 'KYC update scam' },
      
      // UPI fraud patterns
      { category: 'upi', pattern: 'upi pin', weight: 95, description: 'UPI PIN request' },
      { category: 'upi', pattern: 'payment failed', weight: 70, description: 'Fake payment failure' },
      { category: 'upi', pattern: 'refund process', weight: 75, description: 'Fake refund process' },
      
      // Lottery scams
      { category: 'lottery', pattern: 'kbc winner', weight: 95, description: 'KBC lottery scam' },
      { category: 'lottery', pattern: 'congratulations won', weight: 90, description: 'Congratulatory lottery scam' },
      { category: 'lottery', pattern: 'prize money', weight: 85, description: 'Prize money scam' },
    ];

    defaultPatterns.forEach(pattern => {
      this.createScamPattern(pattern);
    });
  }

  // User operations
  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserId++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  // Scan operations
  async createScan(insertScan: InsertScan): Promise<Scan> {
    const id = this.currentScanId++;
    const scan: Scan = { 
      ...insertScan, 
      id,
      timestamp: new Date(),
      riskFactors: insertScan.riskFactors ?? [],
      ipAddress: insertScan.ipAddress ?? null
    };
    this.scans.set(id, scan);
    return scan;
  }

  async getRecentScans(limit: number = 10): Promise<Scan[]> {
    const allScans = Array.from(this.scans.values());
    return allScans
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  async getScansByType(type: string, limit: number = 10): Promise<Scan[]> {
    const scansByType = Array.from(this.scans.values())
      .filter(scan => scan.type === type);
    return scansByType
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  async getScanStats(): Promise<{
    totalScans: number;
    scamsBlocked: number;
    todayScans: number;
    accuracy: number;
  }> {
    const allScans = Array.from(this.scans.values());
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const todayScans = allScans.filter(scan => scan.timestamp >= today).length;
    const scamsBlocked = allScans.filter(scan => 
      scan.verdict === 'dangerous' || scan.verdict === 'suspicious'
    ).length;
    
    return {
      totalScans: allScans.length,
      scamsBlocked,
      todayScans,
      accuracy: 95.8 // Simulated accuracy rate
    };
  }

  // Report operations
  async createReport(insertReport: InsertReport): Promise<Report> {
    const id = this.currentReportId++;
    const report: Report = { 
      ...insertReport, 
      id,
      description: insertReport.description ?? null,
      reporterIp: insertReport.reporterIp ?? null,
      verified: false,
      timestamp: new Date()
    };
    this.reports.set(id, report);
    return report;
  }

  async getReports(limit: number = 20): Promise<Report[]> {
    const allReports = Array.from(this.reports.values());
    return allReports
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  async getReportsByType(type: string): Promise<Report[]> {
    return Array.from(this.reports.values())
      .filter(report => report.type === type)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  // Scam pattern operations
  async getScamPatterns(category?: string): Promise<ScamPattern[]> {
    const allPatterns = Array.from(this.scamPatterns.values());
    if (category) {
      return allPatterns.filter(pattern => pattern.category === category);
    }
    return allPatterns;
  }

  async createScamPattern(insertPattern: InsertScamPattern): Promise<ScamPattern> {
    const id = this.currentPatternId++;
    const pattern: ScamPattern = { 
      ...insertPattern, 
      id, 
      description: insertPattern.description ?? null 
    };
    this.scamPatterns.set(id, pattern);
    return pattern;
  }
}

import { db } from "./db";
import { eq, desc, sql } from "drizzle-orm";

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
      { category: "phishing", pattern: "verify your account", weight: 80, description: "Account verification scam" },
      { category: "phishing", pattern: "click here to claim", weight: 70, description: "Prize claim scam" },
      { category: "financial", pattern: "send money", weight: 90, description: "Money transfer scam" },
      { category: "financial", pattern: "urgent payment", weight: 80, description: "Urgent payment scam" },
      { category: "lottery", pattern: "congratulations you won", weight: 90, description: "Lottery winner scam" },
      { category: "lottery", pattern: "kbc winner", weight: 95, description: "KBC lottery scam" },
      { category: "tech_support", pattern: "microsoft support", weight: 85, description: "Fake Microsoft support" },
      { category: "tech_support", pattern: "computer virus", weight: 70, description: "Fake virus alert" },
      { category: "romance", pattern: "lonely and looking", weight: 60, description: "Romance scam indicator" },
      { category: "investment", pattern: "guaranteed returns", weight: 80, description: "Investment fraud" }
    ];

    for (const pattern of defaultPatterns) {
      await this.createScamPattern(pattern);
    }
  }
}

export const storage = new DatabaseStorage();
