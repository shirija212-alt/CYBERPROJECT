import { INDIAN_SCAM_PATTERNS } from "./indian-scam-patterns";

export interface ScamPattern {
  id: string;
  category: string;
  pattern: string;
  weight: number;
  description: string;
}

export interface DetectionResult {
  verdict: 'safe' | 'suspicious' | 'dangerous';
  confidence: number;
  riskFactors: string[];
  patterns: ScamPattern[];
}

export class ScamDetector {
  private patterns: ScamPattern[];

  constructor() {
    this.patterns = INDIAN_SCAM_PATTERNS;
  }

  /**
   * Analyzes content for scam patterns
   */
  analyzeContent(content: string, contentType: 'url' | 'sms' | 'call' | 'apk' | 'qr'): DetectionResult {
    const normalizedContent = content.toLowerCase().trim();
    const detectedPatterns: ScamPattern[] = [];
    const riskFactors: string[] = [];
    let totalWeight = 0;

    // Find matching patterns
    this.patterns.forEach(pattern => {
      if (this.matchesPattern(normalizedContent, pattern.pattern)) {
        detectedPatterns.push(pattern);
        riskFactors.push(pattern.description);
        totalWeight += pattern.weight;
      }
    });

    // Content-specific checks
    switch (contentType) {
      case 'url':
        this.checkURLSpecific(normalizedContent, detectedPatterns, riskFactors);
        break;
      case 'sms':
        this.checkSMSSpecific(normalizedContent, detectedPatterns, riskFactors);
        break;
      case 'call':
        this.checkCallSpecific(normalizedContent, detectedPatterns, riskFactors);
        break;
      case 'apk':
        this.checkAPKSpecific(normalizedContent, detectedPatterns, riskFactors);
        break;
      case 'qr':
        this.checkQRSpecific(normalizedContent, detectedPatterns, riskFactors);
        break;
    }

    // Calculate confidence score
    const confidence = this.calculateConfidence(detectedPatterns, totalWeight, contentType);
    
    // Determine verdict
    const verdict = this.determineVerdict(confidence, detectedPatterns);

    return {
      verdict,
      confidence,
      riskFactors: [...new Set(riskFactors)], // Remove duplicates
      patterns: detectedPatterns
    };
  }

  /**
   * Checks if content matches a pattern
   */
  private matchesPattern(content: string, pattern: string): boolean {
    // Simple substring matching for now
    // In a real implementation, this could use regex or fuzzy matching
    return content.includes(pattern.toLowerCase());
  }

  /**
   * URL-specific checks
   */
  private checkURLSpecific(url: string, patterns: ScamPattern[], riskFactors: string[]): void {
    // Check for suspicious domains
    const suspiciousDomains = [
      '.tk', '.ml', '.ga', '.cf', // Free domains often used by scammers
      'bit.ly', 'tinyurl.com', 'short.link' // URL shorteners
    ];
    
    suspiciousDomains.forEach(domain => {
      if (url.includes(domain)) {
        riskFactors.push(`Suspicious domain: ${domain}`);
      }
    });

    // Check for IP addresses instead of domains
    const ipPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    if (ipPattern.test(url)) {
      riskFactors.push('Uses IP address instead of domain name');
    }

    // Check for multiple subdomains (subdomain abuse)
    const subdomainCount = (url.match(/\./g) || []).length;
    if (subdomainCount > 3) {
      riskFactors.push('Excessive subdomains detected');
    }
  }

  /**
   * SMS-specific checks
   */
  private checkSMSSpecific(sms: string, patterns: ScamPattern[], riskFactors: string[]): void {
    // Check for urgency words
    const urgencyWords = ['urgent', 'immediate', 'expire', 'block', 'suspend', 'limited time'];
    urgencyWords.forEach(word => {
      if (sms.includes(word)) {
        riskFactors.push(`Urgency tactic: "${word}"`);
      }
    });

    // Check for monetary amounts
    const moneyPattern = /₹[\d,]+|rs\.?\s*\d+|\d+\s*lakh|\d+\s*crore/i;
    if (moneyPattern.test(sms)) {
      riskFactors.push('Contains monetary amounts');
    }

    // Check for shortened URLs
    if (sms.includes('bit.ly') || sms.includes('short.link') || sms.includes('tinyurl')) {
      riskFactors.push('Contains shortened URLs');
    }
  }

  /**
   * Call transcript-specific checks
   */
  private checkCallSpecific(transcript: string, patterns: ScamPattern[], riskFactors: string[]): void {
    // Check for authority impersonation
    const authorities = ['rbi', 'bank', 'police', 'government', 'income tax', 'customs'];
    authorities.forEach(authority => {
      if (transcript.includes(authority)) {
        riskFactors.push(`Claims to be from: ${authority}`);
      }
    });

    // Check for information requests
    const infoRequests = ['otp', 'pin', 'password', 'cvv', 'expiry', 'card number'];
    infoRequests.forEach(request => {
      if (transcript.includes(request)) {
        riskFactors.push(`Requests sensitive info: ${request}`);
      }
    });
  }

  /**
   * APK-specific checks
   */
  private checkAPKSpecific(appContent: string, patterns: ScamPattern[], riskFactors: string[]): void {
    // Check for loan app indicators
    const loanKeywords = ['instant', 'quick', 'easy', 'no document', 'approved'];
    loanKeywords.forEach(keyword => {
      if (appContent.includes(keyword) && appContent.includes('loan')) {
        riskFactors.push(`Loan fraud indicator: ${keyword}`);
      }
    });

    // Check for gaming/rummy indicators
    const gamingKeywords = ['win', 'cash', 'earn', 'daily', 'guaranteed'];
    gamingKeywords.forEach(keyword => {
      if (appContent.includes(keyword) && (appContent.includes('rummy') || appContent.includes('game'))) {
        riskFactors.push(`Gaming fraud indicator: ${keyword}`);
      }
    });
  }

  /**
   * QR code-specific checks
   */
  private checkQRSpecific(qrContent: string, patterns: ScamPattern[], riskFactors: string[]): void {
    // Check if QR contains UPI payment
    if (qrContent.includes('upi://pay')) {
      riskFactors.push('Contains UPI payment request');
      
      // Check for suspicious UPI patterns
      if (qrContent.includes('am=') && !qrContent.includes('pn=')) {
        riskFactors.push('UPI payment without merchant name');
      }
    }

    // Check if QR contains app download link
    if (qrContent.includes('.apk') || qrContent.includes('download')) {
      riskFactors.push('Contains app download link');
    }
  }

  /**
   * Calculates confidence score based on detected patterns
   */
  private calculateConfidence(patterns: ScamPattern[], totalWeight: number, contentType: string): number {
    if (patterns.length === 0) {
      return Math.floor(Math.random() * 10) + 5; // 5-15% for clean content
    }

    // Base confidence on pattern weights
    let confidence = Math.min(totalWeight * 2, 95); // Cap at 95%

    // Adjust based on content type
    switch (contentType) {
      case 'apk':
        confidence += 5; // APKs are inherently riskier
        break;
      case 'call':
        confidence += 3; // Voice calls can be more deceptive
        break;
    }

    // Add some randomness for realism
    confidence += Math.floor(Math.random() * 10) - 5;

    return Math.max(5, Math.min(95, Math.floor(confidence)));
  }

  /**
   * Determines verdict based on confidence score
   */
  private determineVerdict(confidence: number, patterns: ScamPattern[]): 'safe' | 'suspicious' | 'dangerous' {
    if (confidence >= 70) return 'dangerous';
    if (confidence >= 40) return 'suspicious';
    return 'safe';
  }

  /**
   * Gets patterns by category
   */
  getPatternsByCategory(category: string): ScamPattern[] {
    return this.patterns.filter(pattern => pattern.category === category);
  }

  /**
   * Adds a new pattern to the detector
   */
  addPattern(pattern: Omit<ScamPattern, 'id'>): void {
    const newPattern: ScamPattern = {
      ...pattern,
      id: Date.now().toString()
    };
    this.patterns.push(newPattern);
  }
}

// Export singleton instance
export const scamDetector = new ScamDetector();
