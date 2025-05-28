import { ScamPattern } from "@shared/schema";

export function detectScamPatterns(content: string, patterns: ScamPattern[]): string[] {
  const detectedPatterns: string[] = [];
  const normalizedContent = content.toLowerCase().trim();
  
  patterns.forEach(pattern => {
    if (normalizedContent.includes(pattern.pattern.toLowerCase())) {
      detectedPatterns.push(pattern.description || pattern.pattern);
    }
  });
  
  return detectedPatterns;
}

export function calculateRiskScore(riskFactors: string[]): number {
  if (riskFactors.length === 0) {
    return Math.floor(Math.random() * 10) + 5; // 5-15% for clean content
  }
  
  // Base score on number of risk factors
  let score = 0;
  
  if (riskFactors.length === 1) {
    score = 35 + Math.floor(Math.random() * 20); // 35-55%
  } else if (riskFactors.length === 2) {
    score = 55 + Math.floor(Math.random() * 25); // 55-80%
  } else if (riskFactors.length >= 3) {
    score = 80 + Math.floor(Math.random() * 15); // 80-95%
  }
  
  // Add contextual adjustments
  const content = riskFactors.join(' ').toLowerCase();
  
  // High-risk patterns get higher scores
  if (content.includes('instant loan') || content.includes('guaranteed win')) {
    score += 10;
  }
  
  // Authority impersonation is very risky
  if (content.includes('rbi') || content.includes('bank security')) {
    score += 15;
  }
  
  // UPI/payment related scams are dangerous
  if (content.includes('upi pin') || content.includes('otp')) {
    score += 12;
  }
  
  // Ensure score is within bounds
  return Math.max(5, Math.min(95, score));
}

export function analyzeURL(url: string): { riskFactors: string[]; confidence: number } {
  const riskFactors: string[] = [];
  const normalizedURL = url.toLowerCase();
  
  // Check for suspicious domains
  const suspiciousDomains = ['.tk', '.ml', '.ga', '.cf', 'bit.ly', 'tinyurl.com'];
  suspiciousDomains.forEach(domain => {
    if (normalizedURL.includes(domain)) {
      riskFactors.push(`Suspicious domain: ${domain}`);
    }
  });
  
  // Check for IP addresses
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(normalizedURL)) {
    riskFactors.push('Uses IP address instead of domain');
  }
  
  // Check for excessive subdomains
  const subdomainCount = (url.match(/\./g) || []).length;
  if (subdomainCount > 3) {
    riskFactors.push('Excessive subdomains detected');
  }
  
  // Check for HTTPS
  if (!normalizedURL.startsWith('https://')) {
    riskFactors.push('No secure HTTPS connection');
  }
  
  const confidence = calculateRiskScore(riskFactors);
  return { riskFactors, confidence };
}

export function analyzeSMS(text: string): { riskFactors: string[]; confidence: number } {
  const riskFactors: string[] = [];
  const normalizedText = text.toLowerCase();
  
  // Check for urgency words
  const urgencyWords = ['urgent', 'immediate', 'expire', 'block', 'suspend', 'limited time'];
  urgencyWords.forEach(word => {
    if (normalizedText.includes(word)) {
      riskFactors.push(`Urgency tactic: "${word}"`);
    }
  });
  
  // Check for monetary amounts
  if (/₹[\d,]+|rs\.?\s*\d+|\d+\s*lakh|\d+\s*crore/i.test(text)) {
    riskFactors.push('Contains monetary amounts');
  }
  
  // Check for shortened URLs
  if (normalizedText.includes('bit.ly') || normalizedText.includes('tinyurl')) {
    riskFactors.push('Contains shortened URLs');
  }
  
  // Check for common scam phrases
  const scamPhrases = ['click here', 'verify now', 'claim prize', 'congratulations'];
  scamPhrases.forEach(phrase => {
    if (normalizedText.includes(phrase)) {
      riskFactors.push(`Scam phrase: "${phrase}"`);
    }
  });
  
  const confidence = calculateRiskScore(riskFactors);
  return { riskFactors, confidence };
}

export function analyzeCall(transcript: string): { riskFactors: string[]; confidence: number } {
  const riskFactors: string[] = [];
  const normalizedTranscript = transcript.toLowerCase();
  
  // Check for authority impersonation
  const authorities = ['rbi', 'bank', 'police', 'income tax', 'customs'];
  authorities.forEach(authority => {
    if (normalizedTranscript.includes(authority)) {
      riskFactors.push(`Claims to be from: ${authority}`);
    }
  });
  
  // Check for information requests
  const infoRequests = ['otp', 'pin', 'password', 'cvv', 'card number'];
  infoRequests.forEach(request => {
    if (normalizedTranscript.includes(request)) {
      riskFactors.push(`Requests sensitive info: ${request}`);
    }
  });
  
  // Check for threats
  const threats = ['block account', 'legal action', 'arrest', 'fine'];
  threats.forEach(threat => {
    if (normalizedTranscript.includes(threat)) {
      riskFactors.push(`Makes threats: ${threat}`);
    }
  });
  
  const confidence = calculateRiskScore(riskFactors);
  return { riskFactors, confidence };
}

export function analyzeAPK(appName: string, extractedStrings: string): { riskFactors: string[]; confidence: number } {
  const riskFactors: string[] = [];
  const combinedText = `${appName} ${extractedStrings}`.toLowerCase();
  
  // Check for loan app indicators
  const loanKeywords = ['instant', 'quick', 'easy', 'approved'];
  loanKeywords.forEach(keyword => {
    if (combinedText.includes(keyword) && combinedText.includes('loan')) {
      riskFactors.push(`Loan fraud indicator: ${keyword}`);
    }
  });
  
  // Check for gaming/rummy indicators
  const gamingKeywords = ['win', 'cash', 'earn', 'daily'];
  gamingKeywords.forEach(keyword => {
    if (combinedText.includes(keyword) && (combinedText.includes('rummy') || combinedText.includes('game'))) {
      riskFactors.push(`Gaming fraud indicator: ${keyword}`);
    }
  });
  
  // Check for excessive permissions (would need actual APK analysis)
  if (extractedStrings.includes('contact') && extractedStrings.includes('sms')) {
    riskFactors.push('Requests excessive permissions');
  }
  
  const confidence = calculateRiskScore(riskFactors);
  return { riskFactors, confidence };
}
