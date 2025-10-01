import { ScamPattern } from '@shared/schema';

export function detectScamPatterns(content: string, patterns: ScamPattern[]): string[] {
  const riskFactors: string[] = [];
  const lowerContent = content.toLowerCase();

  // Common scam keywords
  const scamKeywords = [
    'lottery', 'winner', 'prize', 'urgent', 'loan', 'instant approval',
    'without documents', 'click link', 'claim', 'kbc', 'offer'
  ];

  // Check for scam keywords
  scamKeywords.forEach(keyword => {
    if (lowerContent.includes(keyword)) {
      riskFactors.push(`Suspicious keyword detected: ${keyword}`);
    }
  });

  // Check for URL shorteners
  const urlShorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co'];
  urlShorteners.forEach(shortener => {
    if (lowerContent.includes(shortener)) {
      riskFactors.push(`URL shortener detected: ${shortener}`);
    }
  });

  // Check for excessive punctuation
  if ((content.match(/[!?]/g) || []).length > 3) {
    riskFactors.push('Excessive punctuation');
  }

  // Check for money amounts
  if (lowerContent.match(/(\₹|rs\.?|rupees?)\s*\d+/)) {
    riskFactors.push('Money amount mentioned');
  }

  // Apply provided patterns
  patterns.forEach(pattern => {
    if (pattern.pattern && new RegExp(pattern.pattern, 'i').test(content)) {
      riskFactors.push(pattern.description ?? 'Pattern matched');
    }
  });

  return riskFactors;
}

export function calculateRiskScore(riskFactors: string[]): number {
  if (riskFactors.length === 0) {
    return 10; // Base risk for any message
  }
  
  let score = 0;
  
  riskFactors.forEach(factor => {
    if (factor.includes('Suspicious keyword')) score += 15;
    if (factor.includes('URL shortener')) score += 20;
    if (factor === 'Excessive punctuation') score += 10;
    if (factor === 'Money amount mentioned') score += 15;
    if (factor.includes('Request for personal information')) score += 30;
    if (factor.includes('Impersonation of authority')) score += 35;
    // Add more specific scores for other risk factors
  });

  // Normalize score to 0-100 range
  return Math.min(Math.max(score, 0), 100);
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
