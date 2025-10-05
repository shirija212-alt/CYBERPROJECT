
import { ScamPattern, scamPatterns } from "@shared/schema";

// Comprehensive risk factor weighting
const riskFactorWeights: { [key: string]: number } = {
  // URL risk factors
  "Suspicious domain": 30,
  "Uses IP address instead of domain": 40,
  "Excessive subdomains detected": 20,
  "No secure HTTPS connection": 15,
  "URL shortener detected": 25,

  // SMS/Text risk factors
  "Urgency tactic": 20,
  "Contains monetary amounts": 15,
  "Scam phrase": 25,
  "Contains shortened URLs": 20,
  "Asks for personal information": 35,

  // Call transcript risk factors
  "Claims to be from authority": 30,
  "Requests sensitive info": 40,
  "Makes threats": 35,
  "Impersonation of authority": 35,

  // APK risk factors
  "Loan fraud indicator": 30,
  "Gaming fraud indicator": 25,
  "Requests excessive permissions": 35,

  // General risk factors
  "Suspicious keyword detected": 10,
  "Money amount mentioned": 15,
  "Excessive punctuation": 5,
  "Request for personal information": 30,
};

export function calculateRiskScore(riskFactors: string[]): number {
  let score = 0;
  const uniqueFactors = [...new Set(riskFactors)]; // Avoid double counting

  uniqueFactors.forEach((factor) => {
    for (const key in riskFactorWeights) {
      if (factor.startsWith(key)) {
        score += riskFactorWeights[key];
        break;
      }
    }
  });

  return Math.min(score, 100);
}

export function analyzeURL(url: string): { riskFactors: string[]; confidence: number } {
  const riskFactors: string[] = [];
  const normalizedURL = url.toLowerCase();

  const suspiciousDomains = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".biz", ".club", ".info",
    ".top", ".win", ".bid", ".loan", ".faith", ".date", ".review",
  ];
  suspiciousDomains.forEach((domain) => {
    if (normalizedURL.includes(domain)) {
      riskFactors.push(`Suspicious domain: ${domain}`);
    }
  });

  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(normalizedURL)) {
    riskFactors.push("Uses IP address instead of domain");
  }

  const subdomainCount = (url.match(/\./g) || []).length;
  if (subdomainCount > 4) {
    riskFactors.push("Excessive subdomains detected");
  }

  if (!normalizedURL.startsWith("https://")) {
    riskFactors.push("No secure HTTPS connection");
  }

  const urlShorteners = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "soo.gd", "short.io"];
  urlShorteners.forEach((shortener) => {
    if (normalizedURL.includes(shortener)) {
      riskFactors.push(`URL shortener detected: ${shortener}`);
    }
  });


  const confidence = calculateRiskScore(riskFactors);
  return { riskFactors, confidence };
}

export function analyzeSMS(text: string): { riskFactors: string[]; confidence: number } {
  const riskFactors: string[] = [];
  const normalizedText = text.toLowerCase();

  const urgencyWords = [
    "urgent", "immediate", "expire", "block", "suspend", "limited time",
    "action required", "verify your account", "do not ignore", "alert", "warning", "final notice"
  ];
  urgencyWords.forEach((word) => {
    if (normalizedText.includes(word)) {
      riskFactors.push(`Urgency tactic: "${word}"`);
    }
  });

  if (/₹[\d,]+|rs\.?\s*\d+|\d+\s*lakh|\d+\s*crore/i.test(text)) {
    riskFactors.push("Contains monetary amounts");
  }

    const scamPhrases = [
    "click here", "verify now", "claim prize", "congratulations", "you have won",
    "kbc lottery", "free gift", "instant loan", "kyc update", "credit card approved",
    "dear customer", "your account has been credited", "winner", "lucky draw", "scratch and win"
  ];
  scamPhrases.forEach((phrase) => {
    if (normalizedText.includes(phrase)) {
      riskFactors.push(`Scam phrase: "${phrase}"`);
    }
  });

  if (/(otp|pin|password|cvv|aadhar|pan card)/.test(normalizedText)) {
      riskFactors.push("Asks for personal information")
  }

  const urlShorteners = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "soo.gd", "short.io"];
  urlShorteners.forEach((shortener) => {
    if (normalizedText.includes(shortener)) {
      riskFactors.push(`Contains shortened URLs: ${shortener}`);
    }
  });

  const confidence = calculateRiskScore(riskFactors);
  return { riskFactors, confidence };
}

export function analyzeCall(transcript: string): { riskFactors: string[]; confidence: number } {
  const riskFactors: string[] = [];
  const normalizedTranscript = transcript.toLowerCase();

  const authorities = [
    "rbi", "reserve bank of india", "bank official", "police", "income tax department",
    "customs office", "fraud detection department", "enforcement directorate", "cyber security"
  ];
  authorities.forEach((authority) => {
    if (normalizedTranscript.includes(authority)) {
      riskFactors.push(`Claims to be from authority: ${authority}`);
    }
  });

  const infoRequests = [
    "otp", "one time password", "pin", "password", "cvv", "card number",
    "expiry date", "aadhar number", "pan number", "bank account details",
    "mother's maiden name", "date of birth"
  ];
  infoRequests.forEach((request) => {
    if (normalizedTranscript.includes(request)) {
      riskFactors.push(`Requests sensitive info: ${request}`);
    }
  });

  const threats = [
    "block your account", "legal action", "arrest warrant", "fine of",
    "suspend your service", "your money will be lost", "your sim will be blocked"
  ];
  threats.forEach((threat) => {
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

    const loanKeywords = [
    "instant loan", "quick cash", "easy money", "personal loan",
    "loan without documents", "get approved in minutes", "unsecured loan", "no credit check"
  ];
  loanKeywords.forEach((keyword) => {
    if (combinedText.includes(keyword)) {
      riskFactors.push(`Loan fraud indicator: ${keyword}`);
    }
  });

  const gamingKeywords = [
    "win real cash", "earn daily", "play and earn", "rummy", "teen patti",
    "betting app", "fantasy cricket", "real money gaming"
  ];
  gamingKeywords.forEach((keyword) => {
    if (combinedText.includes(keyword)) {
      riskFactors.push(`Gaming fraud indicator: ${keyword}`);
    }
  });

  const permissionRequests = ["android.permission.READ_CONTACTS", "android.permission.READ_SMS", "android.permission.ACCESS_FINE_LOCATION", "android.permission.SEND_SMS"];
  permissionRequests.forEach(permission => {
      if(extractedStrings.includes(permission)) {
          riskFactors.push(`Requests excessive permissions: ${permission}`)
      }
  })

  const confidence = calculateRiskScore(riskFactors);
  return { riskFactors, confidence };
}

export function analyzePhoneNumber(
  phoneNumber: string
): { riskFactors: string[]; confidence: number } {
  const riskFactors: string[] = [];
  
  // Basic validation for Indian numbers
  if (!/^(\+91)?[6789]\d{9}$/.test(phoneNumber)) {
    riskFactors.push("Invalid Indian phone number format");
  }

  // Check for suspicious prefixes (e.g., international, premium rate)
  if (phoneNumber.startsWith("+") && !phoneNumber.startsWith("+91")) {
      riskFactors.push("International number, exercise caution");
  } else if (phoneNumber.startsWith("140") || phoneNumber.startsWith("0140")) {
    riskFactors.push("Telemarketing number detected");
  } else if (/^(\+91)?[1-5]/.test(phoneNumber)) {
    riskFactors.push("Suspicious starting digit for an Indian mobile number");
  }
  
  // Placeholder for real-time lookup (integration with Threat Intelligence)
  // In a real scenario, this would involve an API call to a service like Truecaller or a government database
  const knownScammers = ["+919876543210", "+911234567890"]; // Example list
  if (knownScammers.includes(phoneNumber)) {
      riskFactors.push("Number is on a known scammer list");
  }

  const confidence = calculateRiskScore(riskFactors);
  return { riskFactors, confidence };
}

// A more generic detection function that can be used for various content types.
export function detectScamPatterns(
  content: string,
  patterns: ScamPattern[]
): { riskFactors: string[], confidence: number } {
    const riskFactors: string[] = [];
    const lowerContent = content.toLowerCase();

    patterns.forEach(pattern => {
        if (pattern.pattern && new RegExp(pattern.pattern, "i").test(content)) {
            riskFactors.push(pattern.description ?? 'Generic pattern matched');
        }
    });

    const confidence = calculateRiskScore(riskFactors);
    return { riskFactors, confidence };
}
