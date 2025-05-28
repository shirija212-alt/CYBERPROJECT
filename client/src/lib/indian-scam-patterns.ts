import { ScamPattern } from "./scam-detector";

export const INDIAN_SCAM_PATTERNS: ScamPattern[] = [
  // Loan Fraud Patterns
  {
    id: "loan_001",
    category: "loan",
    pattern: "instant loan",
    weight: 45,
    description: "Instant loan promises"
  },
  {
    id: "loan_002", 
    category: "loan",
    pattern: "loan approval",
    weight: 40,
    description: "Guaranteed loan approval"
  },
  {
    id: "loan_003",
    category: "loan",
    pattern: "without documents",
    weight: 50,
    description: "No document loans"
  },
  {
    id: "loan_004",
    category: "loan",
    pattern: "immediate fund",
    weight: 35,
    description: "Immediate fund transfer"
  },
  {
    id: "loan_005",
    category: "loan",
    pattern: "pre approved",
    weight: 40,
    description: "Pre-approved loan claims"
  },
  {
    id: "loan_006",
    category: "loan",
    pattern: "easy loan",
    weight: 35,
    description: "Easy loan promises"
  },
  {
    id: "loan_007",
    category: "loan",
    pattern: "quick cash",
    weight: 40,
    description: "Quick cash offers"
  },

  // Rummy/Gaming Fraud Patterns
  {
    id: "rummy_001",
    category: "rummy",
    pattern: "earn money playing",
    weight: 45,
    description: "Earn money playing games"
  },
  {
    id: "rummy_002",
    category: "rummy",
    pattern: "guaranteed win",
    weight: 50,
    description: "Guaranteed winning"
  },
  {
    id: "rummy_003",
    category: "rummy",
    pattern: "daily earning",
    weight: 40,
    description: "Daily earning promises"
  },
  {
    id: "rummy_004",
    category: "rummy",
    pattern: "cash game",
    weight: 30,
    description: "Cash game references"
  },
  {
    id: "rummy_005",
    category: "rummy",
    pattern: "win cash",
    weight: 35,
    description: "Win cash promises"
  },
  {
    id: "rummy_006",
    category: "rummy",
    pattern: "easy money",
    weight: 40,
    description: "Easy money claims"
  },
  {
    id: "rummy_007",
    category: "rummy",
    pattern: "rummy cash",
    weight: 45,
    description: "Rummy cash games"
  },

  // Phishing Patterns
  {
    id: "phish_001",
    category: "phishing",
    pattern: "verify account",
    weight: 35,
    description: "Account verification scam"
  },
  {
    id: "phish_002",
    category: "phishing",
    pattern: "suspended account",
    weight: 40,
    description: "Account suspension threat"
  },
  {
    id: "phish_003",
    category: "phishing",
    pattern: "click here now",
    weight: 30,
    description: "Urgent action required"
  },
  {
    id: "phish_004",
    category: "phishing",
    pattern: "update kyc",
    weight: 35,
    description: "KYC update scam"
  },
  {
    id: "phish_005",
    category: "phishing",
    pattern: "confirm identity",
    weight: 35,
    description: "Identity confirmation scam"
  },
  {
    id: "phish_006",
    category: "phishing",
    pattern: "security alert",
    weight: 30,
    description: "Fake security alerts"
  },

  // UPI Fraud Patterns
  {
    id: "upi_001",
    category: "upi",
    pattern: "upi pin",
    weight: 50,
    description: "UPI PIN request"
  },
  {
    id: "upi_002",
    category: "upi",
    pattern: "payment failed",
    weight: 30,
    description: "Fake payment failure"
  },
  {
    id: "upi_003",
    category: "upi",
    pattern: "refund process",
    weight: 35,
    description: "Fake refund process"
  },
  {
    id: "upi_004",
    category: "upi",
    pattern: "upi blocked",
    weight: 40,
    description: "UPI blocking threats"
  },
  {
    id: "upi_005",
    category: "upi",
    pattern: "verify upi",
    weight: 35,
    description: "UPI verification scam"
  },

  // Lottery Scams
  {
    id: "lottery_001",
    category: "lottery",
    pattern: "kbc winner",
    weight: 50,
    description: "KBC lottery scam"
  },
  {
    id: "lottery_002",
    category: "lottery",
    pattern: "congratulations won",
    weight: 45,
    description: "Congratulatory lottery scam"
  },
  {
    id: "lottery_003",
    category: "lottery",
    pattern: "prize money",
    weight: 40,
    description: "Prize money scam"
  },
  {
    id: "lottery_004",
    category: "lottery",
    pattern: "lucky draw",
    weight: 35,
    description: "Lucky draw scam"
  },
  {
    id: "lottery_005",
    category: "lottery",
    pattern: "lottery ticket",
    weight: 35,
    description: "Lottery ticket scam"
  },

  // Authority Impersonation
  {
    id: "auth_001",
    category: "authority",
    pattern: "calling from rbi",
    weight: 50,
    description: "RBI impersonation"
  },
  {
    id: "auth_002",
    category: "authority",
    pattern: "bank security",
    weight: 40,
    description: "Bank security impersonation"
  },
  {
    id: "auth_003",
    category: "authority",
    pattern: "income tax department",
    weight: 45,
    description: "Income tax impersonation"
  },
  {
    id: "auth_004",
    category: "authority",
    pattern: "police department",
    weight: 45,
    description: "Police impersonation"
  },
  {
    id: "auth_005",
    category: "authority",
    pattern: "government official",
    weight: 40,
    description: "Government impersonation"
  },

  // Investment Scams
  {
    id: "invest_001",
    category: "investment",
    pattern: "double your money",
    weight: 50,
    description: "Money doubling scam"
  },
  {
    id: "invest_002",
    category: "investment",
    pattern: "guaranteed returns",
    weight: 45,
    description: "Guaranteed return scam"
  },
  {
    id: "invest_003",
    category: "investment",
    pattern: "risk free investment",
    weight: 45,
    description: "Risk-free investment scam"
  },
  {
    id: "invest_004",
    category: "investment",
    pattern: "high profit",
    weight: 35,
    description: "High profit claims"
  },

  // Crypto Scams
  {
    id: "crypto_001",
    category: "crypto",
    pattern: "bitcoin investment",
    weight: 35,
    description: "Bitcoin investment scam"
  },
  {
    id: "crypto_002",
    category: "crypto",
    pattern: "crypto trading",
    weight: 30,
    description: "Crypto trading scam"
  },
  {
    id: "crypto_003",
    category: "crypto",
    pattern: "mining opportunity",
    weight: 40,
    description: "Crypto mining scam"
  },

  // General Scam Indicators
  {
    id: "general_001",
    category: "general",
    pattern: "act now",
    weight: 25,
    description: "Urgency pressure tactic"
  },
  {
    id: "general_002",
    category: "general",
    pattern: "limited time offer",
    weight: 25,
    description: "Limited time pressure"
  },
  {
    id: "general_003",
    category: "general",
    pattern: "share this message",
    weight: 20,
    description: "Viral spreading tactic"
  },
  {
    id: "general_004",
    category: "general",
    pattern: "dont tell anyone",
    weight: 35,
    description: "Secrecy instruction"
  },
  {
    id: "general_005",
    category: "general",
    pattern: "processing fee",
    weight: 40,
    description: "Upfront fee request"
  }
];
