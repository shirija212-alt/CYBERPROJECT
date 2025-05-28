import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { 
  GraduationCap, 
  Smartphone, 
  Gamepad2, 
  Mail, 
  CreditCard, 
  Shield, 
  AlertTriangle,
  Phone,
  MessageSquare,
  Link as LinkIcon
} from "lucide-react";

export default function Learn() {
  const scamCategories = [
    {
      icon: Smartphone,
      title: "Loan App Scams",
      description: "Fraudulent apps promising instant loans ask for personal documents and access to contacts, then harass users and families for money.",
      color: "red",
      tips: [
        "Never share OTP or bank details",
        "Check RBI registered lender list",
        "Avoid apps asking for contact access",
        "Verify company registration"
      ]
    },
    {
      icon: Gamepad2,
      title: "Gaming & Rummy Frauds",
      description: "Apps promise easy money through games but manipulate results and refuse withdrawals after users deposit money.",
      color: "orange",
      tips: [
        "Avoid 'guaranteed win' claims",
        "Research app reviews thoroughly",
        "Never deposit large amounts",
        "Check withdrawal policies"
      ]
    },
    {
      icon: Mail,
      title: "Phishing SMS & Emails",
      description: "Fake messages from banks and government agencies trying to steal personal information and login credentials.",
      color: "yellow",
      tips: [
        "Never share UPI PIN with anyone",
        "Verify QR codes before scanning",
        "Check sender authenticity",
        "Don't click suspicious links"
      ]
    },
    {
      icon: CreditCard,
      title: "UPI & Payment Frauds",
      description: "Scammers trick users into sharing UPI PINs or scanning malicious QR codes that lead to unauthorized transactions.",
      color: "blue",
      tips: [
        "Never share UPI PIN",
        "Verify payment details carefully",
        "Use only official apps",
        "Report suspicious transactions"
      ]
    }
  ];

  const commonPatterns = [
    {
      type: "Suspicious Messages",
      icon: MessageSquare,
      examples: [
        '"Congratulations! You\'ve won ₹25 lakh in KBC lottery"',
        '"Instant loan approval without documents"',
        '"Your UPI account will be blocked, verify immediately"',
        '"Earn ₹5000 daily by playing rummy"'
      ]
    },
    {
      type: "Dangerous URLs",
      icon: LinkIcon,
      examples: [
        'loanapproval-instant.com',
        'kbc-lottery-winner.xyz',
        'upi-verify-account.net',
        'rummy-cash-easy.app'
      ]
    },
    {
      type: "Scam Calls",
      icon: Phone,
      examples: [
        '"I\'m calling from RBI, share your OTP"',
        '"Your account is compromised, give us your PIN"',
        '"Instant loan available, just share Aadhaar"',
        '"You\'ve won a prize, pay processing fee"'
      ]
    }
  ];

  const getColorClasses = (color: string) => {
    const colorMap = {
      red: {
        bg: "bg-red-50 border-red-200",
        icon: "bg-red-100 text-red-600",
        accent: "text-red-700"
      },
      orange: {
        bg: "bg-orange-50 border-orange-200", 
        icon: "bg-orange-100 text-orange-600",
        accent: "text-orange-700"
      },
      yellow: {
        bg: "bg-yellow-50 border-yellow-200",
        icon: "bg-yellow-100 text-yellow-600", 
        accent: "text-yellow-700"
      },
      blue: {
        bg: "bg-blue-50 border-blue-200",
        icon: "bg-blue-100 text-blue-600",
        accent: "text-blue-700"
      }
    };
    return colorMap[color as keyof typeof colorMap] || colorMap.blue;
  };

  return (
    <div className="min-h-screen py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <GraduationCap className="text-blue-600 mr-3" size={32} />
            <h1 className="text-3xl lg:text-4xl font-bold text-slate-800">Stay Educated, Stay Protected</h1>
          </div>
          <p className="text-xl text-slate-600 max-w-3xl mx-auto">
            Learn about the latest scam tactics and how to protect yourself and your family from online fraud
          </p>
        </div>

        {/* Scam Categories */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-slate-800 mb-8">Common Scam Types in India</h2>
          <div className="grid md:grid-cols-2 gap-8">
            {scamCategories.map((category, index) => {
              const colors = getColorClasses(category.color);
              const IconComponent = category.icon;
              
              return (
                <Card key={index} className={`${colors.bg} border hover:shadow-lg transition-all`}>
                  <CardContent className="p-6">
                    <div className={`${colors.icon} p-3 rounded-lg w-fit mb-4`}>
                      <IconComponent size={24} />
                    </div>
                    <h3 className={`text-lg font-bold mb-3 ${colors.accent}`}>{category.title}</h3>
                    <p className="text-slate-600 text-sm mb-4">{category.description}</p>
                    
                    <h4 className="font-semibold text-slate-800 mb-2 flex items-center">
                      <Shield className={`${colors.accent} mr-2`} size={16} />
                      Protection Tips
                    </h4>
                    <ul className="space-y-1">
                      {category.tips.map((tip, tipIndex) => (
                        <li key={tipIndex} className="flex items-start space-x-2 text-sm">
                          <span className={`${colors.accent} mt-1`}>✓</span>
                          <span className="text-slate-700">{tip}</span>
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </section>

        {/* Common Warning Signs */}
        <section className="mb-16">
          <div className="bg-gradient-to-r from-red-50 to-orange-50 rounded-2xl p-8">
            <h2 className="text-2xl font-bold text-slate-800 mb-6 text-center flex items-center justify-center">
              <AlertTriangle className="text-red-600 mr-3" size={28} />
              Common Scam Warning Signs
            </h2>
            
            <div className="grid md:grid-cols-3 gap-8">
              {commonPatterns.map((pattern, index) => {
                const IconComponent = pattern.icon;
                return (
                  <div key={index}>
                    <h3 className="font-semibold text-slate-800 mb-4 flex items-center">
                      <IconComponent className="text-red-600 mr-2" size={20} />
                      {pattern.type}
                    </h3>
                    <ul className="space-y-2">
                      {pattern.examples.map((example, exampleIndex) => (
                        <li key={exampleIndex} className="text-sm">
                          <div className="bg-white/50 p-3 rounded-lg border border-red-200">
                            <span className="text-red-700 font-mono">{example}</span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        {/* Quick Reference */}
        <section className="mb-16">
          <div className="grid md:grid-cols-2 gap-8">
            <Card className="bg-green-50 border-green-200">
              <CardContent className="p-6">
                <h3 className="text-xl font-bold text-green-800 mb-4 flex items-center">
                  <Shield className="mr-2" size={24} />
                  What to DO
                </h3>
                <ul className="space-y-3 text-green-700">
                  <li className="flex items-start space-x-2">
                    <span className="text-green-600 mt-1">✓</span>
                    <span>Verify caller identity independently</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-green-600 mt-1">✓</span>
                    <span>Check official websites directly</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-green-600 mt-1">✓</span>
                    <span>Use INSAFE to scan suspicious content</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-green-600 mt-1">✓</span>
                    <span>Report scams to authorities</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-green-600 mt-1">✓</span>
                    <span>Educate family and friends</span>
                  </li>
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-red-50 border-red-200">
              <CardContent className="p-6">
                <h3 className="text-xl font-bold text-red-800 mb-4 flex items-center">
                  <AlertTriangle className="mr-2" size={24} />
                  What NOT to DO
                </h3>
                <ul className="space-y-3 text-red-700">
                  <li className="flex items-start space-x-2">
                    <span className="text-red-600 mt-1">✗</span>
                    <span>Never share OTP, PIN, or passwords</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-red-600 mt-1">✗</span>
                    <span>Don't click suspicious links immediately</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-red-600 mt-1">✗</span>
                    <span>Avoid downloading unknown APK files</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-red-600 mt-1">✗</span>
                    <span>Don't provide personal info over calls</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="text-red-600 mt-1">✗</span>
                    <span>Never pay upfront fees for loans</span>
                  </li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </section>

        {/* Emergency Contacts */}
        <section className="mb-16">
          <Card className="bg-blue-50 border-blue-200">
            <CardContent className="p-6">
              <h3 className="text-xl font-bold text-blue-800 mb-4 text-center">
                🚨 Emergency Contact Numbers
              </h3>
              <div className="grid md:grid-cols-3 gap-6 text-center">
                <div>
                  <h4 className="font-semibold text-blue-800">Cyber Crime Helpline</h4>
                  <p className="text-2xl font-bold text-blue-600">1930</p>
                </div>
                <div>
                  <h4 className="font-semibold text-blue-800">National Emergency</h4>
                  <p className="text-2xl font-bold text-blue-600">112</p>
                </div>
                <div>
                  <h4 className="font-semibold text-blue-800">Banking Fraud</h4>
                  <p className="text-2xl font-bold text-blue-600">14416</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* CTA Section */}
        <div className="text-center">
          <h2 className="text-2xl font-bold text-slate-800 mb-4">Ready to Protect Yourself?</h2>
          <p className="text-slate-600 mb-6">Use our scanning tools to check suspicious content right now</p>
          <div className="space-x-4">
            <Link href="/scan">
              <Button size="lg" className="bg-blue-600 hover:bg-blue-700">
                Start Scanning Now
              </Button>
            </Link>
            <Link href="/report">
              <Button size="lg" variant="outline">
                Report a Scam
              </Button>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
