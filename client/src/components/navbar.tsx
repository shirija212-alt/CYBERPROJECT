import { Link, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { Menu, Shield } from "lucide-react";

export default function Navbar() {
  const [location] = useLocation();

  const navItems = [
    { href: "/", label: "Home" },
    { href: "/scan", label: "Scan" },
    { href: "/learn", label: "Learn" },
    { href: "/report", label: "Report" },
    { href: "/analytics", label: "Analytics" },
  ];

  const NavLink = ({ href, label }: { href: string; label: string }) => (
    <Link href={href}>
      <span className={`font-medium transition-colors hover:text-blue-600 cursor-pointer ${
        location === href ? "text-blue-600 border-b-2 border-blue-600 pb-1" : "text-slate-600"
      }`}>
        {label}
      </span>
    </Link>
  );

  return (
    <nav className="bg-white shadow-lg sticky top-0 z-50 border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <Link href="/">
            <a className="flex items-center space-x-3">
              <div className="bg-gradient-to-r from-blue-600 to-blue-800 p-2 rounded-lg">
                <Shield className="text-white" size={24} />
              </div>
              <div>
                <h1 className="text-xl font-bold text-blue-600">INSAFE</h1>
                <p className="text-xs text-slate-600 hidden sm:block">Scam Protection</p>
              </div>
            </a>
          </Link>
          
          <div className="hidden md:flex items-center space-x-6">
            {navItems.map((item) => (
              <NavLink key={item.href} href={item.href} label={item.label} />
            ))}
            <Link href="/report">
              <Button className="bg-blue-600 hover:bg-blue-700">
                Emergency Report
              </Button>
            </Link>
          </div>
          
          <Sheet>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon" className="md:hidden">
                <Menu size={24} />
              </Button>
            </SheetTrigger>
            <SheetContent>
              <div className="flex flex-col space-y-4 mt-8">
                {navItems.map((item) => (
                  <NavLink key={item.href} href={item.href} label={item.label} />
                ))}
                <Link href="/report">
                  <Button className="w-full bg-blue-600 hover:bg-blue-700">
                    Emergency Report
                  </Button>
                </Link>
              </div>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </nav>
  );
}
