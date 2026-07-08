import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import About from "@/components/Manifesto";
import StatsBand from "@/components/EditorialMarquee";
import LiveThreatLandscape from "@/components/LiveThreatLandscape";
import AttackFeed from "@/components/AttackFeed";
import ThreatDashboard from "@/components/ThreatDashboard";
import Services from "@/components/Services";
import Gallery from "@/components/Gallery";
import Careers from "@/components/Careers";
import Contact from "@/components/Contact";

export default function Landing() {
  return (
    <div data-testid="landing-page" className="bg-white">
      <Navbar />
      <Hero />
      <About />
      <StatsBand />
      <LiveThreatLandscape />
      <AttackFeed />
      <ThreatDashboard />
      <Services />
      <Gallery />
      <Careers />
      <Contact />
    </div>
  );
}
