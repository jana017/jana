import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import Manifesto from "@/components/Manifesto";
import EditorialMarquee from "@/components/EditorialMarquee";
import LiveThreatLandscape from "@/components/LiveThreatLandscape";
import ThreatDashboard from "@/components/ThreatDashboard";
import Gallery from "@/components/Gallery";
import Services from "@/components/Services";
import Careers from "@/components/Careers";
import Contact from "@/components/Contact";

export default function Landing() {
  return (
    <div data-testid="landing-page">
      <Navbar />
      <Hero />
      <Manifesto />
      <EditorialMarquee />
      <LiveThreatLandscape />
      <ThreatDashboard />
      <Services />
      <Gallery />
      <Careers />
      <Contact />
    </div>
  );
}
