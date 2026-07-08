import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import { useEffect } from "react";
import About from "@/components/Manifesto";
import StatsBand from "@/components/EditorialMarquee";
import LiveThreatLandscape from "@/components/LiveThreatLandscape";
import AttackFeed from "@/components/AttackFeed";
import Services from "@/components/Services";
import Gallery from "@/components/Gallery";
import Careers from "@/components/Careers";
import Contact from "@/components/Contact";
import NivxBlogs from "@/components/NivxBlogs";
import useSeo from "@/lib/useSeo";

export default function Landing() {
  useSeo({
    title: "NivX Machines · Cybersecurity, AI & Threat Intelligence",
    description: "NivX Machines delivers enterprise cybersecurity, managed detection & response, threat intelligence and incident response — with a live global threat landscape and smart IOC analyzer.",
    canonical: "https://nivxmachines.com/",
  });
  useEffect(() => {
    const target = sessionStorage.getItem("scrollTo");
    if (target) {
      sessionStorage.removeItem("scrollTo");
      setTimeout(() => document.getElementById(target)?.scrollIntoView({ behavior: "smooth" }), 400);
    }
  }, []);

  return (
    <div data-testid="landing-page" className="bg-white">
      <Navbar />
      <Hero />
      <About />
      <StatsBand />
      <LiveThreatLandscape />
      <AttackFeed />
      <NivxBlogs />
      <Services />
      <Gallery />
      <Careers />
      <Contact />
    </div>
  );
}
