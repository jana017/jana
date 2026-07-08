import { motion } from "framer-motion";
import { Calendar, ArrowUpRight, Tag } from "lucide-react";

// 2026 threat/security articles curated for NivX readers. Each entry links
// back to the original public reference (attribution preserved).
const BLOG_POSTS = [
  {
    slug: "cyberdefenders-in-locked-shields-2026",
    title: "NivX participation in Locked Shields 2026",
    category: "News & Announcements",
    excerpt: "Bridging the gap between modern cloud security training and real-world cyber defense — a look at the NATO CyberDefense Center exercise sharpening the next generation of defenders.",
    date: "May 14, 2026",
    image: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/cyberdefenders-in-locked-shields-2026/",
  },
  {
    slug: "fileless-malware-soc-detection",
    title: "Fileless Malware Detection: How SOC Teams Hunt In-Memory Attacks",
    category: "SOC Playbook",
    excerpt: "Traditional malware detection assumes malware writes files to disk. What happens when attackers never touch the file system? A field guide to hunting in-memory threats.",
    date: "May 13, 2026",
    image: "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/fileless-malware-soc-detection/",
  },
  {
    slug: "encoded-powershell-detection-soc-playbook",
    title: "Encoded PowerShell Detection: How to Investigate Encoded PowerShell Commands",
    category: "SOC Playbook",
    excerpt: "PowerShell's -EncodedCommand flag accepts a Base64-encoded UTF-16LE string and executes it at runtime — attackers know it, defenders must decode it.",
    date: "May 12, 2026",
    image: "https://images.unsplash.com/photo-1629654297299-c8506221ca97?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/encoded-powershell-detection-soc-playbook/",
  },
  {
    slug: "azure-cloud-security",
    title: "Azure Cloud Security: The SOC Analyst's Complete Detection & Threat Hunting Guide (2026)",
    category: "Cloud Security",
    excerpt: "Azure Cloud Security is not just a product suite; it's an operational discipline. A comprehensive detection and threat hunting reference for SOC analysts.",
    date: "May 11, 2026",
    image: "https://images.unsplash.com/photo-1451187580459-43490279c0fa?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/azure-cloud-security/",
  },
  {
    slug: "alert-triage-process",
    title: "Alert Triage Process: The Complete SOC Analyst's Guide",
    category: "SOC Playbook",
    excerpt: "The alert triage process is the backbone of every effective SOC. On any given day, a team may receive thousands of alerts — here's how the best cut through the noise.",
    date: "May 10, 2026",
    image: "https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/alert-triage-process/",
  },
  {
    slug: "hacker-mindset-how-do-attackers-really-think",
    title: "Hacker Mindset: How Do Attackers Really Think?",
    category: "Threat Actor Insight",
    excerpt: "The hacker mindset is not a skillset — it's a way of thinking. If you work in a SOC, understanding it is the difference between chasing alerts and preventing attacks.",
    date: "May 6, 2026",
    image: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/hacker-mindset-how-do-attackers-really-think/",
  },
  {
    slug: "disk-forensics-for-soc-analysts",
    title: "Disk Forensics: The SOC Analyst Playbook",
    category: "Forensics",
    excerpt: "Disk forensics is no longer the exclusive domain of incident responders or law enforcement. Modern SOC analysts need it in their kit — here's the operational playbook.",
    date: "May 5, 2026",
    image: "https://images.unsplash.com/photo-1597852074816-d933c7d2b988?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/disk-forensics-for-soc-analysts/",
  },
  {
    slug: "cross-site-scripting-xss",
    title: "Cross-Site Scripting (XSS): How the Browser Security Model Works and Why It Breaks",
    category: "AppSec",
    excerpt: "XSS is a web application vulnerability that lets attackers inject malicious scripts into pages viewed by other users — a deep dive into the browser security model.",
    date: "May 4, 2026",
    image: "https://images.unsplash.com/photo-1516116216624-53e697fedbea?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/cross-site-scripting-xss/",
  },
  {
    slug: "soc-training-usb-device-alert-investigation",
    title: "SOC Simulator: USB Device Alert Investigation",
    category: "Case Study",
    excerpt: "A field guide for Tier 1 and Tier 2 SOC analysts covering removable media triage, evidence collection, insider risk signals, and malware detection.",
    date: "May 3, 2026",
    image: "https://images.unsplash.com/photo-1614064548237-096d0f6db4e7?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/soc-training-usb-device-alert-investigation/",
  },
  {
    slug: "cloud-compromise-case-study",
    title: "SOC Simulator: Cloud Account Compromise in Microsoft 365",
    category: "Case Study",
    excerpt: "A step-by-step case study for SOC analysts investigating a Microsoft 365 account compromise — from initial alert to root-cause and remediation.",
    date: "Apr 29, 2026",
    image: "https://images.unsplash.com/photo-1573164574572-cb89e39749b4?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/cloud-compromise-case-study/",
  },
  {
    slug: "practical-soc-case-study",
    title: "SOC Simulator: Malware Download Alert Investigation from Browser Telemetry",
    category: "Case Study",
    excerpt: "A practical SOC case study for detecting and responding to suspicious file downloads — with real browser telemetry patterns and detonation workflow.",
    date: "Apr 26, 2026",
    image: "https://images.unsplash.com/photo-1518432031352-d6fc5c10da5a?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/practical-soc-case-study/",
  },
  {
    slug: "email-compromise-investigation-training",
    title: "SOC Simulator: Detecting BEC Attacks — Email Forensics & Log Analysis",
    category: "Case Study",
    excerpt: "Business Email Compromise (BEC) remains one of the most pervasive and financially damaging threats. A hands-on investigation walk-through for finance teams.",
    date: "Apr 23, 2026",
    image: "https://images.unsplash.com/photo-1596526131083-e8c633c948d2?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/email-compromise-investigation-training/",
  },
  {
    slug: "what-is-a-data-breach-detection-and-response-full-guide",
    title: "What Is a Data Breach? Detection and Response Full Guide",
    category: "Fundamentals",
    excerpt: "A data breach is any security incident where unauthorized individuals gain access to sensitive data. Causes, signs, impact and the modern response playbook.",
    date: "Apr 14, 2026",
    image: "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/what-is-a-data-breach-detection-and-response-full-guide/",
  },
  {
    slug: "advanced-persistence-threats",
    title: "Advanced Persistent Threats: Full Guide for the SOC Team",
    category: "APT Deep Dive",
    excerpt: "APTs are not your average cyberattack — they don't smash and grab; they infiltrate, lurk, and operate on timelines measured in months. A lifecycle-based defender's guide.",
    date: "Apr 13, 2026",
    image: "https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/advanced-persistence-threats/",
  },
  {
    slug: "what-is-intrusion-detection-system-ids",
    title: "What is an Intrusion Detection System (IDS)? A Complete Explainer",
    category: "Fundamentals",
    excerpt: "An IDS monitors network traffic or host activity for signs of malicious behavior. Architecture, deployment modes, and how modern SOCs actually operationalize them.",
    date: "Apr 12, 2026",
    image: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1600&q=80",
    href: "https://cyberdefenders.org/blog/what-is-intrusion-detection-system-ids/",
  },
];

export default function NivxBlogs() {
  const featured = BLOG_POSTS[0];
  const rest = BLOG_POSTS.slice(1);

  return (
    <section id="blog" data-testid="nivx-blogs" className="py-20 lg:py-28 bg-white border-t border-slate-100">
      <div className="mx-auto max-w-7xl px-6">
        {/* Header */}
        <div className="max-w-3xl mb-12">
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-orange-500 mb-3">NivX Blogs</div>
          <h2 className="font-heading text-3xl md:text-4xl lg:text-5xl font-semibold tracking-tight text-slate-900">
            Threats & Attacks · articles from the field
          </h2>
          <p className="mt-5 text-base md:text-lg text-slate-600 leading-relaxed">
            Dive into the world of cybersecurity with NivX Blogs. Explore informative articles, insights, and expert perspectives on the latest trends, best practices, and cutting-edge technologies in the field. Stay updated, enhance your knowledge, and empower yourself to defend against cyber threats.
          </p>
        </div>

        {/* Featured post */}
        <motion.a
          href={featured.href}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="blog-featured"
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="group grid grid-cols-1 lg:grid-cols-[1.35fr_1fr] gap-0 rounded-2xl border border-slate-200 overflow-hidden hover:shadow-xl hover:border-slate-300 transition-all mb-14 bg-white"
        >
          <div className="relative aspect-[16/10] lg:aspect-auto overflow-hidden bg-slate-100">
            <img src={featured.image} alt={featured.title} loading="lazy" className="absolute inset-0 w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" />
            <div className="absolute inset-0 bg-gradient-to-t from-black/40 via-transparent to-transparent" />
            <div className="absolute top-4 left-4">
              <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider bg-white/95 text-slate-900 px-2.5 py-1 rounded shadow-sm">
                <Tag className="w-3 h-3" /> {featured.category}
              </span>
            </div>
          </div>
          <div className="p-8 lg:p-10 flex flex-col justify-center bg-white">
            <div className="text-xs font-semibold uppercase tracking-wider text-orange-500 mb-3">Featured</div>
            <h3 className="font-heading text-2xl md:text-3xl font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors leading-snug">
              {featured.title}
            </h3>
            <p className="mt-4 text-slate-600 leading-relaxed">{featured.excerpt}</p>
            <div className="mt-6 flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs text-slate-500">
                <Calendar className="w-3.5 h-3.5" /> {featured.date}
              </div>
              <span className="inline-flex items-center gap-1 text-sm font-semibold text-[#2E7DF5] group-hover:gap-2 transition-all">
                Read article <ArrowUpRight className="w-4 h-4" />
              </span>
            </div>
          </div>
        </motion.a>

        {/* Grid of posts */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" data-testid="blog-grid">
          {rest.map((p, i) => (
            <motion.a
              key={p.slug}
              href={p.href}
              target="_blank"
              rel="noopener noreferrer"
              data-testid={`blog-card-${i}`}
              initial={{ opacity: 0, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: (i % 3) * 0.05 }}
              className="group flex flex-col rounded-xl border border-slate-200 overflow-hidden bg-white hover:shadow-lg hover:-translate-y-1 hover:border-slate-300 transition-all"
            >
              <div className="relative aspect-[16/9] overflow-hidden bg-slate-100">
                <img src={p.image} alt={p.title} loading="lazy" className="absolute inset-0 w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" />
                <div className="absolute inset-0 bg-gradient-to-t from-black/30 via-transparent to-transparent" />
                <div className="absolute top-3 left-3">
                  <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider bg-white/95 text-slate-900 px-2 py-0.5 rounded shadow-sm">
                    {p.category}
                  </span>
                </div>
              </div>
              <div className="p-5 flex-1 flex flex-col">
                <h3 className="font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors leading-snug line-clamp-3">
                  {p.title}
                </h3>
                <p className="mt-2 text-sm text-slate-600 leading-relaxed line-clamp-3 flex-1">{p.excerpt}</p>
                <div className="mt-4 flex items-center justify-between pt-3 border-t border-slate-100">
                  <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
                    <Calendar className="w-3 h-3" /> {p.date}
                  </div>
                  <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-[#2E7DF5] group-hover:-translate-y-0.5 group-hover:translate-x-0.5 transition-all" />
                </div>
              </div>
            </motion.a>
          ))}
        </div>
      </div>
    </section>
  );
}
