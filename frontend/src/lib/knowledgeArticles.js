// Cybersecurity 101 knowledge base articles. NivX Machines original content —
// structured as long-form educational articles similar to industry primers.
// Each article: hero, definition, types/phases, use cases, defense, takeaways.

export const KB_ARTICLES = [
  {
    slug: "malware-analysis",
    title: "Malware Analysis Explained",
    tagline: "Understand the behaviour and purpose of a suspicious file or URL so you can prevent the next attack.",
    category: "Malware",
    read_mins: 9,
    updated: "2026",
    cover_tone: "from-red-500 to-orange-500",
    cover: "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?auto=format&fit=crop&w=1600&q=80",
    summary:
      "Malware analysis is the process of understanding the behaviour and purpose of a suspicious file or URL. The output aids in detection, triage, and mitigation of the potential threat — enriching incident response, threat hunting and SOC operations.",
    sections: [
      {
        heading: "What is malware analysis?",
        body: [
          "Malware analysis is the process of understanding the behaviour and purpose of a suspicious file or URL. It answers questions like: what does it do, how does it spread, what does it communicate with, and how can we detect it in the future?",
          "The key benefit is that it helps incident responders and security analysts to (1) triage incidents by severity, (2) uncover hidden indicators of compromise (IOCs) that should be blocked, (3) improve the fidelity of alerts and (4) enrich context when threat hunting.",
        ],
      },
      {
        heading: "Types of malware analysis",
        subs: [
          {
            title: "Static analysis",
            body: [
              "Basic static analysis examines the file for signs of malicious intent without actually running the code. It's useful to identify malicious infrastructure, libraries or packed files.",
              "Technical indicators — file names, hashes, embedded strings, IP addresses, domains and PE/ELF header data — help determine whether a file is malicious. Tools like disassemblers, hex editors and network analyzers observe the sample without executing it.",
              "However, sophisticated malware can include runtime behaviour that goes undetected statically (e.g., a payload downloaded via a dynamically generated URL).",
            ],
          },
          {
            title: "Dynamic analysis",
            body: [
              "Dynamic analysis executes suspected code inside a safe environment called a sandbox. This isolated environment lets defenders watch the malware in action without letting it infect production.",
              "Sandboxes eliminate the time it would otherwise take to reverse-engineer a sample. But adversaries know sandboxes exist — modern malware often uses anti-sandbox tricks: check for VM artifacts, wait for user interaction, or stay dormant until conditions are met.",
            ],
          },
          {
            title: "Hybrid analysis",
            body: [
              "Hybrid analysis combines static and dynamic techniques for the best of both worlds. It can detect malicious code trying to hide from a sandbox, then apply static analysis to memory dumps or dropped files that dynamic execution surfaced.",
              "For example, dynamic execution generates a memory dump; hybrid analysis then applies static introspection on that memory to extract additional IOCs and zero-day exploit fingerprints.",
            ],
          },
        ],
      },
      {
        heading: "Malware analysis use cases",
        list: [
          { t: "Malware detection", d: "Behavioural analysis and shared-code identification catch adversaries that traditional signature-based tools miss. IOCs feed SIEMs, TIPs and SOAR platforms to detect related threats." },
          { t: "Alert triage", d: "Higher-fidelity alerts earlier in the kill chain let responders prioritise what matters instead of drowning in noise." },
          { t: "Incident response", d: "IR teams use analysis output to establish root cause, scope of impact and the right containment / eradication steps." },
          { t: "Threat hunting", d: "Behavioural artifacts (a suspicious mutex, a specific C2 hostname pattern, a rare persistence key) become high-quality hunt hypotheses across firewall, proxy and endpoint logs." },
          { t: "Research", d: "Academic and industry researchers use analysis to track emerging TTPs, novel evasion tricks and attacker tooling." },
        ],
      },
      {
        heading: "Stages of malware analysis",
        list: [
          { t: "Static properties analysis", d: "Strings, headers, hashes, metadata, embedded resources. Fast, no execution needed — useful to create initial IOCs and decide if deeper investigation is warranted." },
          { t: "Interactive behaviour analysis", d: "Observe registry, filesystem, process and network activity inside a lab. Memory forensics complements this to understand how the sample manipulates memory." },
          { t: "Fully automated analysis", d: "Rapid, scalable assessment via a sandbox pipeline. Best for processing volume — thousands of samples/day producing consistent, easy-to-consume reports." },
          { t: "Manual code reversing", d: "Reverse-engineering with debuggers and disassemblers to decode encryption, understand algorithms and reveal hidden capabilities the sample hasn't yet executed." },
        ],
      },
      {
        heading: "Building an effective malware analysis workflow",
        body: [
          "A mature workflow starts with automated triage: every suspicious file entering the environment gets a rapid verdict from a hybrid sandbox. High-confidence malicious verdicts are auto-blocked; ambiguous cases are queued for analyst review.",
          "IOCs are stored in a curated database (like the one powering the NivX Threat Intel Hub) and pushed to detection tooling. Anti-sandbox artifacts should be actively hunted — if the same sample runs cleanly in a sandbox but detonates in production, that's a strong signal.",
          "Finally, findings should be captured in structured formats (STIX / MISP / OpenIOC) so intelligence flows freely between teams and tools.",
        ],
      },
      {
        heading: "Key takeaways",
        list: [
          { t: "Combine static + dynamic", d: "Hybrid analysis is the industry standard because sophisticated malware defeats each technique in isolation." },
          { t: "Extract IOCs early", d: "Even 30 seconds of static analysis yields hashes, strings and header data that immediately enrich detection." },
          { t: "Automate at scale", d: "Manual analysis is precious; use it on the samples where automation flagged uncertainty." },
          { t: "Feed downstream tools", d: "IOCs are only valuable when they flow into SIEM, EDR and firewall rules quickly." },
        ],
      },
    ],
  },

  {
    slug: "advanced-persistent-threat",
    title: "Advanced Persistent Threat (APT) Explained",
    tagline: "Understand how nation-state and organised adversaries persist inside a network for months — and how SOCs detect them.",
    category: "Threat Actors",
    read_mins: 10,
    updated: "2026",
    cover_tone: "from-red-600 to-rose-700",
    cover: "https://images.unsplash.com/photo-1618044733300-9472054094ee?auto=format&fit=crop&w=1600&q=80",
    summary:
      "An Advanced Persistent Threat is a stealthy, well-resourced adversary that maintains long-term access to a target network to steal data, disrupt operations or preposition for future action. Understanding the APT lifecycle is core to detecting the invisible attacker.",
    sections: [
      {
        heading: "What is an APT?",
        body: [
          "An Advanced Persistent Threat (APT) is a sophisticated, prolonged cyberattack where an intruder — typically a state-sponsored group, criminal syndicate or industrial-espionage crew — gains unauthorised access to a network and remains undetected for an extended period. The goal is not immediate financial gain; it is intelligence collection, intellectual property theft, or strategic prepositioning.",
          "The three characteristics — Advanced, Persistent, Threat — describe the operator (specialised skill, custom tooling), the tempo (weeks to years, patient and low-and-slow) and the intent (targeted, mission-driven).",
        ],
      },
      {
        heading: "APT characteristics",
        list: [
          { t: "Specific targeting", d: "APT groups pick high-value victims — defence contractors, critical infrastructure, healthcare, finance — and study them before engaging." },
          { t: "Custom tooling", d: "Bespoke malware, zero-day exploits or supply-chain compromise. Off-the-shelf tools may be used but often heavily modified." },
          { t: "Living-off-the-land", d: "Rather than dropping new binaries, APTs weaponise built-in Windows / Linux administrative tools (PowerShell, WMI, PsExec) to blend in with legitimate traffic." },
          { t: "Multi-stage kill chain", d: "Attacks unfold across many discrete stages — each low-signal on its own." },
          { t: "Persistence through resilience", d: "Multiple footholds, redundant C2 channels and sleeper accounts ensure eviction from one host doesn't end the campaign." },
        ],
      },
      {
        heading: "The APT attack lifecycle",
        list: [
          { t: "1. Reconnaissance", d: "Passive and active intelligence gathering — LinkedIn scraping, DNS enumeration, supply-chain mapping, phishing pretext research." },
          { t: "2. Initial access", d: "Spear-phishing, watering-hole compromise, exploit of an internet-facing service, or supply-chain implant. The goal: one foothold, minimal noise." },
          { t: "3. Establish foothold", d: "Install a small implant that survives reboot and beacons out to command-and-control. Payload is often staged — a first-stage loader fetches the real tool later." },
          { t: "4. Privilege escalation", d: "Move from a limited user context to local admin, then domain admin. Techniques: token theft, kerberoasting, credential dumping (LSASS)." },
          { t: "5. Internal reconnaissance", d: "Map Active Directory, identify data owners, locate crown-jewel systems. Often uses native tools like nltest, whoami, net.exe." },
          { t: "6. Lateral movement", d: "Move host-to-host using stolen credentials or Pass-the-Hash / Pass-the-Ticket. WMI, WinRM, RDP and SMB are the common vehicles." },
          { t: "7. Maintain presence", d: "Establish multiple redundant persistence mechanisms (services, scheduled tasks, registry Run keys, WMI event subscriptions, malicious GPOs)." },
          { t: "8. Complete mission", d: "Exfiltrate data to attacker-controlled storage, disrupt operations, or lie dormant until instructed. Cleanup follows to remove artefacts." },
        ],
      },
      {
        heading: "Notable APT groups & activity",
        list: [
          { t: "APT28 / FANCY BEAR", d: "Russian military intelligence (GRU 26165). Known for election interference, aerospace and defence targeting." },
          { t: "APT29 / COZY BEAR", d: "Russian foreign intelligence (SVR). Behind SolarWinds / SUNBURST supply-chain compromise." },
          { t: "APT41 / WICKED PANDA", d: "Chinese, blends state-sponsored espionage with financially motivated ops — a rare hybrid mandate." },
          { t: "LAZARUS / HIDDEN COBRA", d: "North Korean, notorious for financial heists (Bangladesh Bank), crypto exchange attacks and WannaCry-adjacent operations." },
          { t: "Volt Typhoon", d: "China-linked, focused on pre-positioning inside US critical infrastructure via living-off-the-land techniques." },
        ],
      },
      {
        heading: "Detecting and defending against APTs",
        list: [
          { t: "Baseline behaviour", d: "Know what normal PowerShell / WMI / lateral movement looks like in your environment so anomalies stand out." },
          { t: "Endpoint & identity telemetry", d: "EDR + Active Directory audit logs + identity provider logs (Okta / Azure AD) catch credential-based lateral movement." },
          { t: "Network egress analysis", d: "Long-lived beacons and jitter patterns to unusual destinations betray C2. Even DoH / DoT traffic to rare resolvers is a signal." },
          { t: "Threat intelligence integration", d: "Feed known APT IOCs (host artifacts, C2 domains, TLS certificates) into detection continuously — not once a quarter." },
          { t: "Threat hunting", d: "Assume breach: hypothesis-driven hunts using MITRE ATT&CK techniques (T1078 Valid Accounts, T1021 Remote Services, T1055 Process Injection) frequently catch what alerts miss." },
          { t: "Zero-trust segmentation", d: "Even if the attacker gets a foothold, network micro-segmentation and identity-aware access limit blast radius." },
        ],
      },
      {
        heading: "Key takeaways",
        list: [
          { t: "APTs are patient", d: "Detection windows measured in months, not hours. Dwell time is the metric that matters." },
          { t: "They abuse legitimate tools", d: "The best defence is behavioural, not signature-based." },
          { t: "Identity is the new perimeter", d: "Most APTs escalate via credentials. Harden identity aggressively." },
          { t: "Hunt, don't just alert", d: "Alerts detect the known-bad. Hunting detects the novel." },
        ],
      },
    ],
  },

  {
    slug: "incident-response",
    title: "Incident Response Plan & Framework",
    tagline: "A repeatable playbook to contain, eradicate and recover from cyber incidents — before they escalate into breaches.",
    category: "SOC Operations",
    read_mins: 8,
    updated: "2026",
    cover_tone: "from-blue-500 to-indigo-600",
    cover: "https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1600&q=80",
    summary:
      "Incident Response (IR) is the organised approach to preparing for, detecting, containing and recovering from a cyber incident. A mature IR programme reduces dwell time, limits business impact and turns every incident into an opportunity to improve.",
    sections: [
      {
        heading: "What is Incident Response?",
        body: [
          "Incident Response is the coordinated set of processes, tooling and people that an organisation uses to identify, contain and recover from cyber incidents. Its purpose is to reduce the time between compromise and containment (dwell time) — the single strongest predictor of breach impact.",
          "IR is not an ad-hoc scramble; it is a repeatable, drill-tested lifecycle owned by a defined team with authority to make decisions in the middle of the night.",
        ],
      },
      {
        heading: "The NIST 6-phase Incident Response lifecycle",
        list: [
          { t: "1. Preparation", d: "Build the plan, roles, runbooks, forensic tooling, communications templates and legal / regulatory playbooks — before you need them. Tabletop-test the plan quarterly." },
          { t: "2. Identification", d: "Detect the incident. Correlate telemetry from SIEM, EDR, identity provider, network flow, threat intel. Classify severity and open the ticket." },
          { t: "3. Containment", d: "Short-term (isolate the affected host / disable the compromised account) and long-term (rebuild systems from known-good baselines, rotate credentials, patch the exploited vulnerability)." },
          { t: "4. Eradication", d: "Remove the adversary's footholds: malware, persistence mechanisms, backdoor accounts, malicious GPOs, scheduled tasks and any implanted webshells." },
          { t: "5. Recovery", d: "Restore systems to production, monitor closely for re-emergence, communicate with stakeholders and progressively increase trust as behaviour normalises." },
          { t: "6. Lessons learned", d: "Post-incident review: what worked, what failed, what will change. Update runbooks, invest in the gaps, share sanitised findings." },
        ],
      },
      {
        heading: "The IR team",
        list: [
          { t: "Incident Commander", d: "Owns the incident end-to-end. Sets tempo, makes go / no-go decisions, keeps stakeholders informed." },
          { t: "Lead Analyst / Forensics", d: "Drives the technical investigation: memory forensics, disk imaging, log correlation, malware triage." },
          { t: "Threat Hunter", d: "Answers: where else is the adversary? Sweeps the estate for related indicators and TTPs." },
          { t: "Communications lead", d: "Owns internal (execs, legal, PR) and external (customers, regulators, media) messaging on a strict cadence." },
          { t: "IT operations", d: "Executes containment actions: isolate hosts, rotate credentials, apply patches, rebuild systems." },
          { t: "Legal & Compliance", d: "Regulatory notification timelines (GDPR 72h, HIPAA, CIRCIA, SEC 8-K), evidence-handling and law-enforcement liaison." },
        ],
      },
      {
        heading: "Key metrics for a mature IR programme",
        list: [
          { t: "MTTD", d: "Mean Time To Detect — from initial compromise to alert. Target: minutes to hours." },
          { t: "MTTR", d: "Mean Time To Respond / Contain — from alert to attacker eviction. Target: hours to a day." },
          { t: "Dwell time", d: "How long the adversary was inside before eviction. Industry benchmark is trending down but still 10-20 days for many organisations." },
          { t: "Incident volume", d: "Trending down over time indicates prevention improvements; a sudden spike suggests either new campaigns or improved detection." },
          { t: "Post-incident action closure rate", d: "% of lessons-learned action items completed within 90 days — the cultural KPI that separates mature programmes." },
        ],
      },
      {
        heading: "Building an effective IR plan",
        body: [
          "Start with an accurate asset inventory — you cannot respond to an incident on a host you didn't know existed. Layer in a communication tree that includes on-call rotation, legal escalation and executive briefing paths.",
          "Standardise runbooks for the most common incident classes: ransomware, business email compromise, credential compromise, insider risk, denial-of-service and supply-chain implant. Each runbook should specify triggers, decision trees, containment actions and communication templates.",
          "Rehearse. Tabletop exercises quarterly and a full-scale simulation annually catch weaknesses in the calm before the real event.",
        ],
      },
      {
        heading: "Key takeaways",
        list: [
          { t: "Prep beats improvisation", d: "The best IR happens in Preparation, not Identification." },
          { t: "Speed is a habit", d: "Rehearsal converts panicked scrambling into muscle memory." },
          { t: "Communicate deliberately", d: "Regulators, customers and executives all need the right message on the right cadence." },
          { t: "Learn every time", d: "Every incident is a paid training exercise. Extract full value." },
        ],
      },
    ],
  },

  {
    slug: "man-in-the-middle-attack",
    title: "Man-in-the-Middle (MITM) Attack Explained",
    tagline: "How attackers position themselves between two parties to eavesdrop, intercept and manipulate — and how modern defenders stop them.",
    category: "Network Attacks",
    read_mins: 8,
    updated: "2026",
    cover_tone: "from-purple-500 to-indigo-600",
    cover: "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1600&q=80",
    summary:
      "A Man-in-the-Middle attack places the adversary invisibly between two communicating parties, allowing them to intercept, read and often alter the exchange. MITM sits at the intersection of network, cryptography and identity — and defeating it requires all three.",
    sections: [
      {
        heading: "What is a MITM attack?",
        body: [
          "A Man-in-the-Middle (MITM) attack occurs when an adversary secretly positions themselves between two parties who believe they are communicating directly. The attacker can eavesdrop, harvest credentials, inject malicious content, or manipulate the exchange in real time.",
          "MITM is not one attack — it's a family. What ties them together is the topology: attacker sits on the path between A and B. What varies is how the attacker arrives at that topology and what layer they exploit.",
        ],
      },
      {
        heading: "Common MITM techniques",
        list: [
          { t: "ARP spoofing", d: "On a local Ethernet segment, the attacker floods the network with forged ARP responses, associating their MAC address with the gateway's IP. Traffic destined for the gateway now flows through the attacker." },
          { t: "DNS spoofing / cache poisoning", d: "The attacker corrupts a DNS resolver's cache so that lookups for a legitimate domain return an IP the attacker controls. The victim's browser then happily connects to the wrong server." },
          { t: "HTTPS spoofing (fake CA)", d: "If the attacker has compromised or been issued a certificate for a target domain (e.g., via a rogue CA or misconfigured internal PKI), they can terminate TLS at their proxy and re-encrypt to the destination — reading everything in the middle." },
          { t: "SSL stripping", d: "Downgrade a client's HTTPS attempt to plain HTTP by intercepting the initial HTTP request that would normally redirect to HTTPS. Everything the victim sends is then plaintext." },
          { t: "Wi-Fi eavesdropping (evil twin)", d: "The attacker stands up a rogue access point with the same SSID as a legitimate hotspot. Devices auto-connect, and now all traffic passes through the attacker's AP." },
          { t: "Session hijacking", d: "Steal an active session cookie (via XSS, packet sniffing on unencrypted networks, or malware) and use it to impersonate the victim without needing their password." },
          { t: "IP spoofing", d: "Forge the source IP of packets to appear as a trusted host. Combined with a race-condition or asymmetric routing, it can bypass source-IP-based access controls." },
          { t: "Email hijacking / BEC", d: "A subset of MITM where the attacker inserts themselves in an email thread (often after compromising a mailbox) and manipulates payment instructions or contract details." },
        ],
      },
      {
        heading: "Real-world examples",
        list: [
          { t: "Superfish (Lenovo, 2015)", d: "Preinstalled adware injected ads by acting as a MITM on all HTTPS traffic — via a shipped root CA that any attacker could clone." },
          { t: "DarkHotel", d: "Nation-state group targeting executives on hotel Wi-Fi using rogue APs and forged updater prompts." },
          { t: "SSL Strip / Firesheep era", d: "Public Wi-Fi cafes were a MITM playground until major sites moved to HSTS-preloaded HTTPS-only." },
        ],
      },
      {
        heading: "How to defend against MITM",
        list: [
          { t: "HTTPS everywhere + HSTS preload", d: "Force TLS on every request from the very first byte, and preload HSTS so browsers refuse HTTP altogether." },
          { t: "Certificate pinning (where sensible)", d: "Mobile apps and internal services can pin the expected public key, breaking rogue-CA attacks." },
          { t: "Strong Wi-Fi hygiene", d: "WPA3, unique per-user credentials on enterprise Wi-Fi (802.1X), and disable auto-connect to open networks on client devices." },
          { t: "DNSSEC + encrypted DNS", d: "Signed DNS responses and DoH / DoT protect the lookup step from tampering." },
          { t: "Mutual TLS for machine-to-machine", d: "Both client and server present certificates — no more one-way trust." },
          { t: "Endpoint detection", d: "EDR can spot the local-network anomalies (unexpected ARP behaviour, rogue proxies) that a compromised host would exhibit." },
          { t: "User training", d: "Certificate warnings are the last line of defence. Users must be taught not to click 'proceed anyway'." },
        ],
      },
      {
        heading: "Detection signals to watch for",
        list: [
          { t: "Sudden ARP table changes", d: "Multiple MAC addresses claiming the gateway IP within seconds is a classic ARP spoof fingerprint." },
          { t: "Certificate mismatches", d: "Alerts from your endpoint or browser telemetry about unexpected certificate issuers on well-known domains." },
          { t: "TLS downgrade attempts", d: "HTTP requests to hosts that should be HSTS-preloaded, or client-hello patterns indicating older ciphers being negotiated when they shouldn't be." },
          { t: "New rogue APs on premises", d: "Wireless intrusion detection (WIDS) that flags SSIDs impersonating your corporate network." },
        ],
      },
      {
        heading: "Key takeaways",
        list: [
          { t: "Encryption is necessary, not sufficient", d: "MITM finds a way in when trust anchors (CAs, DNS, ARP) are compromised even if the transport is encrypted." },
          { t: "Attack the topology assumption", d: "The attacker's advantage is invisibility — remove it with pinning, DNSSEC and network segmentation." },
          { t: "Public Wi-Fi is hostile", d: "Assume every open network has an evil-twin and enforce VPN or app-level TLS." },
          { t: "Detect at the edge", d: "Rogue AP detection and certificate anomaly telemetry are cheap wins that catch a broad class of MITM." },
        ],
      },
    ],
  },
];

export function findArticle(slug) {
  return KB_ARTICLES.find((a) => a.slug === slug);
}
