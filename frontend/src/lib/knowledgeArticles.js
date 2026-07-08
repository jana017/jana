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
    cover: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=1600&q=80",
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
        image: "https://images.unsplash.com/photo-1614064548237-096d0f6db4e7?auto=format&fit=crop&w=1600&q=80",
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
        image: "https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=1600&q=80",
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
    cover: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1600&q=80",
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
        image: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=1600&q=80",
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
        image: "https://images.unsplash.com/photo-1451187580459-43490279c0fa?auto=format&fit=crop&w=1600&q=80",
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
    cover: "https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=1600&q=80",
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
        image: "https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=1600&q=80",
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
        image: "https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1600&q=80",
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
    cover: "https://images.unsplash.com/photo-1520869562399-e772f042f422?auto=format&fit=crop&w=1600&q=80",
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
        image: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1600&q=80",
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

  {
    slug: "sql-injection-attack-analysis",
    title: "SQL Injection Attack Analysis",
    tagline: "One of the oldest web vulnerabilities and still one of the most dangerous — how SQLi works, how to detect it, and how to stop it.",
    category: "AppSec",
    read_mins: 8,
    updated: "2026",
    cover_tone: "from-blue-500 to-indigo-600",
    cover: "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?auto=format&fit=crop&w=1600&q=80",
    summary:
      "SQL Injection occurs when an application concatenates user-controlled input into a SQL query without proper parameterisation, allowing an attacker to change the intent of the query. Two decades after it first appeared in the OWASP Top 10, SQLi remains a leading root cause of data breaches.",
    sections: [
      { heading: "What is SQL Injection?", body: [
        "A web application takes user input, builds a SQL query from it, and executes it against a database. SQL Injection happens when the application fails to distinguish data from code — the attacker's input is interpreted as part of the query syntax, changing what the query does.",
        "Impact spans data theft, authentication bypass, data destruction, remote code execution (via UDFs or xp_cmdshell on some databases) and, in the worst cases, complete server takeover.",
      ]},
      { heading: "The main variants",
        image: "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?auto=format&fit=crop&w=1600&q=80",
        list: [
        { t: "In-band (classic)", d: "Attacker sees the query's output directly — via error messages or a UNION-based technique that appends attacker-controlled rows to the legitimate result set." },
        { t: "Blind (Boolean-based)", d: "The application returns different responses for true vs false conditions. Attacker infers data one bit at a time by asking yes/no questions." },
        { t: "Blind (Time-based)", d: "No visible difference in response — but the attacker can force the DB to sleep (WAITFOR DELAY, BENCHMARK, pg_sleep) when a condition is true. Slow but reliable." },
        { t: "Out-of-band", d: "The database exfiltrates data via a side channel — DNS lookup, HTTP request, SMB — when the primary channel is unavailable." },
        { t: "Second-order", d: "Attacker input is stored safely first, then later concatenated unsafely into a different query. The injection fires without matching the initial input pattern." },
      ]},
      { heading: "A classic anatomy", body: [
        "A login form runs: SELECT * FROM users WHERE username='$user' AND password='$pass'",
        "Attacker sends username = admin' -- and any password. The resulting query becomes: SELECT * FROM users WHERE username='admin' -- ' AND password='...'. The comment marker (--) neutralises the password check. Auth bypass in one line.",
        "The same weakness in a search field enables UNION SELECT to append rows from other tables (users, credentials, session tokens) into the visible result.",
      ]},
      { heading: "Detection in the SOC",
        image: "https://images.unsplash.com/photo-1451187580459-43490279c0fa?auto=format&fit=crop&w=1600&q=80",
        list: [
        { t: "WAF alerts on SQL keywords", d: "UNION, SELECT, WAITFOR, BENCHMARK, SLEEP, xp_cmdshell in request parameters. Tune to avoid FPs from legitimate CMSes." },
        { t: "Response-length anomalies", d: "Union-based SQLi often produces responses much larger than baseline — instrument content-length delta detection." },
        { t: "Response-time anomalies", d: "Time-based SQLi produces predictable latency spikes on hits. Baseline endpoint latency and alert on outliers." },
        { t: "DB audit logs", d: "Direct DB audit logging on the backend catches successful attacks even when the WAF was bypassed. Enable for high-value databases." },
        { t: "Error-message leakage", d: "Verbose DB errors (ORA-, ERROR:, MySQL, PDOException) in HTTP responses are strong indicators of both vulnerability and exploitation." },
      ]},
      { heading: "Defensive patterns", list: [
        { t: "Parameterised queries / prepared statements", d: "The only defence that actually works. Every mainstream DB driver supports them. Concatenating SQL is an anti-pattern in 2026." },
        { t: "ORM with safe defaults", d: "Modern ORMs (Django ORM, SQLAlchemy, Prisma, Entity Framework) parameterise by default — but escape hatches like raw() bypass the safety. Review those." },
        { t: "Least-privilege DB accounts", d: "Web app accounts should have SELECT/INSERT on their own tables — never DROP, never sysadmin. Limits blast radius when SQLi succeeds." },
        { t: "WAF as defence-in-depth (not primary)", d: "Signature-based WAFs are bypassed by encoding tricks. Use them as a speed bump, never as the primary defence." },
        { t: "Input validation with allow-lists", d: "For inputs with a known format (email, UUID, integer), validate strictly. Reject everything else." },
      ]},
      { heading: "Key takeaways", list: [
        { t: "It's still on the OWASP Top 10", d: "For a reason — SQLi remains one of the most common breach root causes 25+ years after discovery." },
        { t: "Parameterisation is the fix", d: "Not sanitisation. Not escaping. Parameterisation." },
        { t: "Detect at multiple layers", d: "WAF, application logs and DB audit logs together tell the complete story." },
      ]},
    ],
  },

  {
    slug: "powershell-fileless-malware-analysis",
    title: "PowerShell & Fileless Malware Analysis",
    tagline: "Modern malware increasingly avoids the disk. Understanding PowerShell abuse and in-memory execution is the difference between catching adversaries and missing them.",
    category: "Malware",
    read_mins: 9,
    updated: "2026",
    cover_tone: "from-purple-500 to-indigo-600",
    cover: "https://images.unsplash.com/photo-1629654297299-c8506221ca97?auto=format&fit=crop&w=1600&q=80",
    summary:
      "Fileless malware executes primarily in memory using legitimate system tools (PowerShell, WMI, .NET assemblies, LOLBins) — leaving no persistent executable to hash. Detecting it requires a shift from file-centric to behaviour-centric analysis.",
    sections: [
      { heading: "Why PowerShell is the attacker's best friend", body: [
        "PowerShell ships on every modern Windows machine. It's signed by Microsoft, trusted by AV, has full .NET Framework access and can download, decode and execute code entirely in memory. For an attacker, it's a perfect Swiss Army knife.",
        "The pattern that appears in almost every incident: powershell.exe -nop -w hidden -enc <base64_blob>. The blob decodes to a downloader that pulls the real payload from the internet and reflectively loads it — no file written to disk.",
      ]},
      { heading: "The fileless toolkit",
        image: "https://images.unsplash.com/photo-1629654297299-c8506221ca97?auto=format&fit=crop&w=1600&q=80",
        list: [
        { t: "PowerShell reflective loader", d: "IEX (New-Object Net.WebClient).DownloadString('...') pattern. Executes remote code in the current process." },
        { t: ".NET Assembly.Load", d: "Loads a raw DLL byte-buffer directly into memory. Common for Cobalt Strike beacons and Sliver implants." },
        { t: "WMI event subscriptions", d: "Persistent __EventFilter + __EventConsumer pairs. Persistence with no file, no registry Run key, no scheduled task." },
        { t: "LOLBins (Living-off-the-Land binaries)", d: "regsvr32, rundll32, mshta, msbuild, installutil — legitimate signed binaries that can execute attacker payloads through built-in features." },
        { t: "Registry-only payloads", d: "Malicious code stored as base64 blobs in registry values, executed by a lightweight PowerShell loader launched by a Run key." },
      ]},
      { heading: "Analysis techniques",
        image: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1600&q=80",
        list: [
        { t: "Command-line reconstruction", d: "Sysmon Event 1 gives you the full command line. Decode -EncodedCommand blobs (base64 + UTF-16LE) and analyse the resulting script." },
        { t: "Script-block logging (4104)", d: "Even encoded PowerShell decodes at runtime and produces Event 4104 with the plain-text script block. Enable via Group Policy — free, high-signal." },
        { t: "Module-load telemetry", d: "EDR module-load events reveal unusual DLLs loaded into powershell.exe, winword.exe, or explorer.exe. Reflectively loaded assemblies show up here." },
        { t: "Memory forensics", d: "Volatility's malfind, ldrmodules, and yarascan on process memory catch payloads never on disk. Slow but definitive." },
        { t: "AMSI telemetry (Anti-Malware Scan Interface)", d: "Windows exposes script content to AMSI at execution time. Alerts on suspicious PowerShell can be routed through your EDR / SIEM." },
      ]},
      { heading: "Detection rules that catch 80% of fileless attacks", list: [
        { t: "Encoded PowerShell > 500 chars", d: "Legitimate encoded commands are usually short. Long ones warrant review." },
        { t: "Suspicious parent-child", d: "winword.exe → powershell.exe, excel.exe → cmd.exe, outlook.exe → powershell.exe. Rare in legitimate use." },
        { t: "PowerShell downloading", d: "DownloadString, DownloadFile, WebClient, Invoke-WebRequest with an internet destination — outside allowlisted use." },
        { t: "WMI event subscription creation", d: "Sysmon 19/20/21 — almost never legitimate outside change windows." },
        { t: "Registry Run keys with encoded payloads", d: "New Run/RunOnce values containing 'FromBase64String' or long b64 strings are near-100% malicious." },
      ]},
      { heading: "What good analysis looks like", body: [
        "You spot the encoded PowerShell command line. You decode the b64. You see it's a Cobalt Strike stager pointing to a fresh domain. You retrieve the stager (safely), unpack the shellcode, extract the config (beacon interval, C2 hosts, watermark), and generate high-fidelity IOCs. Those IOCs go into every EDR, firewall and SIEM. Total analysis time: 60 minutes. Total analyst investment: high. Coverage improvement: massive.",
      ]},
      { heading: "Key takeaways", list: [
        { t: "Enable script-block logging", d: "Free, and catches the majority of fileless attacks." },
        { t: "Behaviour over signatures", d: "You can't hash what was never written. Detection must be behavioural." },
        { t: "AMSI + Sysmon + EDR", d: "Three layers of visibility catch what one alone misses." },
      ]},
    ],
  },

  {
    slug: "email-phishing-analysis",
    title: "Email Phishing Analysis",
    tagline: "Phishing remains the #1 initial-access vector in every industry — how modern SOCs analyse suspicious email and stop the attack before it lands.",
    category: "Threat Actor Insight",
    read_mins: 8,
    updated: "2026",
    cover_tone: "from-amber-500 to-orange-500",
    cover: "https://images.unsplash.com/photo-1596526131083-e8c633c948d2?auto=format&fit=crop&w=1600&q=80",
    summary:
      "Phishing is the practice of tricking a user into taking an action — clicking a link, opening an attachment, entering credentials — that benefits an attacker. It's cheap, it scales infinitely, and it works. Analysing a phishing email systematically turns a scary alert into actionable intelligence.",
    sections: [
      { heading: "The taxonomy of phishing", list: [
        { t: "Bulk phishing", d: "Untargeted, high-volume campaigns. Cheap to run, low success rate per recipient, high total yield." },
        { t: "Spear phishing", d: "Targeted at a specific individual using personal / professional details. Much higher success rate — often the initial access vector for APTs." },
        { t: "Whaling", d: "Spear phishing targeted at executives. High-value payoff (wire transfer authority, sensitive access)." },
        { t: "Business Email Compromise (BEC)", d: "No malware — pure social engineering. Attacker impersonates an executive or vendor to redirect a payment." },
        { t: "Vishing / Smishing", d: "Voice or SMS variants. MFA-fatigue and SIM-swap-adjacent techniques." },
      ]},
      { heading: "The analysis checklist",
        image: "https://images.unsplash.com/photo-1596526131083-e8c633c948d2?auto=format&fit=crop&w=1600&q=80",
        list: [
        { t: "Sender identity", d: "Return-Path, From, Reply-To — do they match? A mismatched Reply-To is a classic phish. Check the actual authenticating domain, not just the display name." },
        { t: "SPF / DKIM / DMARC results", d: "Full authentication headers. A DMARC=fail from a domain you've configured as p=reject should never reach the user in the first place." },
        { t: "Message headers", d: "Received: chain reveals the true origin. Client-header inconsistencies (e.g., mail sent 'from Outlook' but no X-Mailer: Microsoft) are telling." },
        { t: "URL analysis", d: "Extract every URL. Check against VirusTotal, URLScan, and Google Safe Browsing. Look for typosquats (rn instead of m), open-redirect abuse, and homoglyphs." },
        { t: "Attachment analysis", d: "Hash it. VT + Hybrid Analysis lookup. If unknown, detonate in a sandbox. Common formats: HTML smuggling, macro-enabled Office, ISO/IMG containers hiding LNK files." },
        { t: "Body pattern matching", d: "Urgency, authority, unusual payment request, credential-harvest landing page. Modern phish templates are eerily polished — the tell is often the ask, not the language." },
      ]},
      { heading: "Automating triage", body: [
        "Mature SOCs have a phishing mailbox (phishing@your-domain) where users report suspicious mail. A SOAR playbook then: (1) extracts headers, URLs, and attachments, (2) runs each against VT / URLScan / HA / internal IOC DB, (3) auto-classifies malicious / suspicious / benign, and (4) purges from every user's mailbox at once (Microsoft 365 has native APIs for this).",
        "This turns a labour-intensive workflow into a 30-second decision for the analyst.",
      ]},
      { heading: "Prevention that actually moves the needle",
        image: "https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1600&q=80",
        list: [
        { t: "DMARC at p=reject", d: "Prevents attackers from spoofing your exact domain. External senders can still impersonate visually — see below." },
        { t: "External-sender banner", d: "Every email from outside gets a visible tag. Cheap, high-impact user awareness." },
        { t: "Phishing-resistant MFA", d: "FIDO2 keys, Windows Hello for Business, Authenticator with number matching. Removes the credential-theft payoff." },
        { t: "URL rewriting + click-time scanning", d: "M365 Safe Links, Google Safe Browsing, Proofpoint URL Defense. Scan the link at click time, not just send time (attacker infra often flips post-delivery)." },
        { t: "User training", d: "Not enough on its own. But combined with everything above, quarterly phish simulations turn users into a detection layer." },
      ]},
      { heading: "What good response looks like", body: [
        "A user reports a suspicious email at 09:12. SOAR triages it at 09:12:30. Verdict: malicious credential-harvest for O365. Playbook: purge from every mailbox, block the sender domain, add the landing-page URL to the WAF blocklist, sweep sign-in logs for any user who clicked and authenticated, force-reset any successful captures. Time from report to full response: under 10 minutes.",
      ]},
      { heading: "Key takeaways", list: [
        { t: "Users are a detection layer", d: "Make it easy to report suspicious email; reward it." },
        { t: "Automate the boring parts", d: "Header/URL/attachment triage is perfect for SOAR." },
        { t: "MFA that resists phishing is table stakes", d: "SMS-based MFA is no longer sufficient in 2026." },
      ]},
    ],
  },
];

export function findArticle(slug) {
  return KB_ARTICLES.find((a) => a.slug === slug);
}
