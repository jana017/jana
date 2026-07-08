# NivX Machines — PRD

## Problem Statement
NivX Machines (Cyber Security, AI, Tech firm) landing site. Tabs: About Us, Gallery, Threat Report, Careers, Services, Support. Threat Report shows real-time threat reports with Attack Chain (MITRE ATT&CK), Process Trees, images. Contact: Mobile 9059565125, Email info@nivxmachines.com. Real-time threat landscape.

## User Choices
- Landing page (single-page marketing site + admin).
- Threat reports: live external feed (CISA KEV) + admin panel CRUD.
- Careers: static roles, apply via email.
- Support: contact info only.
- Design: CLEAN CORPORATE / enterprise-security (Palo Alto / Cisco / Optiv / Trend Micro reference). Light-dominant, restrained heading sizes.
- Fonts: Outfit (headings), Inter (body), IBM Plex Mono (data). (Earlier tried Unbounded/JetBrains Mono — rejected.)
- Brand: logo provided (navy + orange #F5821F + blue #2E7DF5). Logo at /app/frontend/public/nivx-logo.webp.

## Architecture
- Backend FastAPI (/app/backend/server.py): JWT admin auth (Bearer/localStorage), threat CRUD (/api/threats), live CISA KEV feed (/api/live-feed, 30-min cache), admin + sample threats seeded on startup.
- Frontend React (light theme): Landing (Navbar, Hero, About, StatsBand, LiveThreatLandscape, ThreatDashboard, Services, Gallery, Careers, Contact) + /admin (login + dashboard). Lenis smooth scroll, framer-motion.

## Implemented (2026-07-08)
- All 6 sections + hero + live threat landscape + admin panel.
- Live CISA feed (1,635 CVEs) — CVE rows link to NVD detail (new tab).
- Live Attack Feed (ransomware.live recent victims, screenshots) — real-time online attack data.
- 7 detailed threat reports, each with MITRE attack chain, process tree, image. Featured brief uses an animated kill-chain node diagram + MITRE T-codes.
- Support "Request a Security Assessment" lead-capture form -> POST /api/leads (EmailStr validated); admin GET /api/leads.
- Admin delete uses shadcn AlertDialog (no native confirm).
- Transparent/light logo variants (nivx-logo-light.png for white nav, nivx-logo-transparent.png for navy footer).
- Full redesign: light corporate enterprise theme (Outfit/Inter/IBM Plex Mono).
- Tests: backend 13/13, frontend 100%.

## Credentials
- Admin: admin@nivxmachines.com / NivX@Admin2025 (see /app/memory/test_credentials.md)

## Backlog / Next
- P2: Smart OSINT — DONE (IOC analyzer: auto-detect + inline enrichment + prefilled deep-links).
- P2: Persist rate-limit in Redis/Mongo if scaling to multiple replicas (currently in-memory per worker).
- P2: Lead management enhancements — notes/assignee, filter by status.
- P2: Unit42 reader — search within very large IOC tables.

## Latest (2026-07-08, session 3)
- IOC Analyzer ("Investigate indicators in one click") upgraded — no API keys required:
  - File hashes now enriched via CIRCL hashlookup (no-key): shows Known Malicious / Known Good verdict + filename/size/product/source; unknown hashes show a clear "not in known-file DB, use deep links" note (old "no key-free source" message removed).
  - Expanded per-type deep-link icons (each → the IOC's result page): hashes = VirusTotal/MalwareBazaar/ThreatFox/Hybrid Analysis/IBM X-Force; IP = VT/AbuseIPDB/Talos/Shodan/GreyNoise/X-Force; domain = VT/urlscan/Talos/Shodan/X-Force; URL = VT/urlscan/X-Force.
  - OSINT tool grid: added Shodan, Censys, CyberChef quick-link cards (icons + hyperlinks).
- Hero visual replaced with a LIVE animated world threat map (LiveThreatMap.jsx): plots real recent ransomware-victim countries (ransomware.live) as pulsing geo markers on an equirectangular world map (/world-equirect.jpg) via COUNTRY_CENTROIDS; rotating live-incident label + animated attack arcs; live counters (KEV tracked, recent incidents, ransomware-linked CVEs) from CISA + attack feeds; monitoring badge shows live signal count.
- Note: No paid keys — full VirusTotal-style detection ratios remain via one-click deep links (VT/MalwareBazaar/ThreatFox all now require a key for their APIs).
- Tests: frontend E2E passed (iteration_9) for live map + IOC analyzer (hash/IP/domain/URL, deep links, target=_blank). Backend ioc-lookup curl-verified.

## Latest (2026-07-08, session 4)
- BULK IOC paste (P2-A): IOC Analyzer has a Single/Bulk toggle. Bulk mode (IocBulkTable.jsx) accepts many IOCs (newline/comma/space), POST /api/ioc-lookup-batch (dedupe + cap 50, concurrent, semaphore 8), renders a results table (Indicator/Type/Summary/Reputation/Investigate links) + Download CSV (resultsToCSV/downloadCSV in lib/iocUtils.js).
- INLINE VT + AbuseIPDB reputation (P2-B, LIVE): keys in backend/.env (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY). server.py _vt_lookup (ip/domain/url/file via VT v3) + _abuseipdb_lookup (IP) + _reputation with 6h Mongo cache (ioc_cache) to conserve free quota. Graceful fallback when keys absent / rate-limited. GET /api/ioc-config exposes provider status. Frontend ReputationBadges.jsx shows VT ratio (e.g. 65/68, red/green) + AbuseIPDB % in single header and bulk table.
- Tests: iteration_10 (bulk UI + CSV + graceful empty rep) and iteration_11 (real VT/AbuseIPDB scores in single + bulk) both fully passed. Backend curl-verified (EICAR 65/68 malicious; 8.8.8.8 VT 0/91 + AbuseIPDB 0%).

## Latest (2026-07-08, session 5)
- VT community context (hash view): single-hash result now shows a "VirusTotal Community" block — suggested threat label, threat categories + tags chips, and last-analysis date (from VT file object). _vt_lookup extended with last_analysis_date/threat_label/threat_categories/tags.
- Live CVE feed upgrade: GET /api/live-feed now returns the FULL CISA KEV catalog (~1,635 CVEs) instead of top 50. LiveThreatLandscape has a real-time search box (by CVE id / name / vendor / product) + clear button + "X of Y" count over a scrollable list.
- OSINT tool grid additions: Shodan, Censys, CyberChef (session 4) + MITRE ATT&CK + MITRE D3FEND (icons + deep links). 10 tools total.
- Tests: iteration_12 passed (CVE search/scroll + VT community hash block). MITRE cards verified visually.

## Latest (2026-07-08, session 6)
- Domain/URL enrichment made robust (was: relied only on rate-limited urlscan and often showed nothing). Now _do_lookup resolves the host via Google DNS-over-HTTPS (_resolve_host) then pulls Shodan InternetDB (_shodan_ip) + ip-api geo (_geo_ip) for the resolved IP, plus urlscan (now with URLSCAN_API_KEY in .env) + VirusTotal reputation. Frontend web block shows resolved IP, geo, open ports, known vulns, urlscan scans + VT badge.
- Landing-page preview: urlscan() returns a representative homepage screenshot (enrichment.preview {screenshot,url,result}); frontend renders it as an image with a 'LIVE PAGE PREVIEW · urlscan.io' badge (ioc-web-preview), gracefully hidden if none/broken.
- Bulk Summary column for domains now includes geo + ports + scans (iocUtils.iocSummary).
- Keys added to backend/.env: URLSCAN_API_KEY (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY already present).
- Tests: iteration_13 (domain/url enrichment + IP/hash regression) and iteration_14 (screenshot preview + graceful absence + bulk summary) both fully passed, zero console errors.

## Latest (2026-07-08, session 7)
- CURATED IOC DATABASE (new): Mongo collection `iocs` (fields: value, key[canonical], type[auto], threat_name, tags, severity, source, notes, created_at). Admin-only manage, public view/search.
  - Backend: POST /api/iocs (single), POST /api/iocs/bulk (paste), POST /api/iocs/upload (CSV/TXT/XLSX via openpyxl), GET /api/iocs (search/filter q/type/severity/tag), GET /api/iocs/stats, DELETE /api/iocs/bulk (multi), DELETE /api/iocs/{id}. Upsert by canonical key (_ioc_key defang+lowercase). All writes require admin JWT.
  - Analyzer integration: _do_lookup adds result.local_db when the analyzed IOC exists; frontend shows severity-colored 'Known IOC — in your database' banner (KnownIocBanner.jsx) in single view + a 'Known · <severity>' chip in bulk rows.
  - Frontend: IocDatabase.jsx on Threat Intelligence page — stats chips, search + type/severity filters, table; admin-only upload panel (single / bulk paste / CSV-Excel file) + multi-select bulk delete + row delete. Admin gating via useAuth().
  - Tests: iteration_15 passed (guest gating, admin CRUD, upload, bulk/single delete, analyzer banner). Minor: success toast (ioc-db-msg) sometimes auto-clears fast — cosmetic only, operations succeed.
- Key rotation: VIRUSTOTAL_API_KEY and URLSCAN_API_KEY updated to new values in backend/.env (verified working: EICAR 62/66, urlscan previews OK). ioc_cache cleared on rotation.
- Dependency added: openpyxl (Excel parsing) — in requirements.txt.

## Latest (2026-07-08, session 8)
- Lead management (P2 done): Lead model gained `notes` + `assignee`; PATCH /api/leads/{id} now accepts optional status/notes/assignee (LeadUpdate) and preserves untouched fields. Admin Leads tab: filter-by-status dropdown + inline editable Assignee input and Notes textarea per lead; CSV export includes them.
- AI IOC threat summary (Gemini): POST /api/ioc-ai-summary runs the lookup, builds context, and calls Gemini (emergentintegrations, model gemini-3-flash-preview) via EMERGENT_LLM_KEY; result cached 7d in Mongo `ioc_ai_cache`. GET /api/ai-config exposes availability. Frontend: 'Analyze with AI' button on single results renders a threat assessment panel. EMERGENT_LLM_KEY added to backend/.env.
- Save to IOC Database (analyzer): admin-only 'Save to IOC Database' button on single results POSTs to /api/iocs, pre-filling VT threat label/categories + a suggested severity (from VT malicious/AbuseIPDB score); shows 'In IOC database' badge when present.
- Tests: iteration_16 fully passed (AI summary, admin-gated save, lead assignee/notes/status-filter), zero console errors.

## Latest (2026-07-08, session 9)
- AlienVault OTX auto-sync (P0 done): OTX_API_KEY in backend/.env. New backend module in server.py (_sync_otx_pulses, _otx_severity, _otx_sync_loop, _otx_indicator_value). Pulls up to 50 latest subscribed pulses / 500 indicators from `/api/v1/pulses/subscribed`, upserts into MongoDB `iocs` collection via _upsert_ioc with source='AlienVault OTX · {pulse_id}', notes=pulse description, tags=pulse tags + actor/family. Severity derived from pulse characteristics (critical if ransomware/apt/0day tag; high if adversary/malware_family attributed; medium default — TLP is NOT used since almost all pulses are TLP=white). Endpoints: GET /api/otx/status (public — configured + last_sync summary from db.otx_meta), POST /api/otx/sync (JWT-only — triggers manual resync). Scheduled task launched at startup runs first sync ~15s after boot then every 24h.
- Bulk "Save all flagged" (P0 done): IocBulkTable.jsx new isFlagged() helper (VT flagged>0 OR AbuseIPDB score>0 → captures both malicious and suspicious) + inferredSeverity() (critical for VT≥5 or Abuse≥75, high for VT≥1 or Abuse≥50, medium else). Admin-only red button (data-testid=`ioc-bulk-save-flagged`) shows count of flagged results; click groups values by inferred severity and POSTs to /api/iocs/bulk with source='IOC Analyzer (bulk save)' + tag 'analyzer-flagged'; success flash (`ioc-bulk-save-msg`).
- IOC Database admin panel new OTX sync bar (data-testid=`otx-sync-bar`): shows last-sync timestamp / added / updated / pulse count; "Sync now" button (data-testid=`otx-sync-btn`) triggers manual resync and refreshes the table/stats.
- Tests: iteration_18 (100% backend 7/7 + 100% frontend) — SOC dashboard + HA integration verified.

## Latest (2026-07-08, session 11)
- **Hybrid Analysis integration**: `HYBRID_ANALYSIS_API_KEY` in `.env`. Backend `_ha_hash_lookup` uses `/api/v2/overview/{sha256}` (v2.35+ replacement; SHA256 only, MD5/SHA1 return `{skipped:true}`). Uses non-www host `hybrid-analysis.com` (www 301-redirects and Cloudflare strips POST body). Also added `_ha_search_terms` (host/domain enrichment helper) and `_ha_quick_scan_url` (URL sandbox submission) — endpoint `POST /api/hybrid/quick-scan-url`. HA verdict badge added to `ReputationBadges.jsx` alongside VT + AbuseIPDB.
- **AbuseIPDB key rotated** in `.env`.
- **CrowdStrike-style Threat Intel Overview** at top of `/threat-intelligence`: dark gradient hero band ("Know your adversary. Stop the breach."), 4 big stat tiles, 4 module cards (Adversary Intel / Malware Analysis / Digital Risk / Curated IOC DB), 3 leaderboards (Top adversaries / Top families / Sources), Recent IOCs + Top active campaigns. Backend: `GET /api/threat-intel/overview` aggregates OTX-tagged IOCs.
- **Admin SOC Dashboard** (P1) — new default tab in `/admin`. Component `/app/frontend/src/components/SocDashboard.jsx`, backed by `GET /api/admin/overview` (JWT-protected). Shows: 4 KPIs (IOCs / open leads / threat reports / OTX last sync), IOC breakdown (severity + type progress bars), Lead pipeline (4 status counters + top malware families in DB), Recent leads / Recent IOCs / Integration health (6 providers with Connected/Not-configured badges), Latest threat reports grid. Includes Refresh button and cross-tab navigation via `nivx-admin-goto` custom events.

## Latest (2026-07-08, session 10)
- Deployed to production at https://nivxmachines.com. SEO overhaul: unique per-page titles + meta descriptions via new `useSeo` hook (`/app/frontend/src/lib/useSeo.js`), OG + Twitter Card tags in `index.html`, canonical to nivxmachines.com, `robots.txt` + `sitemap.xml` in `public/`, `noindex,nofollow` on `/admin`, `React.lazy` route code-splitting, client-side redirect from `*.emergent.host` → `nivxmachines.com` (in-head inline script).
- Hero redesigned: removed inline Mobile/Email chips (moved to Support/Contact only), added WhatsApp + Twitter/X + LinkedIn social icon pills (empty hrefs for later fill-in) + website URL row.
- **Hybrid Analysis integration** (session 11): `HYBRID_ANALYSIS_API_KEY` in `.env`. Backend `_ha_hash_lookup` uses `/api/v2/overview/{sha256}` (v2.35+ replacement for deprecated `/search/hash` — SHA256 only, MD5/SHA1 gracefully skipped). Returns verdict / threat_score / vx_family / classification / report URL. Integrated into `_reputation` (cached 6h). Frontend `haVerdict` helper + third badge in `ReputationBadges.jsx` (green/orange/red tones).
- **AbuseIPDB key rotated** to the new value in `.env`.
- **CrowdStrike-inspired Threat Intel Overview** (`/app/frontend/src/components/ThreatIntelOverview.jsx`) mounted at top of `/threat-intelligence`: dark gradient hero ("Know your adversary. Stop the breach.") with 4 big stat tiles (IOCs tracked, named adversaries, malware families, last OTX sync), 4 module cards (Adversary Intelligence / Malware Analysis / Digital Risk / Curated IOC DB), and 3 progress-bar columns for Top adversaries / Top malware families / Intelligence sources, plus Recent IOCs and Top active campaigns. Powered by new `GET /api/threat-intel/overview` endpoint aggregating `db.iocs` tags (`actor:*` / `family:*`), threat_name and source via Mongo aggregation pipelines.
- Threat Intelligence: type facets + date-range + pagination over ~395 Unit42 reports; in-app report reader (notes/refs/IOC table + copy-all).
- OSINT section: 5 tool quick-links + SMART IOC ANALYZER (/api/ioc-lookup): classifies hash/IP/domain/URL, live no-key enrichment (Shodan InternetDB + ip-api for IPs, urlscan search for domains/URLs), prefilled deep-links (VT/AbuseIPDB/Talos/urlscan/X-Force).
- Admin: Leads tab with status workflow (new/contacted/qualified/archived) + CSV export.
- Anti-spam on lead form (honeypot + IP rate limit 3/10min).
- Global scroll-to-top button (Lenis-aware, positioned to clear Emergent badge).
- Responsive verified (mobile 390 / tablet 820, no overflow). Tests: backend 24+7/… all pass; frontend 100%.
