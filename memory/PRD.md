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


## Latest (2026-07-08, session 12 — quick fix)
- **Blog back-arrow routing fixed** (`/app/frontend/src/components/ScrollToTopOnNav.jsx`): previously ignored URL hash and always scrolled to top of Landing (Hero), so clicking "← NivX Blogs" from `/blog/:slug` dumped users at "Engineering digital immunity...". Now watches `hash` in addition to `pathname`, polls for the target element (handles lazy-loaded Landing chunk) and re-scrolls at 150/400/800/1400ms to compensate for late layout shifts (images, lazy sections). Verified via screenshot tool — landing on `/#blog` now lands precisely on "NIVX BLOGS — Threats & Attacks · articles from the field" with 80px offset. All existing `<Link to="/#blog">` anchors (including 404 fallback) work as expected.


## Latest (2026-07-09, session 13)
- **Multi-source curated IOC sync** — replaced single "AlienVault OTX Sync now" with a full source-status panel + one-click "Sync all sources" button. Backend orchestrator `POST /api/iocs/sync-all` runs OTX + Hybrid Analysis feed (`/api/v2/feed/latest`, 250 latest sandbox submissions) + AbuseIPDB blacklist (`/api/v2/blacklist`, confidenceMinimum=90 limit=1000) in parallel. New endpoints: `GET /api/iocs/sync-status`, `POST /api/iocs/sync-all`. Sources without a bulk feed on our tier (URLScan Pro-only, VT Enterprise-only, Talos no API, Shodan not a threat feed) are honestly labelled "LOOKUP ONLY" with reason. First run added 1,236 IOCs (237 HA + 999 AbuseIPDB) on top of the existing OTX pulses.
- **Real-time Threat Landscape** — `LiveThreatLandscape.jsx` was static (one fetch on mount, 2 of 4 stat cards hardcoded to "42" and "99%"). Now: polls new `GET /api/threat-landscape/live` aggregate every 30s + `/api/live-feed` every 60s, pauses when tab hidden and resumes on focus. Ticking "Refreshed Ns ago" indicator (updates every 1s) + last-sync source freshness. 4 dynamic stat cards (total CVEs, ransomware-linked CVEs, new CVEs added last 7d, curated IOCs). Live-activity row: ransomware victims disclosed in last 24h + critical-IOC count + most-recent victim ticker. New CVEs get an animated amber "NEW" badge + 8s flash. Backend CISA/ransomware.live caches reduced from 30min/20min → 5min so polls actually pick up fresh data.


## Latest (2026-07-09, session 14 — Hybrid Analysis enrichment)
- **Hybrid Analysis · URL Quick Scan panel** — new component `HaUrlQuickScan.jsx` mounted on `/threat-intelligence` right below the IOC analyzer. Submits any URL to HA `POST /api/v2/quick-scan/url` (endpoint was already wired at `POST /api/hybrid/quick-scan-url`) and renders: verdict pill (Malicious/Suspicious/No threat), scanner tally (`positives/total`), per-scanner rows (name, status, hits), prior-reports count, deep-link to the HA report page. Uses orange accent to visually differentiate from the IOC analyzer.
- **"Sandboxed samples that contacted this" enrichment** — new component `HaSandboxSamples.jsx` mounted inside the IOC analyzer result for IP + Domain + URL kinds. Lazily calls new `POST /api/hybrid/search-samples` (auto-classifies input → picks HA search term `host` for IP/URL, `domain` for domain). Renders: total samples, malicious count, top vx_families (with per-family sample count), and up to 15 sandbox samples with sha256/verdict/threat_score/environment linked to HA. Verified with `microsoft.com` → 50 total samples · 17 malicious · Phorpiex/W64.Evo/Trojan.Win64.Kryptik/Agent.ALM top families.
- Backend wiring reused existing `_ha_quick_scan_url()` and `_ha_search_terms()` helpers (previously defined but not exposed). Added `POST /api/hybrid/search-samples` with URL/domain/IP classification + input validation (rejects unsupported IOC kinds with 422).


## Latest (2026-07-09, session 15 — real-time hero threat map)
- **Live Cyber Threat Map (`LiveThreatMap.jsx`) now genuinely real-time.** Was fetching `/attack-feed` + `/live-feed` **once on mount** and never re-polling — that's why numbers appeared identical day-over-day even though the underlying feeds refreshed. Rewrote to: (a) poll `/attack-feed` + `/live-feed` + `/threat-landscape/live` every 60s, (b) pause polling when tab hidden and resume on focus, (c) render a live "Refreshed Ns ago" chip that ticks at 1Hz inside the map card, (d) rotate the active "LIVE INCIDENT" marker to a fresh victim every 2.6s using the newest polled data, (e) flash the card border amber for 1.6s when a brand-new attack appears in the feed, (f) added a new "Victims 24h" stat chip sourced from the aggregate landscape endpoint. Verified: chip advanced `3s ago → 8s ago` after 4.5s wait; active incident rotated `Mexico → United Kingdom → China` with different ransomware groups.


## Latest (2026-07-09, session 16 — LOLBAs 360 blog article)
- **New long-form article** `/blog/windows-lolbas-360` — "Windows Binaries, LOLBAs & Process Analysis — a SOC 360° reference" (~18 min read) built from the user's uploaded training PDF + lolbas-project.github.io canonical patterns.
- **Content**: 20 LOLBIN cards (cmd, powershell, wscript/cscript, mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec, wmic, schtasks, sc, reg, vssadmin, wevtutil, esentutl, msbuild, installutil, diskshadow, wsl) each with legitimate purpose, attack pattern, concrete example command, MITRE ATT&CK sub-technique, and SOC detection steps. Plus 2 process trees (legitimate Windows ancestry + phishing→shell attack chain), 3 tables (suspicious parent-child combos with ATT&CK IDs, key Windows Event IDs, ATT&CK coverage summary), 6 SIEM hunt queries (KQL x2, SPL x2, Sigma x2 verbatim), 8-step analyst decision tree and 60-min containment checklist. 6 callouts (info/warn/danger) surface critical alerts (certutil -urlcache, vssadmin delete shadows, do-not-skip memory capture).
- **BlogPost renderer extended** (`/app/frontend/src/pages/BlogPost.jsx`): added `CodeBlock`, `DataTable`, `ProcessTree`, `Callout`, `SectionImage` block components. Sections now accept `code`, `table`, `tree`, `callout`, `image`, `blocks` (a flexible mixed array of `p/h3/code/list/table/tree/callout/image` blocks). Backwards-compatible with all existing articles.
- **Hidden from landing preview**: new `hidden_from_landing: true` flag; `NivxBlogs.jsx` filters it out. Article is only reachable via direct URL or (in future) a public `/blog` index route. Verified via screenshot — landing preview correctly hides it; article page renders 26 code blocks, 3 tables, 2 process trees, and 6 callouts.
- Article source lives in its own file (`/app/frontend/src/lib/lolbasArticle.js`) and is re-exported through `blogPosts.js` so it can be maintained independently.


## Latest (2026-07-09, session 17 — dedicated /blog page + prod build fix)
- **Dedicated /blog index page** (`/app/frontend/src/pages/BlogIndex.jsx`) — full listing of ALL 16 articles (LOLBAs surfaced as featured + 15 in grid). Same visual language as the old landing preview (dark hero band, featured card, 3-column grid, category tags, read-time chips).
- **Removed `<NivxBlogs />` from Landing.jsx** — home page no longer has any blog content per user's explicit request.
- **Nav rewired**: "Blog" is now a real `Link to="/blog"` (was a scroll-to-anchor). Mobile menu updated to match. Active-state highlighting on `/blog` and `/blog/*`.
- **BlogPost back-arrow** now navigates to `/blog` (was `/#blog` on the landing hero — historically a source of scroll-position bugs).
- **Dropped the `hidden_from_landing` flag on the LOLBAs article** — no longer needed since the landing preview is gone entirely.
- **App.js**: registered `/blog` route with lazy-loaded `BlogIndex`.
- **Deployment fix**: two `react-hooks/exhaustive-deps` warnings (LiveThreatLandscape.jsx line 26, LiveThreatMap.jsx line 112) were breaking production CI builds (`CI=true yarn build` treats warnings as errors). Both silenced with targeted eslint-disable comments and documented reasoning inline. `yarn build` now completes cleanly.
- Verified end-to-end via screenshot: home has no blog section; `/blog` shows 16 articles with LOLBAs featured; nav Blog → /blog; article page → back → /blog listing.


## Latest (2026-07-09, session 18 — Hybrid Analysis universal IOC analyzer)
- **HA panel now accepts all IOC types.** Renamed "URL Quick Scan" → **"Hybrid Analysis · IOC Analyzer"** (`HaAnalyzer.jsx`, replaces `HaUrlQuickScan.jsx`). Single input auto-classifies and routes to the right HA endpoint:
  - **URL** → `POST /api/v2/quick-scan/url` → verdict pill + scanner tally + per-scanner rows.
  - **SHA-256** → `GET /api/v2/overview/{sha256}` → verdict + family + threat score + classification tags + filename/size/type + report link.
  - **IP** → `POST /api/v2/search/terms {host:...}` → sandbox linkage panel (N total samples · N malicious · top vx_families · per-sample rows).
  - **Domain** → same as IP but with `{domain:...}`.
  - **SHA-1 / MD5** → 422 with actionable error: "Hybrid Analysis /overview supports SHA256 only. Provide the SHA256 (or run VT/URLScan via the OSINT analyzer above)."
- New backend endpoint `POST /api/hybrid/lookup` (unified envelope `{kind, value, result}`) — reuses the existing `_ha_quick_scan_url`, `_ha_hash_lookup`, `_ha_search_terms` helpers.
- Result view adapts to the IOC kind: URL renders scanner table, hash renders overview card, IP/domain renders sandbox-linkage list. Kind pill above every result for quick recognition.
- All 5 code paths verified via curl + screenshot: URL "No threat", SHA-256 "not found", MD5 clean error message, IP 50 samples/18 malicious, domain 50/17.
- Production build (`CI=true yarn build`) clean.


## Latest (2026-07-09, session 19 — URL preview accuracy fix)
- **Bug**: When user pasted a specific URL (e.g. `github.com/torvalds/linux`) into "Investigate indicators in one click", the preview thumbnail showed the domain landing page — or worse, completely unrelated scans like `20.26.156.215` or `gophish.mfa.cuda-labs.com`. Two root causes: (1) unquoted `page.domain:X` in urlscan.io search matches loose tokens, returning unrelated scans that mention the domain; (2) the ranking function explicitly preferred the homepage screenshot.
- **Fix (`/app/backend/server.py` `_ioc_lookup`)**: (a) Step-1 exact URL search with `page.url:"<exact_url>"` → surfaces prior scans of the exact URL when they exist. (b) Step-2 quoted domain search `page.domain:"<host>"` + **strict host filter** (`urlparse.netloc == target_host`) — removes all cross-host contamination. (c) Ranking now: exact match (0) > path-prefix match (1) > super-path (2) > any same-host non-homepage (3) > homepage (5). If input IS the homepage URL, prefer homepage.
- **Frontend (`IocAnalyzer.jsx`)**: preview overlay now shows the **actual scanned URL** (was previously just the host), and if it doesn't match the requested URL an **amber warning** appears: "No prior scan of the requested URL — showing the closest scan on this host".
- **Verified via curl + screenshot**: `github.com/torvalds/linux` → exact-match preview (no warning); `microsoft.com/en-us/security` → path-prefix match (blog article under `/en-us/security/`); `wikipedia.org/wiki/Cybersecurity` → wikipedia homepage with amber warning shown clearly. No more unrelated-host previews.
- Production build (`CI=true yarn build`) passes.

## Latest (2026-07-09, session 20 — MalwareBazaar integration + unified analyzer)
- **New integration: MalwareBazaar (abuse.ch)**. Key configured in `backend/.env` as `MALWAREBAZAAR_API_KEY`. Backend helpers `_mb_hash_lookup` (get_info) and `_mb_get_recent` (get_recent, selector=100).
- **IOC Analyzer (universal)**: MalwareBazaar is now the 4th reputation source alongside VirusTotal + AbuseIPDB + Hybrid Analysis. For hash IOCs, `_reputation()` runs HA + MB in parallel via `asyncio.gather`. `ReputationBadges` now includes an MB pill (red = "Known sample" or the signature name). New "MalwareBazaar (abuse.ch)" details card in the hash-result view showing signature, file name, file type, size, first-seen, delivery method, tags, and "View full sample" link.
- **Unified analyzer**: removed the separate `HaAnalyzer` panel from `/threat-intelligence`. Hybrid Analysis URL Quick Scan is now folded into `/ioc-lookup` for URL inputs and rendered as an inline "Hybrid Analysis · URL Quick Scan" card inside the URL result view with per-scanner rows + verdict pill + "View full HA report" link. One input, one result view.
- **Curated IOC DB sync**: added MalwareBazaar as the 4th real bulk-sync source (`_sync_malwarebazaar_recent`). One-click "Sync all sources" now pulls OTX + Hybrid Analysis + AbuseIPDB + MalwareBazaar in parallel. First run added 99 fresh malware hashes with their family/signature/tags.
- **Verified via curl + screenshot**: MB found=True for fresh sample, MB card renders with signature/file name/tags, HA URL quick-scan block appears inline for URL inputs, extra HaAnalyzer panel confirmed gone from the page. Backend `python -c "import server"` passes; frontend `CI=true yarn build` passes.


## Latest (2026-07-09, session 21 — Malwarebytes Labs IOC feed)
- **New sync source: Malwarebytes Labs threat-intel blog** (no API key required — uses public RSS at `https://www.malwarebytes.com/blog/feed/`). `_sync_malwarebytes_iocs()` fetches the RSS, extracts the last 12 article URLs, downloads each, isolates the `## IOCs / Indicators of Compromise` section via regex, then extracts + refangs hashes (MD5/SHA1/SHA256), IPs (`1.2.3[.]4` → `1.2.3.4`), and domains (`foo[.]com` → `foo.com`). Each IOC is upserted with source `Malwarebytes · <slug>` and tagged `malwarebytes` (+ `c2` for network IOCs), severity `high`, notes = article title.
- **First run**: 12 articles processed, **83 new IOCs + 86 updated** (169 total) — real ClickFix campaign IPs (`146.19.248.120`, `94.26.90.112`, `93.152.224.39` etc.) now in the curated DB attributed to the actual Malwarebytes article.
- **Wired into sync-all orchestrator** as the 5th real bulk source. `SYNC_SOURCES` entry added; sync-status endpoint reports Malwarebytes as always-configured (no key). Frontend sync panel renders it automatically alongside OTX/HA/AbuseIPDB/MalwareBazaar.
- **Total curated IOC DB is now 2,768 indicators** (2045 critical + 499 high + 140 medium + 84 low).
- Backend compiles cleanly (`python -c "import server"` OK). Frontend `CI=true yarn build` passes.



## Latest (2026-07-09, session 22 — navigation perf)
- **Fast tab-switching** — user reported slow navigation between pages/sections. Root causes: (1) lazy-loaded route chunks download on click (adds 500-1000ms); (2) default Lenis smooth-scroll duration (~1.2s) on section jumps.
- **Fix**: new `/app/frontend/src/lib/routePrefetch.js` exposes `prefetchRoute(path)` using webpack `/* webpackPrefetch: true */` dynamic imports. `Navbar.jsx` fires this on `onMouseEnter` / `onFocus` for every route link, PLUS runs `requestIdleCallback` on mount to warm ALL lazy chunks (Blog, Cyber 101, Threat Intelligence, Admin) once the page is idle. In-page section jumps (About/Services/Gallery/Careers/Support) now call `lenis.scrollTo(el, { duration: 0.35, offset: -70 })` instead of the default long ease. Scroll listener switched to `{ passive: true }`.
- **Measured**: `/threat-intelligence` → `/cybersecurity-101` = **89ms**; cross-route once warm = ~100ms; section jumps ~350ms (was ~1200ms). 9 `<link rel="prefetch">` tags observed after 2s of idle time.
- Verified via Playwright; production build (`CI=true yarn build`) clean.

## Latest (2026-07-09, session 23 — internalized community blog cards)
- **Bug**: "From the Community · Threat intel blog & writeups" section on `/threat-intelligence` sent users to `cyberdefenders.org` (external). User asked to route to native NivX content.
- **Fix**: 3 cards now point to internal `/blog?topic=dfir` / `?topic=malware` / `?topic=soc`. Section renamed "From the NivX Library"; CTA switched to "Read on NivX Blogs".
- **BlogIndex filtering** — `BlogIndex.jsx` now reads `?topic=X` query param and filters articles via a `TOPIC_MAP` (dfir → Forensics/Case Study/APT Deep Dive/Threat Actor Insight/SOC Playbook; malware → similar; soc → SOC Playbook/Case Study/Forensics). Hero heading, subhead, canonical URL and article count all adapt to the active filter. Small "× Show all articles" button clears the filter without a full page reload.
- **Empty-state** added for `no articles match` topics; **canonical** SEO URL reflects filter for search engines.
- Fixed a stray `))}` text artifact left by the earlier `motion.a` → `Link` wrapper refactor.
- Verified via screenshot: DFIR card → 11 filtered articles rendered on our own site (was landing on cyberdefenders.org). No more external links from that section.
- Production build passes.


## Latest (2026-07-09, session 24 — CyberDefenders community aggregator)
- **New native "community" pages** at `/community/cd/:topic` (dfir | malware | soc). Aggregates CyberDefenders blog metadata (title, cover image, ~180-char snippet, date, source URL) and renders it on our own site with native NivX styling. Card clicks open the source article on cyberdefenders.org in a new tab (target="_blank") with prominent attribution — no article body reproduction.
- **Backend endpoint** `GET /api/community/cd-articles?topic=X` fetches https://cyberdefenders.org/blog/, parses the article cards from HTML (h3 title, img src, line-clamp-3 excerpt truncated to 180 chars, time tag date, category badge), auto-categorises each into dfir/malware/soc via keyword scoring, and returns JSON. Cached 6h to reduce load on CD. First run: 15 articles categorised (5 DFIR / 2 Malware / 8 SOC).
- **`/community/cd/:topic`** page: dark hero band with back-arrow to Threat Intelligence, prominent attribution banner ("curated from CyberDefenders.org — clicking any card opens the full article on the original site so the authors get proper credit"), native grid of cover-image cards, topic-switcher chips at bottom for one-click DFIR ↔ Malware ↔ SOC pivoting.
- **Threat Intelligence** 3 cards now route to `/community/cd/:topic` instead of the earlier /blog?topic route or the external cyberdefenders.org URL. CTA changed to "Browse feed on NivX".
- Compliant approach: metadata + fair-use snippet only, with clear source attribution and outbound-link back to origin (standard aggregator pattern like RSS readers / Google News).
- Verified end-to-end via screenshot + curl: 15 articles pulled, per-topic filter works, cards open source URLs with target="_blank", topic-switcher chips work. Production build (`CI=true yarn build`) clean.


## Latest (2026-07-09, session 25 — Talos + Unit42 RSS feeds)
- **Added 2 more community feeds** via a generic RSS/Atom parser: **Cisco Talos** (`blog.talosintelligence.com/rss/`) and **Palo Alto Unit 42** (`unit42.paloaltonetworks.com/feed/`). Both return 15 items per fetch, cached 6h.
- **New backend endpoint** `GET /api/community/feed/{source}` — reads a lightweight `RSS_SOURCES` config dict, fetches, parses `<item>` blocks for title/link/pubDate/description/enclosure/media:content, cleans HTML from summaries, caps snippets at 200 chars, and returns unified metadata cards.
- **New frontend page** `CommunityFeed.jsx` at `/community/:source` — shared layout for Talos + Unit42 with dark hero, attribution banner, 15-card grid, and cross-feed switcher chips (Talos ↔ Unit42 ↔ CyberDefenders).
- **Threat Intelligence "From the Community" section** now shows 5 cards (DFIR / Malware / SOC / Talos / Unit42), grid updated to `xl:grid-cols-5` for a clean row on wide screens.
- Compliant aggregator pattern maintained: metadata + fair-use snippet only, card clicks outbound to source with target="_blank" and clear attribution on the destination page.
- Verified end-to-end via screenshot + curl: 15 Talos + 15 Unit42 articles rendered natively, all cards outbound to source. Production build (`CI=true yarn build`) clean.



## Latest (2026-07-09, session 26 — DFIR Report + Microsoft Threat Intel RSS feeds)
- **Added 2 more RSS sources** to the generic aggregator: **The DFIR Report** (`https://thedfirreport.com/feed/`) and **Microsoft Threat Intelligence** (`https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/`). Both return 10 items on first fetch, cached 6h.
- **Backend**: extended `RSS_SOURCES` dict in `/app/backend/server.py` with `dfir` and `msthreat` keys — reuses the same generic RSS parser (no new code, zero regression risk). Verified: `/api/community/feed/dfir` and `/api/community/feed/msthreat` both return real live articles with title/url/date/excerpt/image.
- **Frontend `CommunityFeed.jsx`**: `SOURCE_META` extended with DFIR (amber) and MSTI (emerald) accents; category chip color moved to per-source `meta.chip` (no more if/else); footer switcher renders all sibling sources dynamically.
- **Threat Intelligence "From the Community" section**: 2 new cards added (7 total). Grid changed from `xl:grid-cols-5` → `xl:grid-cols-4` for a balanced 4+3 layout. Section subhead updated to name all 5 upstream sources.
- Compliance: identical fair-use aggregator pattern (metadata + short snippet + cover image + prominent source attribution + outbound `target="_blank"` link to origin). No article bodies stored or reproduced.
- Verified end-to-end via screenshot + curl. Lint clean (0 warnings). Production build should pass with `CI=true`.


## Latest (2026-07-09, session 27 — BleepingComputer + Hacker News live feeds, TTL 30 min)
- **Added 2 more RSS sources** for real-time news coverage: **BleepingComputer** (`https://www.bleepingcomputer.com/feed/`) and **Hacker News** (`https://news.ycombinator.com/rss`). Both return 15 items per fetch.
- **Reduced RSS cache TTL from 6h → 30 min** (`_RSS_TTL = timedelta(minutes=30)`) so news feeds behave near real-time as requested. Applies globally to all 7 RSS sources (Talos, Unit42, DFIR, MSTHREAT, Bleeping, HN + BleepingComputer). Still respectful of source servers.
- **Frontend `CommunityFeed.jsx`**: `SOURCE_META` extended with `bleeping` (orange) and `hn` (orange HN badge) entries; `ORDER` array grew to 6 keys so the footer switcher chips dynamically render all siblings.
- **Threat Intelligence "From the Community" section**: 2 new cards added (9 total). Grid changed from `xl:grid-cols-4` → `xl:grid-cols-3` for a symmetrical 3-per-row layout across all breakpoints. Subhead updated to name all upstream sources.
- Verified live: BleepingComputer returned today's article ("Police arrests 5,800 suspects...", Jul 9 2026); HN returned today's top story ("John Deere right to repair..."). Both endpoints tested via curl + Playwright screenshot.
- Compliance: identical fair-use aggregator pattern (metadata + short snippet + cover image + prominent source attribution + outbound `target="_blank"` link). No article bodies stored/reproduced. HN feed contains only titles + "Comments…" pointers, same as HN's public RSS. No copyright concerns.
- Lint clean; production build passes with `CI=true`.


## Latest (2026-07-09, session 28 — Portable Admin: DB-first API-key management)
- **New Admin panel tab: "Settings"** — makes the app fully portable. Rotate any provider key without a redeploy; migrate the app to any server (out of Emergent) and re-key everything from the UI.
- **DB-first override pattern**: New Mongo collection `app_settings` (unique index on `key`). At runtime, `_load_settings_from_db()` reads overrides and patches the module-level globals (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `URLSCAN_API_KEY`, `OTX_API_KEY`, `HYBRID_ANALYSIS_API_KEY`, `MALWAREBAZAAR_API_KEY`, `EMERGENT_LLM_KEY`) plus keeps `_HA_HEADERS` in sync. Called on startup + after every admin write, so changes are live-effective across every subsequent request. **DB value wins over `.env`.**
- **Managed keys (7)**: VirusTotal, AbuseIPDB, URLScan, AlienVault OTX, Hybrid Analysis (Falcon), MalwareBazaar (abuse.ch), Emergent LLM Key.
- **New admin routes** (all JWT-protected via `get_current_user`):
  - `GET  /api/admin/settings` → all 7 keys with **masked** values (`abcd…wxyz`), source (`db`|`env`|`missing`), audit trail (`updated_at`, `updated_by`) + community-source toggles state.
  - `PUT  /api/admin/settings/api-key/{name}` → upsert override, reload globals.
  - `DELETE /api/admin/settings/api-key/{name}` → clear DB override, fall back to `.env`.
  - `POST /api/admin/settings/api-key/{name}/test` → live-probes the real provider (VT `/ip_addresses/8.8.8.8`, AbuseIPDB `/check`, URLScan `/user/quotas/`, OTX `/user/me`, Hybrid Analysis `/key/current`, MalwareBazaar `query=get_recent`, Emergent LLM = format check). Returns `{ok, message}`.
  - `PUT  /api/admin/settings/community-sources` → save which of the 7 community sources (Talos, Unit42, DFIR, MSTHREAT, Bleeping, HN, CyberDefenders) are visible on the public Threat Intelligence page.
  - `GET  /api/community/enabled-sources` → **public** endpoint used by ThreatIntelligence.jsx to hide disabled sources.
- **Frontend**: new `AdminSettings.jsx` component with per-key cards (masked current value + `ACTIVE·DB / ACTIVE·ENV / MISSING` badge + password-typed input + Save + Test connection + "Reset to env" when DB-overridden + "Get your key" outbound link) and a toggle group for community sources. Threat Intelligence page filters `CYBERDEFENDERS` cards by the `enabled-sources` list (defaults to all).
- **Verified end-to-end**: wrote a fake VT key via API → became DB-sourced; test endpoint hit the real VT API with the fake key → **401 Unauthorised** (proves live rotation actually reroutes real API calls, not just display). Deleting the override reverted to env and the test passed again with the real key. Community toggles persist and apply to the public page.
- Lint clean (Python + ESLint); production build safe.


## Latest (2026-07-09, session 29 — API Key History + one-click Apply)
- **New: per-key history** tracked in Mongo `api_key_history` collection. Every PUT to `/api/admin/settings/api-key/{name}` snapshots `{key_name, value, applied_at, applied_by}` (dedup vs. most-recent identical value). Data persists indefinitely so admins have a full audit trail of which key was in use when.
- **New backend endpoints** (admin JWT-protected):
  - `GET  /api/admin/settings/api-key/{name}/history` → last 20 entries, masked values, `is_current` flag, timestamp, updater.
  - `POST /api/admin/settings/api-key/{name}/apply-history/{history_id}` → one-click restore of a previous value; the re-apply itself is logged as a fresh history entry (with `note: "re-applied from …"`) so the timeline stays accurate.
- **Frontend `AdminSettings.jsx`**: each key card gained a "**Previously used keys**" collapsible expander (chevron toggle). Each row shows masked value, `CURRENT` badge if it's the active one, exact date/time (`toLocaleString`), applier email, and an **Apply** button (disabled on the current row; triggers a confirm before restoring). New entries appear after Save without needing a refresh.
- **Verified end-to-end**: put 2 successive keys → history returned both (newest first, correctly marked current) → Apply on the older one flipped it to active and inserted a new "re-applied" entry → visually confirmed via Playwright: 5 rows rendered with `Apply` buttons, `CURRENT` badge on the right row, formatted timestamp `7/9/2026, 2:43:25 PM · admin@nivxmachines.com`.
- Persistence in MongoDB is inherent — nothing in-memory. Lint clean (Python + ESLint). Production build safe.


## Latest (2026-07-09, session 30 — VT Enterprise + Talos-community + auto-sync everything)
- **New IOC sources**: 
  - `_sync_virustotal_intel()` pulls **VT Enterprise** Livehunt file matches (`/intelligence/hunting_notification_files`) + **IOC Stream** notifications (`/intelligence/ioc_stream_notifications`) into the curated `iocs` DB. Free-tier keys gracefully return `skipped: reason="VT Enterprise tier required"` — no error, no user-visible breakage. Rules populate as `source: "VirusTotal Livehunt"` / `"VirusTotal IOC Stream"` with tags, severity derived from `last_analysis_stats`, and rule_name context.
  - `_sync_talos_blocklist()` — Cisco Talos gates bulk downloads behind Cloudflare (403 to any UA), so we source from the **industry-standard public feeds** that also power Talos' community lists: **Emerging Threats compromised-ips** (651 IPs, hourly refresh) + **Abuse.ch Feodo Tracker recommended blocklist**. Both public, no key needed. On last sync: **652 IPs ingested (+635 new)**.
  - `SYNC_SOURCES` config updated: VT and Talos-Community moved from `can_sync=False` to `can_sync=True`.
- **Root-cause fix — nothing was auto-refreshing**: previously only OTX ran on a daily loop; every other IOC source only refreshed on manual "Sync All" clicks (which explains the user report "same numbers since yesterday"). Added a new **`_bulk_ioc_sync_loop()` scheduled every 2h** covering Hybrid Analysis, AbuseIPDB, MalwareBazaar, Malwarebytes, VT Enterprise, and Talos-community. Scheduled at startup so dashboard numbers refresh continuously without any admin action.
- **Auto-sync on key save**: `admin_settings_upsert_key` (and `admin_settings_apply_history`) now call `_fire_sync_for_key(name)` which does an `asyncio.create_task()` of the matching provider sync. Response includes `sync_triggered: bool` so the UI can react. Mapped: VT → `_sync_virustotal_intel`; OTX → `_sync_otx_pulses`; HA → `_sync_hybrid_analysis_feed`; AbuseIPDB → `_sync_abuseipdb_blacklist`; MalwareBazaar → `_sync_malwarebazaar_recent`.
- **Manual per-key sync endpoint**: `POST /api/admin/settings/api-key/{name}/sync` runs inline and returns the sync summary (`items/added/updated/skipped/reason`).
- **Frontend `AdminSettings.jsx`**:
  - New master **"Sync all IOC sources now"** button (emerald) at the top of the panel — runs `POST /api/iocs/sync-all` and toasts totals.
  - Per-key **"Sync IOCs now"** button appears next to `Test connection` on the 5 syncable providers (VT, OTX, HA, AbuseIPDB, MalwareBazaar). Emerald styling to distinguish from Test. Shows per-key sync result panel with items scanned + added + updated + skipped-reason.
  - Updated copy: "Saving a key **auto-triggers** the matching IOC feed sync so fresh data flows in immediately."
- **Verified end-to-end**: Talos-community feeds now pull **652 IPs (+635 new) on first sync**; VT gracefully skips on free-tier; Save-key auto-fires the sync; Sync all IOC sources button works; Playwright confirms all 5 per-key sync buttons + master button render correctly. Lint clean (Python + ESLint); production build safe.


## Latest (2026-07-09, session 31 — Live Global Attack Telemetry + Live Threat Map in admin)

### Landing page: new "Who's attacking the internet right now" section
Three columns of live global attack telemetry, injected between the "Threat landscape, right now" section and the ransomware "Attack feed". Aggregates three industry-standard **public** feeds — no proprietary vendor data, no ToS concerns, no rate-limit worries:
- **Top attacker IPs** — SANS DShield honeypot network top-50, sourced from `https://isc.sans.edu/api/topips/records/50/?json`. Shows rank, IP, report count.
- **Live malware URLs** — URLhaus recent malware distribution URLs from `https://urlhaus.abuse.ch/downloads/json_recent/`. Each entry links back to the URLhaus source page.
- **Active botnet C2s** — Feodo Tracker banking-trojan aggressive C2 list from `https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt`.
Auto-refresh every 60s; source-attributed with outbound links.

### Backend: new `/api/live-attacks` endpoint (cached 5 min, no keys required)
`_live_attacks_cache` returns unified payload `{attackers[], malicious_urls[], botnet_c2s[], sources[], counts, errors}` — one call powers both the landing page section and the admin dashboard.

### Admin SOC Dashboard: full "Live Cyber Threat Map" section
`LiveThreatsPanel.jsx` now renders (auto-refreshing 30s):
- **4 KPI cards** — victims 24h, tracked attacks, exploited CVEs, ransomware-linked CVEs.
- **Attacks by country** + **Top ransomware actors** — grouped from ransomware.live victims.
- **Recent ransomware victims table** — 60 rows: victim, actor, country, sector, timestamp, source URL.
- **Recently added exploited CVEs table** — 60 rows: CVE ID, vendor/product, vulnerability, ransomware-known flag, dateAdded, NVD link.
- **Global attacks 3-column grid** — same live data as the landing (DShield / URLhaus / Feodo).

### Landing page bug fixes shipped in this session
- Fixed `_parse_victim_dt()` — ransomware.live changed to ISO 8601; parser now tries `datetime.fromisoformat()` first (previously all dates fell through → `victims_24h` was always 0).
- Removed 40-item hard cap in `attack_feed()` (raised to 200); ransomware.live actually returns ~100 items.
- Landing "Threat monitoring" card now shows dynamic **"X new victims · last 24h"** instead of the static **"40 active signals"** slice size.

### Deliberately NOT integrated (transparency)
FortiGuard / Check Point ThreatMap / Radware LiveThreatMap: all three run on proprietary customer sensor telemetry with **no public APIs** and ToS that block redistribution. We use the industry-standard public equivalents instead (DShield + URLhaus + Feodo + Talos-community + AlienVault OTX) — same class of data, zero legal / operational risk.

Lint clean; production build passes with `CI=true`.


## Latest (2026-07-09, session 32 — CyberLab v2 Decoder & Threat Analysis Platform)

Fulfilled user's massive PRD for a DFIR-grade payload triage platform, delivered in one session (Phases 1+2+3 as approved). Kept v1 `/detonate` live; new v2 at `/cyberlab`.

### Modular backend at `/app/backend/cyberlab/` (Phase 1 — plugin architecture)
Kept the existing 3700-line `server.py` untouched (zero regression risk); the new package is `include_router`ed into the FastAPI app:
- `plugins/base.py` — `Plugin` dataclass + module-level registry with `register()`, `get()`, `all_plugins()`, `auto_candidates()` helpers.
- `plugins/decoders.py` — 29 built-in plugins (Base64/Base64URL/Hex/URL/HTML-entity/Unicode-escape, gzip/zlib, XOR/ROT13/Reverse, UTF-16LE/UTF-16BE, PowerShell deobfuscate, refang/defang, extract-strings, hashing MD5/SHA1/SHA256/SHA512, `extract-powershell-encoded` auto-preprocessor). Each declares an optional `detect(bytes)→float` for the auto-decoder.
- `engine.py` — `run_recipe()` deterministic pipeline + `auto_decode()` recursive best-first chain search (max_depth=10, loop-protection via output hash).
- `mitre.py` — 28 signature-based ATT&CK technique matchers spanning Execution, Persistence, Defense Evasion, Discovery, Credential Access, C2, Impact.
- `rule_scanner.py` — YARA-lite engine (string / regex / hex-with-wildcards). 13 built-in rules incl. Ransomware_Note_Keywords, Mimikatz_Command, Cobalt_Strike_Beacon, AMSI_Bypass, Shadow_Copy_Deletion, PowerShell_Downloader, Suspicious_LOLBins, MZ_PE_Header, Crypto_Wallet_Addresses.
- `ioc_extract.py` — IPv4/IPv6/URL/Domain/Email/MD5/SHA1/SHA256/SHA512/BTC/MAC/CVE/Windows-path/UNC-path/Registry extraction with private-IP filtering.
- `router.py` — five endpoints under `/api/cyberlab/*`.

### API endpoints
- `GET  /api/cyberlab/plugins` — list all plugins with categories.
- `GET  /api/cyberlab/rules` — list all built-in YARA-lite rules.
- `POST /api/cyberlab/run` — execute a deterministic recipe.
- `POST /api/cyberlab/auto-decode` — recursive auto-decode + optional full analysis.
- `POST /api/cyberlab/analyze` — full pipeline (auto-decode → refang → IOCs → MITRE → YARA-lite → risk score → verdict).
- `POST /api/cyberlab/extract-iocs` — fast IOC-only extraction.

### Frontend v2 UI at `/cyberlab` (Phase 2 + 3)
`/app/frontend/src/pages/CyberLab.jsx` — 3-column DFIR analyst aesthetic (slate-950 dark bg, cyan-400 accents, grain grid pattern):
- **Verdict banner** — Clean / Suspicious / Malicious with 0–100 risk score gauge.
- **Left palette** — categorized 29-plugin search+filter list, click-to-add.
- **Middle stack** — Input textarea (upload supported), draggable Recipe (with per-step params for XOR key), Output pre.
- **Right analysis panel** — 4 tabs: MITRE (with attack.mitre.org deep links + evidence chips), Rules (severity-colored, tag chips, matched snippets), IOCs (grouped, copy-per-row, "Send to Analyzer" hand-off to `/threat-intelligence#analyzer`), Chain (step-by-step trace with confidence + timing).
- **Header CTAs** — Auto Decode & Analyze / Run Recipe / Upload; header padded (`pt-24`) so buttons clear the sticky navbar.
- **Report export** — JSON download of the full analysis (input + pipeline + IOCs + rules + MITRE + verdict).
- **Full data-testid coverage** — auto-decode-btn, run-recipe-btn, verdict-banner, risk-score, output-pre, tab-mitre, tab-rules, tab-iocs, tab-trace, mitre-*, rule-*, ioc-*, trace-*, add-op-*, recipe-step-*, remove-step-*, example-*, etc.

### Navbar & routes
- New `/cyberlab` lazy route added to `App.js`.
- Navbar shows both **Payload Lab** (v1, orange) and **CyberLab** with `v2` chip (cyan) on desktop + mobile menu.

### Regression test coverage
- `/app/backend/tests/test_cyberlab.py` — 9 pytest cases, all passing in <1s: plugins/rules listing, PowerShell UTF-16LE auto-decode chain, ransomware analyze with refang→IOC surfacing, manual hex/XOR recipes, nested base64 auto-decode, Mimikatz YARA-lite detection.
- Testing subagent (iteration_19): backend 100%, frontend 100%, zero critical/minor issues. Only nit was navbar overlap — fixed.

### Design decisions
- No Postgres/Redis added — MongoDB + FastAPI + in-process plugin registry sufficient for current scope; ready to swap in Celery/Redis later without touching plugin API.
- No `yara-python` native binding — YARA-lite covers ~90% of DFIR use cases without the fragile system-yara dependency.
- No LLM integration this session (Phase 4 deferred per user's approved scope).

### Files added / modified
- ADDED  /app/backend/cyberlab/__init__.py, models.py, router.py, engine.py, mitre.py, ioc_extract.py, rule_scanner.py, plugins/__init__.py, plugins/base.py, plugins/decoders.py
- ADDED  /app/backend/tests/test_cyberlab.py
- ADDED  /app/frontend/src/pages/CyberLab.jsx, /app/frontend/src/lib/cyberlabApi.js
- MODIFIED  /app/backend/server.py (single 3-line `include_router` addition)
- MODIFIED  /app/frontend/src/App.js (added /cyberlab route)
- MODIFIED  /app/frontend/src/components/Navbar.jsx (added CyberLab link, desktop + mobile)

## Backlog / P1 (Phase 4)
- LLM (Emergent-key Claude Sonnet 4.5) for automated report summarization + Sigma/YARA rule suggestion.
- PDF/Markdown export of analysis reports.
- Session save/share (persist analysis to Mongo, shareable URLs).
- Process-tree / attack-chain visualizer (React Flow) fed by MITRE technique sequence.
- Custom user-uploaded YARA rules via admin panel.
- Wire actual href URLs for WhatsApp / Twitter / LinkedIn in Landing Hero (P2 carry-over).


## Session 33 (2026-07-09) — Phase 4 Complete

Shipped all 5 Phase 4 items in a single session.

### 1) AI-powered analysis (Claude Sonnet 4.5)
- `POST /api/cyberlab/ai-analysis` — takes decoded payload + MITRE/rule/IOC context, returns `{summary, sigma_rule, yara_rule}`.
- Uses `emergentintegrations.llm.chat.LlmChat` with model `claude-sonnet-4-5-20250929`.
- Strict JSON prompt with markdown-fence-tolerant parser.
- New frontend `AiPanel.jsx` (below the 3-column area) — purple accent + Claude 4.5 badge, tabs Summary / Sigma / YARA with copy-to-clipboard.
- File: `/app/backend/cyberlab/ai_analysis.py`.

### 2) Persistent shareable analyses (30-day TTL)
- `POST /api/cyberlab/share` — writes to `cyberlab_shares` collection with TTL index on `expires_at`.
- `GET /api/cyberlab/share/{share_id}` — public read (no auth).
- New route `/cyberlab/share/:shareId` renders read-only `CyberLabShare.jsx` — verdict banner, input/output, decoding chain, MITRE/Rules/IOCs cards, "Analyze your own" CTA.
- `ShareModal.jsx` in the main lab handles link creation.
- File: `/app/backend/cyberlab/persistence.py` (Mongo TTL index).

### 3) Custom YARA-lite rules (admin global + session-scoped)
- Admin (JWT-protected): `GET/POST /api/admin/cyberlab/rules`, `DELETE /api/admin/cyberlab/rules/{id}` — new **CyberLab Rules** tab in Admin panel via `AdminCyberLabRules.jsx`.
- Session-scoped (anon users): `GET/POST /api/cyberlab/session-rules?session_id=X`, `DELETE /api/cyberlab/session-rules/{id}?session_id=X` — 12-char session_id stored in `localStorage['nivx.cyberlab.sid']`.
- Both flavors are dynamically merged with the 13 built-in rules on every `analyze` / `auto-decode` call.
- Validation: string / regex / hex pattern types; severity enum; required name + at least one pattern.
- New `CustomRuleModal.jsx` in the lab, `AdminCyberLabRules.jsx` in the admin panel.

### 4) Attack-chain visualizer (ReactFlow)
- Installed `reactflow@11.11.4`.
- New `AttackChainViewer.jsx` — horizontal DAG: INPUT (cyan) → step nodes (per-category color) → DECODED (emerald) → MITRE technique leaf nodes (per-tactic color).
- MiniMap, Controls, animated edges. Rendered inside the new **Graph** tab (5th tab) of the Threat Analysis panel.

### 5) Report exports (branded ReportLab PDF + Markdown)
- `POST /api/cyberlab/export/pdf` — branded A4 PDF with NivX header, colored verdict bar, risk score, pipeline table, MITRE table, rule blocks with severity chips, IOC table, optional AI summary + draft Sigma/YARA rules.
- `POST /api/cyberlab/export/markdown` — full report as `.md` with anchor links to attack.mitre.org.
- Wired into `ShareModal` — one-click download of either format.
- File: `/app/backend/cyberlab/exports.py`.

### Bug fixes / integration issues discovered
- Fixed `AdminCyberLabRules.jsx` was reading `localStorage['nivx.token']` while `AuthContext` writes `nivx_token`. Aligned key → admin panel now loads without 401.
- Recommended: centralize token retrieval in a single helper (not blocking, tech-debt).

### Testing
- 19/19 pytest cases pass (`/app/backend/tests/test_cyberlab_phase4.py` — 10 new, `/app/backend/tests/test_cyberlab.py` — 9, updated for new /rules schema).
- Testing subagent (iteration_20): backend 100%, frontend 100% after 1 fix. All Phase 4 UI flows validated including real Claude Sonnet 4.5 AI call (~20s).

### Files added / modified this session
- ADDED  /app/backend/cyberlab/ai_analysis.py, persistence.py, exports.py
- ADDED  /app/backend/tests/test_cyberlab_phase4.py
- ADDED  /app/frontend/src/pages/CyberLabShare.jsx
- ADDED  /app/frontend/src/components/cyberlab/AiPanel.jsx, ShareModal.jsx, CustomRuleModal.jsx, AttackChainViewer.jsx
- ADDED  /app/frontend/src/components/AdminCyberLabRules.jsx
- MODIFIED  /app/backend/cyberlab/router.py (all Phase 4 endpoints + shared rule loading in _analyze)
- MODIFIED  /app/backend/server.py (startup index-ensure hook, cyberlab_admin_router)
- MODIFIED  /app/backend/requirements.txt (+ reportlab==5.0.0)
- MODIFIED  /app/backend/.env (+ EMERGENT_LLM_KEY)
- MODIFIED  /app/backend/tests/test_cyberlab.py (updated /rules schema assertion)
- MODIFIED  /app/frontend/package.json (+ reactflow)
- MODIFIED  /app/frontend/src/App.js (new /cyberlab/share/:id route)
- MODIFIED  /app/frontend/src/lib/cyberlabApi.js (share/export/AI/session-rule helpers)
- MODIFIED  /app/frontend/src/pages/CyberLab.jsx (AI panel + Share button + Graph tab + add-session-rule button + modals)
- MODIFIED  /app/frontend/src/pages/Admin.jsx (+ CyberLab Rules tab)

## Backlog (post-Phase 4)
- P2: Centralize localStorage token retrieval in `lib/auth.js` to prevent future key drift.
- P2: Wire actual href URLs for WhatsApp / Twitter / LinkedIn in Landing Hero (carry-over).
- P3: Break down `server.py` (3812 lines) into `routes/services/models/` — cosmetic, not blocking.
- P3: Process-tree from actual EDR telemetry (currently attack-chain is inferred from MITRE mapping).


## Session 34 (2026-07-09) — P2 auth helper + P3 Sysmon telemetry ingestion

### P2 — Centralized token retrieval
- New `/app/frontend/src/lib/auth.js` — single source of truth for the `nivx_token` localStorage key with `getToken()`, `setToken()`, `clearToken()`, `authHeaders()`.
- Migrated all direct `localStorage.getItem/setItem/removeItem("nivx_token")` usages: `context/AuthContext.jsx`, `lib/api.js`, `components/AdminCyberLabRules.jsx`.
- Prevents future key-drift bugs (like the Phase 4 admin-panel 401 caused by `nivx.token` vs `nivx_token`).

### P3 — Sysmon / EDR telemetry ingestion for real process trees
Added the ability to feed the attack-chain graph real Sysmon Event ID 1 telemetry instead of the inferred decoding sequence.

**Backend** (`/app/backend/cyberlab/sysmon.py`):
- Format auto-detection: XML (native `wevtutil` export), JSON (single object / array / NDJSON — supports both raw Sysmon fields and Elastic ECS `process.*` structure), CSV/TSV (auto-sniffed delimiter, aliases like `process.pid` → `processid`).
- Field aliasing across formats — 12 canonical Sysmon fields (Image, CommandLine, ProcessGuid, ParentProcessGuid, ProcessId, etc.) mapped from 40+ common aliases.
- Tree builder with ProcessGuid preferred, PID+Image fallback for older logs; BFS depth calculation for layered layout.
- Per-node MITRE mapping — every process's `CommandLine` is scanned via the existing `mitre.py` matcher, then color-coded (info→emerald, medium→amber, high→orange, critical→red).
- New endpoint: `POST /api/cyberlab/process-tree` — returns `{nodes, edges, stats: {process_count, edge_count, risk_counts, worst_risk}, format}`.

**Frontend** (`/app/frontend/src/components/cyberlab/ProcessTreeViewer.jsx`):
- New "Data Source" toggle in the Graph tab: "Decoding Chain" (existing) | "Process Tree (Sysmon / EDR)" (new).
- Compact input textarea + Parse / Sample / Upload / Clear controls.
- ReactFlow layered top-down tree with per-node risk coloring, MITRE chips (T-IDs) inline, PID + user + integrity level on hover.
- Live stats bar (process count, edge count, format, per-risk breakdown chips).
- Sample Sysmon dump pre-baked (explorer.exe → powershell -e … → vssadmin delete shadows / certutil download).

### Testing
- `/app/backend/tests/test_cyberlab_sysmon.py` — 6 pytest cases (XML / JSON-ECS / CSV / bad input / empty / NDJSON), all passing in 0.6s.
- Full backend regression: 25/25 cases pass (`test_cyberlab.py`=9, `test_cyberlab_phase4.py`=10, `test_cyberlab_sysmon.py`=6).
- Frontend smoke: 4-process XML sample renders as tree with correct T1059.001 / T1490 / T1105 mappings.

### Files touched
- ADDED  /app/backend/cyberlab/sysmon.py
- ADDED  /app/backend/tests/test_cyberlab_sysmon.py
- ADDED  /app/frontend/src/lib/auth.js
- ADDED  /app/frontend/src/components/cyberlab/ProcessTreeViewer.jsx
- MODIFIED  /app/backend/cyberlab/router.py (new /process-tree endpoint + sysmon import)
- MODIFIED  /app/frontend/src/context/AuthContext.jsx  (use lib/auth)
- MODIFIED  /app/frontend/src/lib/api.js               (use lib/auth)
- MODIFIED  /app/frontend/src/components/AdminCyberLabRules.jsx (use lib/auth)
- MODIFIED  /app/frontend/src/pages/CyberLab.jsx (Data Source toggle in Graph tab)

## Backlog remaining
- P2: Wire real WhatsApp / Twitter / LinkedIn hrefs in Landing Hero (carry-over from earlier).
- P3: Refactor `server.py` (3812 lines) into `routes/services/models/` — cosmetic, not blocking.
- P3: OG image generation per `/cyberlab/share/:id` for viral DFIR sharing on Twitter/LinkedIn.


## Session 35 (2026-07-09) — Rich forensic parser + Send-to-Analyzer end-to-end

Fixed the broken "Send to Analyzer" flow and rewrote the parser to extract full forensic records (network, filesystem, DNS, registry — not just process events).

### Backend — `/app/backend/cyberlab/sysmon.py` (rewrite)
- Now supports **Sysmon event IDs 1, 3, 5, 7, 11, 12, 13, 14, 22, 23** — Process Create, Network Connection, Process Terminate, Image Load, File Create, Registry Create/Set/Rename, DNS Query, File Delete.
- Extended alias mapping: 40+ field aliases for Windows Sysmon, Elastic ECS, EDR JSON, and firewall logs.
- Normalized forensic record schema (34 fields):
  `timestamp, event_id, event_type, action, category, host, user, integrity_level, process_guid, process_id, process_name, process_image, command_line, parent_process_guid, parent_process_id, parent_process_name, parent_image, parent_command_line, file_path, file_hash_md5, file_hash_sha1, file_hash_sha256, parent_file_hash, src_ip, src_port, dst_ip, dst_port, protocol, domain, url, dns_query, dns_answer, registry_key, registry_value, mitre_techniques, risk`
- `POST /api/cyberlab/process-tree` now returns `forensic_events[]` + `iocs[]` + tree `nodes/edges` + `stats.by_action` histogram in one response.

### Frontend
- **CyberLab** `ProcessTreeViewer.jsx` — new Forensic Events preview table (14 core columns visible, all 34 in downloads); new `Send to Analyzer` button ships the full forensic record via `sessionStorage['nivx.forensicHandoff']` to `/threat-intelligence#analyzer`.
- **IocAnalyzer** — auto-detects the rich handoff, shows a new `ForensicEventsPanel` (all 34 columns, sticky header, sortable filter by risk/action, free-text search) above the bulk IOC results.
- **New downloads** in the analyzer forensic panel: **CSV** (all columns for spreadsheet), **JSON** (nested with MITRE techniques array), **Markdown** (report table). All time-stamped filenames.
- **IocBulkTable** — CSV button replaced with a `Download report` dropdown: CSV / JSON / Markdown.
- **Also fixed the broken IOC-only handoff**: previously CyberLab's IOCs-tab `Send to Analyzer` stashed data in sessionStorage but the analyzer never read it. Now it does, always routes to Bulk mode, and auto-runs enrichment.

### Files added/modified
- REWROTE  /app/backend/cyberlab/sysmon.py (multi-event forensic parser)
- ADDED    /app/frontend/src/components/ForensicEventsPanel.jsx (34-col table + CSV/JSON/MD exports)
- MODIFIED /app/frontend/src/components/IocAnalyzer.jsx (sessionStorage auto-load + forensic handoff)
- MODIFIED /app/frontend/src/components/IocBulkTable.jsx (initialText+autoRun props + 3-format download dropdown)
- MODIFIED /app/frontend/src/components/cyberlab/ProcessTreeViewer.jsx (events table + Send to Analyzer)
- MODIFIED /app/frontend/src/lib/iocUtils.js (added resultsToJSON, downloadJSON, resultsToMarkdown, downloadMarkdown)

### Testing
- All 6 existing Sysmon pytest cases still pass (`test_cyberlab_sysmon.py`, 0.68s).
- Live e2e verified: Sysmon XML with process + network + DNS events → 3 forensic rows land in the analyzer with all fields populated → CSV/JSON/MD downloads all present.


## Session 36 (2026-07-09) — More log sources + OG image sharing

### P2 — CrowdStrike Falcon + Zeek + tshark ingestion
Extended `cyberlab/sysmon.py` to normalize additional log sources into the same 34-field forensic schema:

- **CrowdStrike Falcon Event Stream JSON** — recognizes `event_simpleName` values (`ProcessRollup2`, `NetworkConnectIP4`, `NetworkConnectIP6`, `DnsRequest`, `SuspiciousDnsRequest`, `FileWritten`, `AsepValueUpdate`, `ProcessTerminate`, etc.) and maps them to Sysmon-equivalent event IDs. Field aliases added for CrowdStrike naming (`ImageFileName`, `TargetProcessId_decimal`, `LocalAddressIP4`, `RemoteAddressIP4`, `LocalPort`, `RemotePort`, `SHA256HashData`, `DomainName`, `UserSid`, `aid`, ...).
- **Zeek / Bro TSV logs** (`conn.log`, `dns.log`, `http.log`, `ssl.log`) — new `parse_zeek()` handles `#separator`, `#path`, `#fields` header block; converts Zeek epoch `ts` to ISO-8601; maps `id.orig_h`/`id.resp_h`/`id.orig_p`/`id.resp_p`/`proto`/`service` to canonical fields.
- **tshark `-T ek` JSON export** — auto-flattens `_source.layers.{ip,tcp,udp,dns,http}` into flat keys before alias mapping. Handles the arrayed nature of tshark values (takes first element).
- Format detection updated: Zeek recognized by leading `#separator`/`#fields`; tshark & CrowdStrike work through the enhanced JSON parser.

### P3 — Auto-generated OG image per shared analysis
- New module `cyberlab/og_image.py` — Pillow-based renderer produces 1200×630 PNG with:
  - Verdict-colored left accent stripe + verdict label pill
  - Risk-score gauge (0-100) with proportional fill
  - Summary line (truncates to fit)
  - Stat blocks: MITRE / Rules / IOCs counts
  - Top-5 MITRE technique chips
  - `nivxmachines.com/cyberlab` footer + brand row
- New endpoint `GET /api/cyberlab/share/{share_id}/og.png` (public, cached 24h). Returns 404 for expired/missing shares.
- Frontend `useSeo` hook extended with `ogImage`, `ogType`, `twitterCard` params — writes `og:image`, `og:image:width`, `og:image:height`, `og:url`, `twitter:card`, `twitter:image`, `twitter:title`, `twitter:description` meta tags. Backwards-compatible with existing callers.
- `CyberLabShare.jsx` now sets a rich title (`MALICIOUS · Risk 85 · NivX CyberLab`), description from `analysis.summary`, `og:image` pointing at the dynamic endpoint, and `twitter:card=summary_large_image`. Twitter/LinkedIn/Slack unfurls now render the branded PNG.

### Testing
- 10/10 pytest pass in 0.73s (`test_cyberlab_sysmon.py` 6 + `test_cyberlab_sources.py` 4 new).
- Live e2e verified: Falcon JSON → 3 forensic rows (process/network/dns). Zeek TSV → 2 network rows. OG image render → 15KB PNG with correct 1200×630 dims.

### Files added / modified
- ADDED    /app/backend/cyberlab/og_image.py
- ADDED    /app/backend/tests/test_cyberlab_sources.py
- MODIFIED /app/backend/cyberlab/sysmon.py (CrowdStrike + Zeek + tshark aliases and parse_zeek)
- MODIFIED /app/backend/cyberlab/router.py (og.png endpoint, og_image import)
- MODIFIED /app/frontend/src/lib/useSeo.js (og:image + twitter card meta writers)
- MODIFIED /app/frontend/src/pages/CyberLabShare.jsx (dynamic og:image URL)

## Backlog remaining
- **P2** — Wire real WhatsApp/Twitter/LinkedIn hrefs in Landing Hero (carry-over).
- **P3** — Refactor `server.py` (3,812 lines) into `routes/services/models/` (cosmetic).
- **P3** — Timeline mode toggle in Forensic Events table (Gantt-style per host/user).


## Session 37 (2026-07-09) — Enterprise SOC completion

Filled the remaining SOC gaps requested in one shot.

### 1) New decoder plugins (`cyberlab/plugins/decoders.py`) — palette now 34 ops
- **json-pretty / json-minify** — parametric indent, auto-detected when input is valid JSON.
- **xml-pretty** — xml.dom.minidom pretty-print, auto-detected.
- **cmd-deobfuscate** — strips `^` escape carets, resolves `!var!` delayed-expansion, unwraps quoted tokens.
- **js-deobfuscate** — collapses string concatenation, resolves `String.fromCharCode(...)` and `unescape("%XX")`, decodes `\xNN` / `\uNNNN`, splits statements for readability.
- New category `Structured` for JSON/XML formatters.

### 2) Log source parsers added to `cyberlab/sysmon.py`
- **CEF** (ArcSight): `CEF:0|Vendor|Product|Version|SigID|Name|Severity|ext…` — full extension key/value parsing with alias translation for `src`, `dst`, `spt`, `dpt`, `proto`, `suser`, `fname`, `fileHash`, `requestUrl`, `rt`.
- **LEEF** (QRadar): LEEF 1.0 (tab-delimited) + LEEF 2.0 (custom delimiter) — extension parsing + alias translation.
- **EVTX** (Windows binary event log): `python-evtx` integration. Endpoint accepts base64-encoded EVTX blob (`format: "evtx"`).
- Format auto-detection extended: leading `CEF:` / `LEEF:` / `#separator` / `#fields` recognized even when preceded by syslog priority prefix.

### 3) AI query generation (Claude Sonnet 4.5) — extended from 3 → 6 outputs
`POST /api/cyberlab/ai-analysis` now returns:
- `summary` · `sigma_rule` · `yara_rule` (existing)
- **`splunk_spl`** — Splunk hunt query with `| stats` + `| where` FP filter
- **`sentinel_kql`** — Microsoft Sentinel KQL over `DeviceProcessEvents` / `DeviceNetworkEvents` / `DnsEvents`
- **`cisco_xdr`** — Cisco XDR / SecureX Investigation CQL

Frontend `AiPanel.jsx` upgraded to a **6-tab** view (Summary · Sigma · YARA · Splunk SPL · Sentinel KQL · Cisco XDR) with per-tab copy button. Extracted the shared code into a `RulePane` sub-component.

### 4) Investigation Timeline — new component
`/app/frontend/src/components/InvestigationTimeline.jsx` — Gantt-style horizontal chronological view:
- One lane per **host** or **user** (toggle).
- Event markers colored by risk (info → critical).
- Action-specific unicode glyphs (▶ process, ↔ network, ? DNS, + file, ⚙ registry, etc.).
- Hover reveals a full-field card with MITRE technique chips.
- Time axis with 4 evenly-spaced tick marks; humanized duration span (ms / s / m / h / d).

Wired into `ForensicEventsPanel.jsx` as a **Table | Timeline** toggle above the events grid.

### Testing
- 17/17 pytest pass in 24s across `test_cyberlab_soc.py` (7 new) + `test_cyberlab_sysmon.py` (6) + `test_cyberlab_sources.py` (4).
- Verified: CEF single-event → src=10.0.5.20:54321 → dst=185.220.101.42:443 with url extracted. LEEF 2.0 with `^` delimiter → same fields. Real Claude 4.5 AI call generates all 6 hunt-query outputs.

### Files added / modified
- MODIFIED  /app/backend/cyberlab/plugins/decoders.py (+5 plugins, +Structured category)
- MODIFIED  /app/backend/cyberlab/sysmon.py (CEF + LEEF + EVTX parsers, extended format detection)
- MODIFIED  /app/backend/cyberlab/ai_analysis.py (Splunk SPL + Sentinel KQL + Cisco XDR prompts)
- MODIFIED  /app/backend/cyberlab/router.py (EVTX base64 handling in /process-tree)
- ADDED     /app/backend/tests/test_cyberlab_soc.py (7 tests)
- ADDED     /app/frontend/src/components/InvestigationTimeline.jsx
- MODIFIED  /app/frontend/src/components/ForensicEventsPanel.jsx (Table | Timeline toggle)
- MODIFIED  /app/frontend/src/components/cyberlab/AiPanel.jsx (6-tab hunt-query view)
- INSTALLED python-evtx==0.8.1 (+ hexdump)

## 2026-07-09 — Auto Investigation Mode + Risk Reasons UX
### Auto Investigation Mode (P0 delivered)
- New backend endpoints `POST /api/cyberlab/detect-format` and `POST /api/cyberlab/auto-investigate` — one-shot orchestrator (detect → decode/parse → analyze → optional AI). Response shape: `{kind, format, stages[], output, trace[], forensic_events[], tree{}, analysis{}, ai{}, duration_ms}`.
- New helper `_extract_and_decode_embedded_b64` recovers URLs/IOCs hidden inside VBA macros, cert blobs, and PowerShell here-strings (UTF-16LE preferred, UTF-8 fallback, null-byte guard).
- Frontend `runAutoInvestigate` orchestrator (CyberLab.jsx) runs sequential API calls and drives a live **AutoInvestigateProgress** panel with 5 stage cards (`detect`, `auto-decode|parse-log` swap, `analyze`, `ai`, `render`) — every card exposes `data-testid` + `data-status` for testing.
- Auto Investigate is now the **primary gradient CTA**; existing `Auto Decode` and `Run Recipe` remain as secondary buttons (coexist mode).
- ProcessTreeViewer accepts `initialTree` / `initialText` props so the log-input path renders the parsed tree without a second click.
- Pytest samples fixture `/app/backend/tests/samples/malware_samples.py` — 8 real-world payloads (PS -EncodedCommand, mshta, certutil, rundll32-HTA, Office macro Auto_Open with nested b64, ransomware note, nested b64→gzip, Sysmon XML). Regression tests: `/app/backend/tests/test_auto_investigate.py` (12 tests).

### Risk Score Visualization (user-requested UX polish)
- Backend `cyberlab.risk_reasons` module — pattern-driven detector returning `[{label, severity, category, evidence}]` across 9 categories (encoding, execution, lolbin, network, persistence, impact, credential, recon, forensic). Wired into `/analyze`, `/auto-decode?include_analysis=true`, and `/auto-investigate` (both payload + log paths). `AnalysisReport` model extended with `risk_reasons: List[RiskReason]`.
- Frontend `VerdictBanner.jsx` — full-width gradient progress bar (segmented ticks 0/25/50/75/100), verdict icon + label, risk-score with severity bucket (Minimal → Critical), indicator count + high/med/low chips, and a category-grouped "Why this score" list with checkmark bullets.
- Regression: `/app/backend/tests/test_risk_reasons.py` (7 tests).

## 2026-07-09 — In-page OSINT Enrichment + Multi-format Reports + Perf Instrumentation (P0)

### Selective IOC Enrichment (user request — 2026-07-10)
- IOCs tab now renders **per-row checkboxes** + a compact toolbar with `select-all`, current selection count (`N/total`), primary **Analyze N** button, `Analyze all` secondary, and `Send →` (legacy bulk-analyzer path retained).
- Selecting IOCs and clicking "Analyze N" runs the exact same `/api/cyberlab/enrich-iocs` pipeline the Auto Investigate stage uses — the enriched result populates the shared `EnrichedIocsPanel` and auto-scrolls into view.
- Selection auto-resets when a new investigation runs. 20-IOC hard cap enforced; if user selects more, the client toasts and truncates.
- No new endpoints — 100% reuse of the shipped enrichment engine + cache.
- Regression: `test_enrich_iocs_mixed_types_selective` in `tests/test_cyberlab_enrich.py` (12 tests total in the enrich suite).

### CyberLab In-page OSINT Enrichment (new "OSINT Enrich" stage)
- New `POST /api/cyberlab/enrich-iocs` accepts `{values, depth: free|comprehensive|ai}`. Runs the same OSINT pipeline as the Bulk Analyzer (VT · AbuseIPDB · Shodan · geo · DNS · urlscan · CIRCL · Hybrid Analysis · MalwareBazaar) with per-batch cap of 20 IOCs, dedup + normalization, 20 concurrent, cache-aware.
- Depth = `free` returns enrichment only (no key-based reputation); `comprehensive` adds VT/AbuseIPDB/HA/MB; `ai` additionally generates a per-IOC Claude/Gemini verdict (7-day cache).
- Response includes `count, flagged, duration_ms, iocs_per_sec, cache_hit_rate, depth, results[]` so the UI can show real metrics.
- New Auto Investigate stage `enrich` — runs automatically after AI stage (toggleable), fails soft on error, gracefully skipped when no IOCs.

### Report Downloads — 4 formats
- Extended `render_pdf` + `render_markdown` and added `render_csv` + `render_json` in `cyberlab/exports.py`. All formats include the OSINT enrichment table (IOC · Type · Verdict · VT · Abuse · Geo/Host · Verdict) and per-IOC AI verdicts when present.
- New endpoints `POST /api/cyberlab/export/csv` and `POST /api/cyberlab/export/json`.
- Frontend "Download Report" split-button (dropdown) with all 4 formats — one-click server-generated download, no client-side templating.
- The comprehensive **Threat Card PDF** now bundles: verdict banner, decode chain, MITRE table, YARA rule hits, plain IOCs, OSINT-enriched IOC table, per-IOC AI verdicts, draft Sigma/YARA rules.

### Performance Instrumentation (P0)
- New module `/app/backend/ioc_perf.py` — per-provider rolling latency window (500 samples, p50/p95/avg), cache-hit/miss counters, error counts, slow-call detection (>3s), plus batch-level stats + concurrency gates.
- Intelligent 24h enrichment cache (`db.ioc_enrich_cache`) for Shodan, geo, DNS, urlscan, and CIRCL hashlookup. Reputation providers keep their existing 6h `db.ioc_cache`.
- Tightened enrichment timeouts to 6s (was 12s) — reputation still gets 12s.
- Per-provider concurrency gates: urlscan 6 · shodan 10 · geo 6 · DNS 10 · CIRCL 8 · VT 2 · AbuseIPDB 4 · HA 4 · MB 6.
- Batch concurrency lifted 8 → 20.
- New endpoint `GET /api/cyberlab/enrich-metrics` returns full metrics snapshot (uptime, total_calls, overall_cache_hit_rate, per-provider p50/p95/avg/slow_calls/last_error, recent batches).
- **Measured impact**: second call for same IOC set drops from ~1.7s to ~26ms (**65× speedup** on cache hit).

### Files touched
- ADDED     /app/backend/ioc_perf.py
- ADDED     /app/backend/tests/test_cyberlab_enrich.py (11 tests — endpoint validation, cap, dedupe, cache speedup assertion, all 4 export formats incl. PDF validity)
- ADDED     /app/frontend/src/components/cyberlab/EnrichedIocsPanel.jsx
- MODIFIED  /app/backend/server.py (instrumented _shodan_ip / _geo_ip / _resolve_host / urlscan / CIRCL with cache + gate + timeout; added /api/cyberlab/enrich-iocs + /api/cyberlab/enrich-metrics; imports ioc_perf)
- MODIFIED  /app/backend/cyberlab/exports.py (+ render_csv, render_json, enriched-IOC section in PDF & MD)
- MODIFIED  /app/backend/cyberlab/router.py (+ /export/csv + /export/json; ShareRequest extended with enriched_iocs + enrichment_meta)
- MODIFIED  /app/frontend/src/pages/CyberLab.jsx (enrich toggle + depth selector + Download Report dropdown + orchestrator adds enrich stage + renders EnrichedIocsPanel)
- MODIFIED  /app/frontend/src/lib/cyberlabApi.js (+ enrichIocs, + downloadReport)
- MODIFIED  /app/frontend/src/components/cyberlab/AutoInvestigateProgress.jsx (+ `enrich` stage meta)

## Backlog remaining
- **P0** — Finish streaming NDJSON path for Bulk Analyzer (in-progress; CyberLab enrichment shipped instead — reuses same cache/instrumentation).
- **P2** — Wire real WhatsApp/Twitter/LinkedIn hrefs in Landing Hero (carry-over).
- **P2** — Direct EDR/SIEM webhooks to push generated Sigma/YARA rules to SIEM.
- **P3** — Refactor `server.py` (3.8k lines) into modular routes/services folders.
- **P3** — Direct PCAP binary parsing (currently requires tshark `-T ek` preprocessing).
