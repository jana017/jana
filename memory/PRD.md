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

