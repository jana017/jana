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
- Live CISA feed (1,635 CVEs, ransomware counters).
- Threat Report featured brief: MITRE ATT&CK kill-chain w/ tactic IDs, process tree, IOCs; grid cards + detail dialog.
- Admin CRUD verified via UI. Backend 9/9 tests pass; frontend 100%.
- Full redesign from dark hacker theme -> light corporate enterprise theme.

## Credentials
- Admin: admin@nivxmachines.com / NivX@Admin2025 (see /app/memory/test_credentials.md)

## Backlog / Next
- P1: Lead-capture form on Support ("Request a Security Assessment") saving to DB.
- P2: MITRE technique-level tags (T-codes) under tactics; kill-chain node diagram.
- P2: shadcn AlertDialog for delete confirmation instead of native confirm.
- P2: Replace remaining logo navy-chip with transparent logo variant if provided.
