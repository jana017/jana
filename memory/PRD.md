# NivX Machines — PRD

## Problem Statement
Cybersecurity/AI/Tech firm landing page. Sections: About Us, Gallery, Threat Report, Careers, Services, Support. Threat Report shows real-time reports with Attack Chain models, Process Trees, images. Contact: Mobile 9059565125, Email info@nivxmachines.com. Real-time threat landscape.

## User Choices
- Type: Landing page
- Threat data: live external feed (CISA KEV) + admin panel to add/edit/delete
- Careers: static listings, apply via email
- Support: contact info only
- Design: award-worthy dark cyber theme (agent-designed)

## Architecture
- Backend: FastAPI + MongoDB (motor). JWT admin auth (Bearer, localStorage). Threat CRUD. /api/live-feed pulls CISA KEV (cached 30min).
- Frontend: React + framer-motion + lenis smooth scroll + react-fast-marquee. Fonts: Unbounded / Satoshi / JetBrains Mono. Dark neon (#00F0FF) theme.
- Routes: / (Landing), /admin (login + dashboard)

## Implemented (2025-12)
- Kinetic hero (masked line reveal), manifesto chapters, editorial marquee
- Live Threat Landscape (animated counters + live CISA feed table)
- Threat Report cards + detail dialog (attack chain, process tree, IOCs)
- Gallery bento, Services bento, Careers (mailto apply), Support contact cards
- Admin: JWT login, create/edit/delete threat reports
- Tested: 100% backend (9/9), 100% critical frontend flows

## Admin
admin@nivxmachines.com / NivX@Admin2025

## Backlog
- P1: Real product photography / user logo upload
- P2: Threat report image upload (object storage), search/filter on reports
- P2: Split server.py into modules
