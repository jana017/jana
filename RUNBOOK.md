# NivX Machines — Operator Runbook

**Audience**: A developer who just inherited this codebase (or you, six months from now).
**Goal**: Fix any common issue in <30 minutes without an LLM agent.

---

## Table of contents
1. [Architecture at a glance](#architecture-at-a-glance)
2. [Daily commands](#daily-commands)
3. [How HealthBot works (and its limits)](#how-healthbot-works-and-its-limits)
4. [How to add a NivX Forge decoder plugin](#how-to-add-a-nivx-forge-decoder-plugin)
5. [How to debug a frontend white-screen](#how-to-debug-a-frontend-white-screen)
6. [How to debug a backend 500](#how-to-debug-a-backend-500)
7. [How to add a HealthBot check](#how-to-add-a-healthbot-check)
8. [How to interpret HealthBot findings](#how-to-interpret-healthbot-findings)
9. [Redeploy checklist](#redeploy-checklist)
10. [Common bug classes → fix location](#common-bug-classes--fix-location)
11. [When you're truly stuck](#when-youre-truly-stuck)

---

## Architecture at a glance

```
/app
├── backend/                       FastAPI + Motor (async Mongo) on :8001
│   ├── server.py                  API routes, OSINT sync, seeds
│   ├── cyberlab/                  NivX Forge — decoder engine
│   │   ├── engine.py              auto_decode(): chained plugin decoder
│   │   ├── plugins/decoders.py    28+ registered plugins (extractors, decoders)
│   │   ├── repair.py              refine(): fixes paste artifacts (Troubleshoot backend)
│   │   ├── rule_scanner.py        NivX Forge YARA-lite detection rules
│   │   ├── ai_analysis.py         LLM-assisted triage (optional)
│   │   └── router.py              /api/cyberlab/* endpoints
│   ├── healthbot/                 HealthBot — 13 deterministic checks
│   │   ├── checks.py              Register + implement each check
│   │   ├── router.py              /api/healthbot/* endpoints
│   │   └── eslint.smoke.mjs       ESLint config used by frontend_lint check
│   ├── webhooks/                  EDR/SIEM outbound delivery
│   ├── tickets/, employees/, cms/, ui_scanner/
│   └── tests/                     Pytest — 260+ tests (regression bar)
└── frontend/                      React CRA + craco on :3000
    ├── src/pages/                 Route-level components (Admin, ThreatIntelligence, CyberLab...)
    ├── src/components/            Reusable pieces
    ├── src/lib/                   api.js (axios), auth, hooks
    └── src/context/               AuthContext
```

**Key rule**: never break the contract at these seams.
- `REACT_APP_BACKEND_URL` (frontend/.env) → the backend for all API calls
- `/api/*` prefix on every backend route (K8s ingress requires it)
- Motor async client using `MONGO_URL` (never hardcode)

---

## Daily commands

```bash
# See the state of everything
sudo supervisorctl status

# Restart a service (only needed after .env changes / new deps)
sudo supervisorctl restart backend
sudo supervisorctl restart frontend

# Tail logs — first place to look for any 500
tail -f /var/log/supervisor/backend.err.log
tail -f /var/log/supervisor/frontend.err.log

# Run backend tests (should always be green before deploy)
cd /app/backend && python -m pytest tests/ -x --tb=short

# Frontend lint (catches white-screen bugs)
cd /app/frontend && npx eslint --config /app/backend/healthbot/eslint.smoke.mjs src/

# Frontend production build (catches import errors that dev-server hides)
cd /app/frontend && yarn build

# Get admin JWT for testing authed endpoints
curl -s -X POST http://127.0.0.1:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@nivxmachines.com","password":"NivX@Admin2025"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])"
```

---

## How HealthBot works (and its limits)

**What it does** — runs 13 deterministic checks in parallel (~1.5s total):

| Check | What it catches | Auto-fix? |
|---|---|---|
| `mongo_ping` | Mongo unreachable | No |
| `mongo_indexes` | Missing hot indexes | ✅ Yes |
| `plugin_registry` | Broken plugin imports | No |
| `share_pruning` | Old expired shares | ✅ Yes |
| `enrichment_cache` | Cache size | No |
| `webhook_backlog` | Failed deliveries pile-up | No |
| `osint_keys` | API keys unset | No (config choice) |
| `env_vars` | Missing required env | No |
| `disk_space` | Root FS >85% | No |
| `module_health` | Import failures | No |
| **`frontend_lint`** | JS undefined refs (white-screen) | No — but reports file+line |
| **`route_smoke`** | Critical endpoints failing | No — reports HTTP status |
| **`decoder_coverage`** | Decoder plugin regressions | No — reports which sample broke |

**What it doesn't do**:
- Predict brand-new obfuscation patterns → analyst must add to Regression Suite
- Test JS runtime behavior (only static lint + endpoint smoke)
- Fix arbitrary bugs — most checks report; only 2 auto-repair

**Run it**:
```bash
# Manual scan (from Admin UI: Master → Overview → Run scan)
curl -X POST http://127.0.0.1:8001/api/healthbot/scan \
  -H "Authorization: Bearer $TOKEN"

# Auto-fix mode (only touches indexes + expired shares)
curl -X POST http://127.0.0.1:8001/api/healthbot/scan-and-fix \
  -H "Authorization: Bearer $TOKEN"

# Last cached scan (banner uses this)
curl http://127.0.0.1:8001/api/healthbot/latest \
  -H "Authorization: Bearer $TOKEN"
```

---

## How to add a NivX Forge decoder plugin

**Scenario**: You see a payload that produces `0 steps` in Auto Investigate. You need to teach the engine a new pattern.

1. **Reproduce with curl** (no UI needed):
   ```bash
   curl -s -X POST http://127.0.0.1:8001/api/cyberlab/auto-decode \
     -H "Content-Type: application/json" \
     -d '{"input": "<paste raw payload here>"}' \
     | python3 -m json.tool | head -50
   ```
   Look at `trace` — if empty, no plugin recognized the input.

2. **Open** `/app/backend/cyberlab/plugins/decoders.py`. Copy the closest existing plugin (e.g. `extract-python-b64decode`). A plugin has three things:

   ```python
   _MY_PATTERN_RE = re.compile(r"""<your regex>""", re.IGNORECASE)

   def _detect_my(data: bytes) -> float:
       """Return 0.0–1.0. Higher = more confident."""
       text = data.decode("utf-8", errors="ignore")
       return 0.9 if _MY_PATTERN_RE.search(text) else 0.0

   def _extract_my(data: bytes, params: Dict[str, Any]) -> bytes:
       """Return the extracted / decoded bytes."""
       text = data.decode("utf-8", errors="replace")
       m = _MY_PATTERN_RE.search(text)
       return m.group(1).encode("ascii") if m else data

   register(Plugin(
       id="extract-my-thing",
       name="Extract My Obfuscation Format",
       category="Extractors",       # or "Encoding" / "Compression" / "Cryptography"
       description="One-line what-and-why.",
       run=_extract_my,
       detect=_detect_my,
   ))
   ```

3. **Add a golden sample** to `/app/backend/healthbot/checks.py` `_GOLDEN_PAYLOADS`:
   ```python
   {
       "id": "my_new_variant",
       "input": "<the exact payload>",
       "must_decode_to_contain": "<substring you expect in the decoded output>",
   },
   ```

4. **Restart backend + verify**:
   ```bash
   sudo supervisorctl restart backend
   # Then curl the auto-decode again → trace should now have your plugin
   ```

5. **Confidence tuning**:
   - `0.95+` → highly specific plugins (`__import__('base64').b64decode(...)`)
   - `0.75` → fallback / catch-all extractors (any long quoted base64 blob)
   - `0.5` → risky heuristics (would false-positive on user data)
   - Never register a plugin at `>= 0.9` that could match innocent text.

---

## How to debug a frontend white-screen

1. **Open the URL in Chrome → DevTools → Console tab**. Look for the first red error. Copy the identifier from it.

2. **Search the codebase**:
   ```bash
   grep -rn "identifier_name" /app/frontend/src
   ```

3. **Common causes**:
   - **`ReferenceError: X is not defined`** → missing import OR missing `useState`/`useRef` declaration
   - **`Cannot read properties of undefined (reading 'foo')`** → API response shape changed → check the endpoint
   - **`Element type is invalid`** → JSX component name typo or bad `export default`

4. **Fix + confirm** with:
   ```bash
   cd /app/frontend && yarn build
   # If build passes, the fix is real. Then reload the browser (hard refresh).
   ```

5. **Prevent recurrence**: run `frontend_lint`:
   ```bash
   cd /app/frontend && npx eslint --config /app/backend/healthbot/eslint.smoke.mjs src/ --format compact
   ```

---

## How to debug a backend 500

1. **Tail the error log** first:
   ```bash
   tail -n 100 /var/log/supervisor/backend.err.log | grep -A 20 "Traceback"
   ```

2. **Replay the exact request**:
   ```bash
   curl -v -X POST http://127.0.0.1:8001/api/<the-route> \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '<request body>'
   ```

3. **Localize**:
   - Route → search `@api_router.` in `/app/backend/server.py` or module routers
   - Model → check the Pydantic model for the response
   - DB call → check the Motor query (typos silently return empty)

4. **Fix**, then run the pytest that covers this route:
   ```bash
   cd /app/backend && pytest tests/ -k "<route_word>" -v
   ```

---

## How to add a HealthBot check

1. **Open** `/app/backend/healthbot/checks.py`.

2. **Copy an existing simple check** (e.g. `_check_mongo_ping`):
   ```python
   async def _check_my_thing():
       t0 = time.perf_counter()
       # ... your logic. Query DB, check disk, call subprocess, whatever.
       # If OK → return CheckResult(id="my_thing", severity="ok", message="...")
       # If bad → return CheckResult(id="my_thing", severity="critical", ...)
       return CheckResult(
           id="my_thing", name="My New Check",
           severity="ok", message="All good.",
           duration_ms=(time.perf_counter() - t0) * 1000,
       )
   register(_check_my_thing)
   ```

3. **Rules**:
   - **Must complete in <5s** — HealthBot runs everything in parallel; slow checks anchor the whole scan.
   - **Deterministic**: no LLM calls, no external network unless bounded by timeout.
   - **Severity**: `ok` / `info` / `warning` / `critical` — nothing else.
   - **Provide `details`** dict with actionable data (file+line, count, list).

4. **Auto-fix** (optional):
   ```python
   async def _fix_my_thing(result):
       # ... perform the repair
       return "Fixed by X"
   register_fix("my_thing", _fix_my_thing)
   ```

5. **Restart backend** — the new check auto-registers.

---

## How to interpret HealthBot findings

Each finding has: `severity`, `message`, and often a `details` dict.

- **`critical`** → deploy-blocking. Fix before Save & Deploy.
- **`warning`** → non-blocking but track it. Frequently means historical noise (old failed webhook deliveries).
- **`info`** → informational (feature disabled, key not configured — usually user choice).
- **`ok`** → nothing to do.

**Common false alarms and their meaning**:
- `webhook_backlog: 8 old failed deliveries` → historical audit rows. Clear via Admin → Master → EDR/SIEM → Audit → Clear.
- `osint_keys: No DB overrides` → totally fine if you use `.env`. It only warns because DB-store is preferred for zero-downtime rotation.

---

## Redeploy checklist

Before hitting **Save & Deploy** in Emergent:

- [ ] Run pytest: `cd /app/backend && pytest tests/ -x` — must be all-green
- [ ] Run frontend lint: `cd /app/frontend && npx eslint --config /app/backend/healthbot/eslint.smoke.mjs src/` — must be 0 errors
- [ ] Run frontend build: `cd /app/frontend && yarn build` — must succeed (warnings OK)
- [ ] Trigger a HealthBot scan → `overall` must be `ok` or `warning` (never `critical`)
- [ ] Smoke test the preview URL — hit the pages you changed
- [ ] Note the commit / job ID in case rollback is needed

If deploy fails with `K8s readiness timeout`:
- Not a code issue (deployment_agent has already verified)
- Retry Save & Deploy once (transient K8s issue)
- If still failing: email `support@emergent.sh` with the Job ID

---

## Common bug classes → fix location

| Symptom | First place to look | Second place |
|---|---|---|
| **White-screen on a route** | Browser Console → identifier → grep frontend/src | `frontend_lint` HealthBot check |
| **API returns 500** | `/var/log/supervisor/backend.err.log` | The router file for that endpoint |
| **Auto-decode returns 0 steps** | `/app/backend/cyberlab/plugins/decoders.py` — add extractor | `_GOLDEN_PAYLOADS` in healthbot/checks.py |
| **Troubleshoot corrupts payload** | `/app/backend/cyberlab/repair.py` — check the regex bounds | Add a `b64_padding_no_corruption`-style regression test |
| **NivX Forge marks obvious malware as clean** | `/app/backend/cyberlab/rule_scanner.py` — add / fix a rule | Verdict computed in `/app/backend/cyberlab/engine.py::compute_risk` |
| **urlscan preview missing** | `/app/backend/server.py` — search `_urlscan_submit_scan` | Front-end `IocAnalyzer.jsx` fresh_scan branch |
| **OSINT enrichment fails silently** | `/app/backend/server.py` — search provider name | `.env` API key + rate-limit |
| **Deploy fails K8s readiness** | Not your code — retry, then contact `support@emergent.sh` | `deployment_agent` will confirm |
| **Frontend hot-reload not picking changes** | `sudo supervisorctl restart frontend` | Check `/var/log/supervisor/frontend.err.log` |

---

## When you're truly stuck

1. **HealthBot `details`** — most bugs are one dict-lookup away
2. **`git log`** — see what changed recently in the file you're debugging
3. **Community**:
   - CyberChef repo — same plugin architecture: <https://github.com/gchq/CyberChef/blob/master/src/core/operations/README.md>
   - FastAPI Discord: <https://discord.gg/8fJTZ8gV>
   - MITRE ATT&CK Slack: <https://attack.mitre.org/resources/engage-with-attack/community/>
4. **LLM alternatives** (no vendor lock-in):
   - **Cursor** / **Windsurf** — VS Code-style editor with same-repo LLM chat
   - **Aider CLI** — terminal + BYO OpenAI/Anthropic key
   - **OpenRouter** — one API, many models
5. **Save your incident samples** — every hard debug gets added to:
   - `/app/backend/healthbot/checks.py::_GOLDEN_PAYLOADS` (decoder regressions)
   - Admin UI → Master → Overview → Regression Suite (analyst-friendly path)

---

*Last updated: Feb 2026 — during the `bestshoppingday.com / import('base64')` incident.*
