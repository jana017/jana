import { useEffect, useState, useCallback } from "react";
import { Trash2, RefreshCw, Database, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { authHeaders } from "@/lib/auth";

const API = process.env.REACT_APP_BACKEND_URL;

/**
 * Admin panel widget for inspecting and purging OSINT enrichment / reputation
 * / AI-summary caches. Exposed at /admin > Settings.
 *
 * Backend endpoints:
 *   GET  /api/admin/cache/stats
 *   POST /api/admin/cache/purge   { scope, provider?, only_empty? }
 */
const ENRICH_PROVIDERS = [
  { key: "urlscan",     label: "urlscan.io",  hint: "Scan history + preview screenshots" },
  { key: "shodan_ip",   label: "Shodan",      hint: "Open ports / vulnerabilities" },
  { key: "geo_ip",      label: "ip-api.com",  hint: "GeoIP + ASN" },
  { key: "dns_resolve", label: "Google DNS",  hint: "Host → A record" },
  { key: "circl_hash",  label: "CIRCL",       hint: "Known-file hashlookup" },
];

export default function AdminCachePurge() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(null); // label of active purge

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/api/admin/cache/stats`, { headers: authHeaders() });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setStats(await r.json());
    } catch (e) {
      toast.error(`Failed to load cache stats: ${e.message}`);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const purge = useCallback(async (label, body, confirmText) => {
    if (confirmText && !window.confirm(confirmText)) return;
    setBusy(label);
    try {
      const r = await fetch(`${API}/api/admin/cache/purge`, {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      toast.success(`${label} — purged ${d.total} entr${d.total === 1 ? "y" : "ies"}`);
      await load();
    } catch (e) {
      toast.error(`Purge failed: ${e.message}`);
    } finally { setBusy(null); }
  }, [load]);

  const totalEnrich = stats?.enrichment?._total ?? 0;
  const totalRep    = stats?.reputation?.reputation?.count ?? 0;
  const totalAi     = stats?.reputation?.ai_summary?.count ?? 0;

  return (
    <section
      data-testid="admin-cache-purge"
      className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm"
    >
      <div className="flex items-center justify-between gap-4 flex-wrap mb-4">
        <div className="flex items-center gap-2">
          <Database className="w-4 h-4 text-cyan-600" />
          <h3 className="text-base font-semibold text-slate-900">OSINT cache administration</h3>
        </div>
        <button
          data-testid="cache-refresh-btn"
          onClick={load}
          disabled={loading}
          className="text-xs text-slate-500 hover:text-cyan-600 inline-flex items-center gap-1 disabled:opacity-40"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      <p className="text-xs text-slate-500 mb-4">
        The OSINT enrichment cache (24h TTL) and reputation cache (6h TTL) speed up repeat lookups by ~65×. Purge if you see stale or missing results (e.g. urlscan preview not rendering).
      </p>

      {/* Enrichment providers grid */}
      <div className="mb-5">
        <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
          Enrichment cache ({totalEnrich} entries)
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {ENRICH_PROVIDERS.map((p) => {
            const n = stats?.enrichment?.[p.key]?.count ?? 0;
            return (
              <div
                key={p.key}
                data-testid={`cache-row-${p.key}`}
                className="rounded border border-slate-200 bg-slate-50 p-3 flex items-center justify-between gap-2"
              >
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-slate-800">{p.label}</div>
                  <div className="text-[10px] text-slate-500 truncate" title={p.hint}>{p.hint}</div>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-lg font-bold tabular-nums text-slate-800">{n}</div>
                  <button
                    data-testid={`cache-purge-${p.key}`}
                    onClick={() => purge(
                      `${p.label}`,
                      { scope: "enrichment", provider: p.key },
                      `Purge all ${n} ${p.label} cache entries?`,
                    )}
                    disabled={busy !== null || n === 0}
                    className="text-[10px] text-red-600 hover:text-red-700 inline-flex items-center gap-1 disabled:opacity-30 mt-0.5"
                  >
                    {busy === p.label ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Trash2 className="w-3 h-3" />}
                    Purge
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Reputation + AI caches */}
      <div className="mb-5 grid grid-cols-1 sm:grid-cols-2 gap-2">
        <div className="rounded border border-slate-200 bg-slate-50 p-3 flex items-center justify-between gap-2">
          <div>
            <div className="text-sm font-semibold text-slate-800">Reputation cache</div>
            <div className="text-[10px] text-slate-500">VT · AbuseIPDB · HA · MalwareBazaar (6h TTL)</div>
          </div>
          <div className="text-right">
            <div className="text-lg font-bold tabular-nums text-slate-800">{totalRep}</div>
            <button
              data-testid="cache-purge-reputation"
              onClick={() => purge("Reputation", { scope: "reputation" }, `Purge all ${totalRep} reputation cache entries?`)}
              disabled={busy !== null || totalRep === 0}
              className="text-[10px] text-red-600 hover:text-red-700 inline-flex items-center gap-1 disabled:opacity-30 mt-0.5"
            >
              {busy === "Reputation" ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Trash2 className="w-3 h-3" />}
              Purge
            </button>
          </div>
        </div>
        <div className="rounded border border-slate-200 bg-slate-50 p-3 flex items-center justify-between gap-2">
          <div>
            <div className="text-sm font-semibold text-slate-800">AI verdict cache</div>
            <div className="text-[10px] text-slate-500">Per-IOC Claude/Gemini verdicts (7-day TTL)</div>
          </div>
          <div className="text-right">
            <div className="text-lg font-bold tabular-nums text-slate-800">{totalAi}</div>
            <button
              data-testid="cache-purge-ai"
              onClick={() => purge("AI verdicts", { scope: "ai_summary" }, `Purge all ${totalAi} AI-verdict cache entries?`)}
              disabled={busy !== null || totalAi === 0}
              className="text-[10px] text-red-600 hover:text-red-700 inline-flex items-center gap-1 disabled:opacity-30 mt-0.5"
            >
              {busy === "AI verdicts" ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Trash2 className="w-3 h-3" />}
              Purge
            </button>
          </div>
        </div>
      </div>

      {/* Bulk operations */}
      <div className="border-t border-slate-200 pt-3 flex flex-wrap items-center gap-2">
        <button
          data-testid="cache-purge-empty"
          onClick={() => purge("Empty entries", { scope: "enrichment", only_empty: true })}
          disabled={busy !== null}
          className="text-xs font-semibold text-cyan-700 hover:text-cyan-900 border border-cyan-200 hover:bg-cyan-50 rounded px-2.5 py-1.5 inline-flex items-center gap-1.5 disabled:opacity-40 transition-colors"
          title="Delete only entries with empty payloads (e.g. urlscan miss cached as null) — safest cleanup"
        >
          {busy === "Empty entries" ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
          Purge empty entries only
        </button>
        <button
          data-testid="cache-purge-all"
          onClick={() => purge("All caches", { scope: "all" },
            `Purge ALL ${totalEnrich + totalRep + totalAi} cache entries across enrichment + reputation + AI?\n\nNext lookups will hit external APIs and be slower until the cache warms up.`)}
          disabled={busy !== null}
          className="text-xs font-semibold text-red-700 hover:text-red-900 border border-red-200 hover:bg-red-50 rounded px-2.5 py-1.5 inline-flex items-center gap-1.5 disabled:opacity-40 transition-colors ml-auto"
        >
          {busy === "All caches" ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <AlertTriangle className="w-3.5 h-3.5" />}
          Purge everything
        </button>
      </div>
    </section>
  );
}
