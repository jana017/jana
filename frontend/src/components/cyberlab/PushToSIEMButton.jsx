/**
 * PushToSIEMButton — one-click "push generated rules to my SIEM/EDR" button
 * for NivX Forge. Reads webhooks from /api/webhooks, lets the analyst pick,
 * and dispatches the current analysis payload via /api/webhooks/push.
 *
 * Requires admin auth (same JWT the rest of the platform uses). Non-admin
 * viewers see a disabled button prompting them to sign in.
 */
import { useState, useEffect, useCallback } from "react";
import { toast } from "sonner";
import { Send, ChevronDown, Webhook, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { getToken } from "@/lib/auth";

export default function PushToSIEMButton({ input, output, ai, analysis }) {
  const [open, setOpen] = useState(false);
  const [webhooks, setWebhooks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(null); // webhook id being pushed
  const authed = !!getToken();

  const load = useCallback(async () => {
    if (!authed) return;
    setLoading(true);
    try {
      const { data } = await api.get("/webhooks");
      setWebhooks(data.filter((w) => w.enabled));
    } catch (e) {
      // Silent — the dropdown just stays empty. Admin can fix in the /admin panel.
      setWebhooks([]);
    } finally {
      setLoading(false);
    }
  }, [authed]);

  useEffect(() => {
    if (open) load();
  }, [open, load]);

  const push = async (webhookId) => {
    setBusy(webhookId);
    try {
      const payload = {
        webhook_id: webhookId,
        input: (input || "").slice(0, 4000),
        output: (output || "").slice(0, 4000),
        summary: ai?.summary || analysis?.summary || "",
        verdict: analysis?.verdict || "unknown",
        risk_score: analysis?.risk_score || 0,
        sigma_rule: ai?.sigma_rule || "",
        yara_rule: ai?.yara_rule || "",
        splunk_spl: ai?.splunk_spl || "",
        sentinel_kql: ai?.sentinel_kql || "",
        cisco_xdr: ai?.cisco_xdr || "",
        iocs: analysis?.iocs || [],
        mitre: analysis?.mitre || [],
        rules: analysis?.rules || [],
      };
      const { data } = await api.post("/webhooks/push", payload);
      if (data.status === "ok") {
        toast.success(`Pushed to ${data.webhook_name} — HTTP ${data.http_status}`, {
          description: data.content_summary,
        });
      } else {
        toast.error(`${data.webhook_name} failed — HTTP ${data.http_status || "n/a"}`, {
          description: data.error || "no response",
        });
      }
      setOpen(false);
    } catch (e) {
      toast.error(`Push failed: ${e.response?.data?.detail || e.message}`);
    } finally {
      setBusy(null);
    }
  };

  // No AI output yet — hide the button entirely (no rules to push).
  const hasContent =
    !!(ai?.sigma_rule || ai?.yara_rule || (analysis?.iocs || []).length > 0);

  if (!hasContent) return null;

  if (!authed) {
    return (
      <button
        disabled
        data-testid="push-to-siem-disabled"
        title="Sign in as admin to push rules to your SIEM/EDR"
        className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 cursor-not-allowed opacity-60"
      >
        <Webhook className="w-3.5 h-3.5" /> Push to SIEM
      </button>
    );
  }

  return (
    <div className="relative inline-block" data-testid="push-to-siem-root">
      <button
        onClick={() => setOpen(!open)}
        data-testid="push-to-siem-btn"
        className="inline-flex items-center gap-1.5 text-xs font-semibold text-white bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 rounded px-2.5 py-1.5 shadow-sm"
      >
        <Webhook className="w-3.5 h-3.5" /> Push to SIEM
        <ChevronDown className={`w-3 h-3 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <>
          {/* click-outside catcher */}
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div
            data-testid="push-to-siem-menu"
            className="absolute right-0 top-full mt-1 z-50 w-80 rounded-lg border border-slate-700 bg-slate-900 shadow-2xl overflow-hidden"
          >
            <div className="px-3 py-2 border-b border-slate-700 text-xs font-semibold text-slate-400 uppercase tracking-wide">
              Send to endpoint
            </div>
            {loading && (
              <div className="px-3 py-4 text-xs text-slate-400 flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading…
              </div>
            )}
            {!loading && webhooks.length === 0 && (
              <div className="px-3 py-4 text-xs text-slate-400 space-y-2">
                <p>No active webhooks configured.</p>
                <a href="/admin" className="inline-block text-emerald-400 underline">
                  Configure one in /admin →
                </a>
              </div>
            )}
            {webhooks.map((w) => (
              <button
                key={w.id}
                onClick={() => push(w.id)}
                disabled={busy === w.id}
                data-testid={`push-target-${w.id}`}
                className="w-full text-left px-3 py-2.5 hover:bg-slate-800 border-b border-slate-800 last:border-0 disabled:opacity-50 flex items-center gap-2"
              >
                {busy === w.id ? (
                  <Loader2 className="w-3.5 h-3.5 text-emerald-400 animate-spin shrink-0" />
                ) : w.last_status === "ok" ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                ) : w.last_status === "failed" ? (
                  <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                ) : (
                  <Send className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                )}
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-semibold text-white truncate">{w.name}</div>
                  <div className="text-[10px] text-slate-500 font-mono uppercase">
                    {w.target_type} · {w.content_mode === "bundle_full" ? "everything" : "sigma+yara+iocs"}
                  </div>
                </div>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
