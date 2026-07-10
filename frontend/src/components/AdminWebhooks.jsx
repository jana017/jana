/**
 * AdminWebhooks — CRUD manager for EDR/SIEM webhooks with delivery history.
 *
 * Ships alongside `PushToSIEMButton` (NivX Forge). Together they let a SOC
 * team push generated Sigma / YARA / IOC bundles directly to Splunk, Sentinel,
 * Elastic, CrowdStrike, Slack, Discord, Teams — or any custom HTTPS endpoint.
 */
import { useState, useEffect, useCallback } from "react";
import { toast } from "sonner";
import {
  Plus, Trash2, Pencil, Send, RefreshCw, ExternalLink,
  CheckCircle2, XCircle, Zap, ShieldCheck, Webhook,
} from "lucide-react";
import { api } from "@/lib/api";

const inputCls =
  "w-full bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none px-3 py-2 text-sm text-slate-800 placeholder:text-slate-400 rounded-md";

const EMPTY = {
  name: "",
  target_type: "custom",
  url: "",
  method: "POST",
  headers: {},
  payload_template: "",
  content_mode: "bundle_iocs",
  enabled: true,
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
function headersToText(obj) {
  return Object.entries(obj || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

function textToHeaders(text) {
  const out = {};
  for (const line of (text || "").split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx < 0) continue;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function StatusBadge({ status }) {
  if (status === "ok")
    return (
      <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 rounded px-1.5 py-0.5">
        <CheckCircle2 className="w-3 h-3" /> ok
      </span>
    );
  if (status === "failed")
    return (
      <span className="inline-flex items-center gap-1 text-xs font-semibold text-rose-700 bg-rose-50 border border-rose-200 rounded px-1.5 py-0.5">
        <XCircle className="w-3 h-3" /> failed
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-500 bg-slate-50 border border-slate-200 rounded px-1.5 py-0.5">
      never
    </span>
  );
}

// -----------------------------------------------------------------------------
// Main component
// -----------------------------------------------------------------------------
export default function AdminWebhooks() {
  const [webhooks, setWebhooks] = useState([]);
  const [presets, setPresets] = useState([]);
  const [deliveries, setDeliveries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(null); // null | webhook doc | EMPTY
  const [headersText, setHeadersText] = useState("");

  const load = useCallback(async () => {
    try {
      const [w, p, d] = await Promise.all([
        api.get("/webhooks"),
        api.get("/webhooks/presets"),
        api.get("/webhooks/deliveries?limit=100"),
      ]);
      setWebhooks(w.data);
      setPresets(p.data);
      setDeliveries(d.data);
    } catch (e) {
      toast.error(`Failed to load webhooks: ${e.response?.data?.detail || e.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const applyPreset = (presetId) => {
    const p = presets.find((x) => x.id === presetId);
    if (!p) return;
    setEditing((prev) => ({
      ...prev,
      target_type: p.id,
      method: p.method,
      headers: { ...p.headers_template },
      payload_template: p.payload_template,
    }));
    setHeadersText(headersToText(p.headers_template));
  };

  const openCreate = () => {
    const custom = presets.find((x) => x.id === "custom");
    const base = {
      ...EMPTY,
      headers: custom ? { ...custom.headers_template } : {},
      payload_template: custom ? custom.payload_template : "",
    };
    setEditing(base);
    setHeadersText(headersToText(base.headers));
  };

  const openEdit = (w) => {
    setEditing({ ...w });
    setHeadersText(headersToText(w.headers));
  };

  const save = async (e) => {
    e.preventDefault();
    const payload = {
      ...editing,
      headers: textToHeaders(headersText),
    };
    try {
      if (editing.id) {
        const { data } = await api.patch(`/webhooks/${editing.id}`, payload);
        toast.success(`Webhook "${data.name}" updated`);
      } else {
        const { data } = await api.post("/webhooks", payload);
        toast.success(`Webhook "${data.name}" created`);
      }
      setEditing(null);
      await load();
    } catch (e) {
      toast.error(`Save failed: ${e.response?.data?.detail || e.message}`);
    }
  };

  const remove = async (w) => {
    if (!window.confirm(`Delete webhook "${w.name}"?`)) return;
    try {
      await api.delete(`/webhooks/${w.id}`);
      toast.success("Webhook deleted");
      await load();
    } catch (e) {
      toast.error(`Delete failed: ${e.response?.data?.detail || e.message}`);
    }
  };

  const testPush = async (w) => {
    toast.info(`Testing "${w.name}"…`);
    try {
      const { data } = await api.post(`/webhooks/${w.id}/test`);
      if (data.status === "ok") {
        toast.success(`Test OK — HTTP ${data.http_status} (${data.attempts} attempt${data.attempts !== 1 ? "s" : ""})`);
      } else {
        toast.error(`Test failed — HTTP ${data.http_status || "n/a"}: ${data.error || "no response"}`);
      }
      await load();
    } catch (e) {
      toast.error(`Test failed: ${e.response?.data?.detail || e.message}`);
    }
  };

  if (loading) {
    return (
      <div className="mx-auto max-w-7xl px-6 py-10 text-slate-500" data-testid="admin-webhooks-loading">
        Loading webhooks…
      </div>
    );
  }

  return (
    <main className="mx-auto max-w-7xl px-6 py-10 space-y-8" data-testid="admin-webhooks">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-heading text-2xl font-semibold text-slate-900 flex items-center gap-2">
            <Webhook className="w-6 h-6 text-[#2E7DF5]" />
            EDR / SIEM Webhooks
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Push NivX Forge analysis (Sigma, YARA, IOCs) directly to Splunk, Sentinel, Elastic,
            CrowdStrike, Slack, Discord, Teams — or any custom HTTPS endpoint.
          </p>
        </div>
        <button
          data-testid="webhook-new-btn"
          onClick={openCreate}
          className="inline-flex items-center gap-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold px-4 py-2 hover:bg-blue-600 transition-colors"
        >
          <Plus className="w-4 h-4" /> New webhook
        </button>
      </div>

      {/* Table */}
      <section className="bg-white rounded-xl border border-slate-200 overflow-hidden" data-testid="webhook-list">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-xs font-semibold uppercase text-slate-500">
            <tr>
              <th className="px-4 py-3 text-left">Name</th>
              <th className="px-4 py-3 text-left">Target</th>
              <th className="px-4 py-3 text-left">Content</th>
              <th className="px-4 py-3 text-left">Last</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {webhooks.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-slate-400">
                  No webhooks yet. Create one to push rules to your SIEM/EDR.
                </td>
              </tr>
            )}
            {webhooks.map((w) => (
              <tr key={w.id} className="border-t border-slate-100 hover:bg-slate-50/50" data-testid={`webhook-row-${w.id}`}>
                <td className="px-4 py-3">
                  <div className="font-semibold text-slate-900">{w.name}</div>
                  <div className="text-xs text-slate-400 font-mono truncate max-w-[280px]">{w.url}</div>
                  {!w.enabled && <span className="text-[10px] font-bold text-amber-600 uppercase">Disabled</span>}
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs font-mono text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">
                    {w.target_type}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-slate-600">
                  {w.content_mode === "bundle_full" ? "Everything" : "Sigma+YARA+IOCs"}
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={w.last_status} />
                  {w.last_sent_at && (
                    <div className="text-[10px] text-slate-400 mt-0.5">
                      {new Date(w.last_sent_at).toLocaleString()}
                    </div>
                  )}
                </td>
                <td className="px-4 py-3 text-right space-x-1">
                  <button
                    onClick={() => testPush(w)}
                    data-testid={`webhook-test-${w.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:bg-emerald-50 border border-emerald-200 rounded px-2 py-1"
                    title="Send synthetic test payload"
                  >
                    <Zap className="w-3 h-3" /> Test
                  </button>
                  <button
                    onClick={() => openEdit(w)}
                    data-testid={`webhook-edit-${w.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-slate-700 hover:bg-slate-100 border border-slate-200 rounded px-2 py-1"
                  >
                    <Pencil className="w-3 h-3" /> Edit
                  </button>
                  <button
                    onClick={() => remove(w)}
                    data-testid={`webhook-delete-${w.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-rose-700 hover:bg-rose-50 border border-rose-200 rounded px-2 py-1"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* Delivery history */}
      <section className="bg-white rounded-xl border border-slate-200 overflow-hidden" data-testid="webhook-deliveries">
        <div className="px-4 py-3 border-b border-slate-100 flex items-center justify-between">
          <h2 className="font-heading text-sm font-semibold text-slate-900 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-slate-500" /> Delivery audit log
            <span className="text-xs font-normal text-slate-400">last {deliveries.length} pushes</span>
          </h2>
          <button
            onClick={load}
            data-testid="webhook-reload-deliveries"
            className="inline-flex items-center gap-1 text-xs font-semibold text-slate-600 hover:text-slate-900"
          >
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
        <div className="max-h-[400px] overflow-y-auto">
          {deliveries.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-slate-400">No deliveries yet.</div>
          )}
          {deliveries.map((d) => (
            <div key={d.id} className="px-4 py-2.5 border-b border-slate-50 flex items-center gap-3 text-xs hover:bg-slate-50/50" data-testid={`delivery-${d.id}`}>
              <StatusBadge status={d.status} />
              <div className="flex-1 min-w-0">
                <div className="font-semibold text-slate-800 truncate">{d.webhook_name}</div>
                <div className="text-slate-500 truncate">{d.content_summary}</div>
                {d.error && <div className="text-rose-600 truncate">{d.error}</div>}
              </div>
              <div className="text-right shrink-0">
                <div className="font-mono text-slate-600">
                  HTTP {d.http_status ?? "—"} · {d.attempts} try{d.attempts !== 1 ? "s" : ""}
                </div>
                <div className="text-slate-400">{new Date(d.sent_at).toLocaleString()}</div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Editor modal */}
      {editing && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 flex items-start justify-center p-6 overflow-y-auto" onClick={() => setEditing(null)}>
          <form
            onSubmit={save}
            onClick={(e) => e.stopPropagation()}
            className="bg-white rounded-xl shadow-2xl max-w-3xl w-full my-6 p-6 space-y-4"
            data-testid="webhook-editor"
          >
            <div className="flex items-center justify-between">
              <h2 className="font-heading text-lg font-semibold text-slate-900">
                {editing.id ? `Edit "${editing.name}"` : "New webhook"}
              </h2>
              <button type="button" onClick={() => setEditing(null)} className="text-slate-400 hover:text-slate-700">✕</button>
            </div>

            {!editing.id && (
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">Start from preset</label>
                <div className="flex flex-wrap gap-2" data-testid="preset-picker">
                  {presets.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => applyPreset(p.id)}
                      data-testid={`preset-${p.id}`}
                      className={`text-xs font-semibold px-2.5 py-1 rounded border transition-colors ${
                        editing.target_type === p.id
                          ? "bg-[#2E7DF5] text-white border-[#2E7DF5]"
                          : "bg-white text-slate-700 border-slate-300 hover:border-[#2E7DF5]"
                      }`}
                    >
                      {p.name}
                    </button>
                  ))}
                </div>
                {(() => {
                  const cur = presets.find((p) => p.id === editing.target_type);
                  return cur?.notes ? (
                    <div className="text-xs text-slate-500 mt-2 flex items-start gap-1.5">
                      <ExternalLink className="w-3 h-3 mt-0.5 shrink-0" />
                      <span>
                        {cur.notes}{" "}
                        <a href={cur.docs_url} target="_blank" rel="noreferrer" className="text-[#2E7DF5] underline">docs ↗</a>
                      </span>
                    </div>
                  ) : null;
                })()}
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">Name</label>
                <input
                  required data-testid="webhook-name"
                  value={editing.name}
                  onChange={(e) => setEditing({ ...editing, name: e.target.value })}
                  placeholder="e.g. Prod Splunk"
                  className={inputCls}
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">Method</label>
                <select
                  data-testid="webhook-method"
                  value={editing.method}
                  onChange={(e) => setEditing({ ...editing, method: e.target.value })}
                  className={inputCls}
                >
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">URL</label>
              <input
                required data-testid="webhook-url"
                type="url"
                value={editing.url}
                onChange={(e) => setEditing({ ...editing, url: e.target.value })}
                placeholder="https://your-siem.example.com/webhook"
                className={`${inputCls} font-mono`}
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Headers <span className="font-normal text-slate-400">(key: value, one per line — secret values shown as *** when saved)</span>
              </label>
              <textarea
                data-testid="webhook-headers"
                value={headersText}
                onChange={(e) => setHeadersText(e.target.value)}
                rows={4}
                placeholder="Content-Type: application/json&#10;Authorization: Bearer xyz"
                className={`${inputCls} font-mono`}
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">
                Payload template <span className="font-normal text-slate-400">(Jinja-style: {"{{ verdict }}"}, {"{{ risk_score }}"}, {"{{ summary_json }}"}, {"{{ sigma_rule_json }}"}, {"{{ iocs_json }}"}, {"{{ mitre_json }}"}, {"{{ has_sigma }}"}, {"{{ severity_word }}"}, {"{{ sent_at }}"})</span>
              </label>
              <textarea
                required data-testid="webhook-template"
                value={editing.payload_template}
                onChange={(e) => setEditing({ ...editing, payload_template: e.target.value })}
                rows={10}
                className={`${inputCls} font-mono text-xs`}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">Content mode</label>
                <select
                  data-testid="webhook-content-mode"
                  value={editing.content_mode}
                  onChange={(e) => setEditing({ ...editing, content_mode: e.target.value })}
                  className={inputCls}
                >
                  <option value="bundle_iocs">Sigma + YARA + IOCs (lean)</option>
                  <option value="bundle_full">Everything (Sigma + YARA + queries + IOCs + MITRE)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">Enabled</label>
                <label className="inline-flex items-center gap-2 mt-2">
                  <input
                    type="checkbox"
                    data-testid="webhook-enabled"
                    checked={editing.enabled}
                    onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })}
                  />
                  <span className="text-sm text-slate-700">Active — analysts can push to this endpoint</span>
                </label>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setEditing(null)}
                className="px-4 py-2 text-sm font-semibold text-slate-600 hover:text-slate-900"
              >
                Cancel
              </button>
              <button
                type="submit"
                data-testid="webhook-save"
                className="inline-flex items-center gap-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold px-5 py-2 hover:bg-blue-600"
              >
                <Send className="w-4 h-4" /> {editing.id ? "Save changes" : "Create webhook"}
              </button>
            </div>
          </form>
        </div>
      )}
    </main>
  );
}
