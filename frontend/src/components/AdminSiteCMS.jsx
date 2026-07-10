/**
 * AdminSiteCMS — unified control panel for site content.
 *
 * Manages three orthogonal features from a single admin tab:
 *   1. Admin tab visibility (which admin sub-tabs to show/hide)
 *   2. Landing-page section layout (enable/disable + reorder)
 *   3. Top-bar announcement banner (text, variant, expiry)
 *   4. Custom Markdown pages CRUD (published to /pages/:slug)
 *
 * All state persisted via /api/cms/*. Zero LLM / external HTTP required.
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { toast } from "sonner";
import {
  Layout, Eye, EyeOff, ArrowUp, ArrowDown, Megaphone, FileText,
  Plus, Save, Trash2, ExternalLink, Lock, RefreshCw, Upload, Image as ImageIcon,
  Palette, Copy, FolderOpen,
} from "lucide-react";
import { api } from "@/lib/api";

const inputCls =
  "w-full bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none px-3 py-2 text-sm rounded-md";

// -----------------------------------------------------------------------------
// File uploader — any format, any size (up to 25MB server-side)
// -----------------------------------------------------------------------------
function FilesCard() {
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const inputRef = useRef(null);
  const load = useCallback(async () => {
    const { data } = await api.get("/cms/files");
    setFiles(data);
  }, []);
  useEffect(() => { load(); }, [load]);

  const upload = async (fileList) => {
    if (!fileList || fileList.length === 0) return;
    setUploading(true);
    let ok = 0, fail = 0;
    for (const f of fileList) {
      const fd = new FormData();
      fd.append("file", f);
      try {
        await api.post("/cms/files", fd, { headers: { "Content-Type": "multipart/form-data" } });
        ok++;
      } catch (e) {
        fail++;
        toast.error(`${f.name}: ${e.response?.data?.detail || e.message}`);
      }
    }
    setUploading(false);
    if (ok > 0) toast.success(`${ok} file${ok === 1 ? "" : "s"} uploaded${fail ? `, ${fail} failed` : ""}.`);
    load();
    if (inputRef.current) inputRef.current.value = "";
  };

  const remove = async (f) => {
    if (!window.confirm(`Delete "${f.filename}"?`)) return;
    try { await api.delete(`/cms/files/${f.id}`); toast.success("Deleted."); load(); }
    catch (e) { toast.error(`Delete failed: ${e.response?.data?.detail || e.message}`); }
  };

  const copyUrl = (f) => {
    const base = process.env.REACT_APP_BACKEND_URL || "";
    const full = base + f.url;
    navigator.clipboard.writeText(full);
    toast.success("URL copied to clipboard");
  };

  return (
    <section className="bg-white rounded-xl border border-slate-200 p-5 col-span-full" data-testid="cms-files">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h2 className="font-heading text-base font-semibold text-slate-900 flex items-center gap-2">
            <FolderOpen className="w-4 h-4 text-slate-500" /> File uploads
          </h2>
          <p className="text-xs text-slate-500 mt-1">Logos, images, PDFs, docs — any format up to 25MB. Copy the URL to reference from custom pages or CSS.</p>
        </div>
        <label className="inline-flex items-center gap-2 rounded-md bg-[#2E7DF5] hover:bg-blue-600 text-white text-sm font-semibold px-3 py-2 cursor-pointer">
          {uploading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
          Upload files
          <input ref={inputRef} type="file" multiple onChange={(e) => upload(e.target.files)} className="hidden" data-testid="upload-input" />
        </label>
      </div>

      <div className="mt-4 grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3" data-testid="files-grid">
        {files.length === 0 && (
          <div className="col-span-full py-8 text-sm text-slate-400 text-center border-2 border-dashed border-slate-200 rounded-lg">
            No files uploaded yet.
          </div>
        )}
        {files.map((f) => {
          const isImage = f.content_type.startsWith("image/");
          const url = (process.env.REACT_APP_BACKEND_URL || "") + f.url;
          return (
            <div key={f.id} className="rounded-lg border border-slate-200 overflow-hidden bg-slate-50/50" data-testid={`file-${f.id}`}>
              <div className="aspect-square bg-slate-100 flex items-center justify-center overflow-hidden">
                {isImage ? (
                  <img src={url} alt={f.filename} className="w-full h-full object-cover" />
                ) : (
                  <FileText className="w-12 h-12 text-slate-400" />
                )}
              </div>
              <div className="p-2 space-y-1">
                <div className="text-xs font-semibold text-slate-800 truncate" title={f.filename}>{f.filename}</div>
                <div className="text-[10px] text-slate-400 font-mono">
                  {f.content_type} · {(f.size / 1024).toFixed(1)} KB
                </div>
                <div className="flex items-center gap-1">
                  <button onClick={() => copyUrl(f)} data-testid={`copy-url-${f.id}`}
                    className="flex-1 text-[10px] font-semibold text-slate-600 hover:bg-slate-100 border border-slate-200 rounded px-1.5 py-1 inline-flex items-center justify-center gap-1">
                    <Copy className="w-3 h-3" /> URL
                  </button>
                  <button onClick={() => remove(f)} data-testid={`delete-file-${f.id}`}
                    className="text-[10px] text-rose-600 hover:bg-rose-50 border border-rose-200 rounded px-1.5 py-1">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// -----------------------------------------------------------------------------
// Branding + custom CSS / JS
// -----------------------------------------------------------------------------
function BrandingCard() {
  const [b, setB] = useState({ logo_url: "", favicon_url: "", site_title: "", custom_css: "", custom_js: "" });
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    api.get("/cms/branding").then(({ data }) => setB({ ...b, ...data })).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const save = async () => {
    setSaving(true);
    try {
      await api.put("/cms/branding", b);
      toast.success("Branding saved. Reload the site to apply.");
    } catch (e) {
      toast.error(`Save failed: ${e.response?.data?.detail || e.message}`);
    } finally { setSaving(false); }
  };
  return (
    <section className="bg-white rounded-xl border border-slate-200 p-5 col-span-full" data-testid="cms-branding">
      <h2 className="font-heading text-base font-semibold text-slate-900 flex items-center gap-2">
        <Palette className="w-4 h-4 text-slate-500" /> Site branding + custom CSS / JS
      </h2>
      <p className="text-xs text-slate-500 mt-1">Upload assets in <b>Files</b> above, then paste the copied URL here. Custom CSS + JS are injected into every public page.</p>
      <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
        <div>
          <label className="block text-xs font-semibold text-slate-600 mb-1">Site title</label>
          <input value={b.site_title || ""} onChange={(e) => setB({ ...b, site_title: e.target.value })} data-testid="brand-title" className={inputCls} />
        </div>
        <div>
          <label className="block text-xs font-semibold text-slate-600 mb-1">Logo URL</label>
          <input value={b.logo_url || ""} onChange={(e) => setB({ ...b, logo_url: e.target.value })} data-testid="brand-logo" className={inputCls + " font-mono text-xs"} placeholder="/api/cms/files/…/raw" />
        </div>
        <div>
          <label className="block text-xs font-semibold text-slate-600 mb-1">Favicon URL</label>
          <input value={b.favicon_url || ""} onChange={(e) => setB({ ...b, favicon_url: e.target.value })} data-testid="brand-favicon" className={inputCls + " font-mono text-xs"} placeholder="/api/cms/files/…/raw" />
        </div>
      </div>
      <div className="mt-3">
        <label className="block text-xs font-semibold text-slate-600 mb-1">Custom CSS <span className="font-normal text-slate-400">(injected into &lt;head&gt;)</span></label>
        <textarea rows={5} value={b.custom_css || ""} onChange={(e) => setB({ ...b, custom_css: e.target.value })} data-testid="brand-css" className={inputCls + " font-mono text-xs"} placeholder="/* e.g. */ .hero-title { color: #2E7DF5 }" />
      </div>
      <div className="mt-3">
        <label className="block text-xs font-semibold text-slate-600 mb-1">Custom JS <span className="font-normal text-slate-400">(injected at end of &lt;body&gt; — use with care)</span></label>
        <textarea rows={5} value={b.custom_js || ""} onChange={(e) => setB({ ...b, custom_js: e.target.value })} data-testid="brand-js" className={inputCls + " font-mono text-xs"} placeholder="// analytics snippet, chat widget, etc." />
      </div>
      <div className="mt-3 flex justify-end">
        <button onClick={save} disabled={saving} data-testid="save-branding" className="inline-flex items-center gap-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold px-4 py-2 hover:bg-blue-600 disabled:opacity-40">
          {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          Save branding
        </button>
      </div>
    </section>
  );
}

// -----------------------------------------------------------------------------
// Admin tab visibility card
// -----------------------------------------------------------------------------
function AdminTabsCard() {
  const [tabs, setTabs] = useState([]);
  const [saving, setSaving] = useState(false);
  const load = useCallback(async () => {
    const { data } = await api.get("/cms/admin-tabs");
    setTabs(data);
  }, []);
  useEffect(() => { load(); }, [load]);

  const toggle = (id) => {
    setTabs((prev) => prev.map((t) => (t.id === id && !t.locked ? { ...t, visible: !t.visible } : t)));
  };

  const save = async () => {
    setSaving(true);
    try {
      await api.put("/cms/admin-tabs", tabs);
      toast.success("Tab visibility saved. Reload /admin to see changes.");
    } catch (e) {
      toast.error(`Save failed: ${e.response?.data?.detail || e.message}`);
    } finally { setSaving(false); }
  };

  return (
    <section className="bg-white rounded-xl border border-slate-200 p-5" data-testid="cms-admin-tabs">
      <h2 className="font-heading text-base font-semibold text-slate-900 flex items-center gap-2">
        <Layout className="w-4 h-4 text-slate-500" /> Admin tab visibility
      </h2>
      <p className="text-xs text-slate-500 mt-1">Hide sub-tabs your team doesn&apos;t use. Locked tabs (Overview + Site CMS) cannot be hidden.</p>
      <div className="mt-3 space-y-1.5">
        {tabs.map((t) => (
          <label
            key={t.id}
            className={`flex items-center gap-3 px-3 py-2 rounded border transition-colors ${t.locked ? "bg-slate-50 border-slate-200 opacity-60" : t.visible ? "bg-emerald-50/50 border-emerald-200" : "bg-slate-50 border-slate-200"}`}
            data-testid={`admin-tab-${t.id}`}
          >
            <input
              type="checkbox" checked={t.visible} disabled={t.locked}
              onChange={() => toggle(t.id)}
              className="w-4 h-4"
              data-testid={`admin-tab-toggle-${t.id}`}
            />
            <span className="flex-1 text-sm font-semibold text-slate-800">{t.label}</span>
            {t.locked && <Lock className="w-3.5 h-3.5 text-slate-400" />}
            {t.visible ? <Eye className="w-4 h-4 text-emerald-600" /> : <EyeOff className="w-4 h-4 text-slate-400" />}
          </label>
        ))}
      </div>
      <div className="mt-3 flex justify-end">
        <button
          onClick={save} disabled={saving}
          data-testid="save-admin-tabs"
          className="inline-flex items-center gap-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold px-4 py-2 hover:bg-blue-600 disabled:opacity-40"
        >
          {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          Save
        </button>
      </div>
    </section>
  );
}

// -----------------------------------------------------------------------------
// Landing-page section layout card
// -----------------------------------------------------------------------------
function LandingSectionsCard() {
  const [sections, setSections] = useState([]);
  const [saving, setSaving] = useState(false);
  const load = useCallback(async () => {
    const { data } = await api.get("/cms/landing-sections");
    setSections(data);
  }, []);
  useEffect(() => { load(); }, [load]);

  const move = (idx, dir) => {
    setSections((prev) => {
      const next = [...prev];
      const target = idx + dir;
      if (target < 0 || target >= next.length) return prev;
      [next[idx], next[target]] = [next[target], next[idx]];
      return next.map((s, i) => ({ ...s, order: i }));
    });
  };

  const toggle = (id) => {
    setSections((prev) => prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s)));
  };

  const save = async () => {
    setSaving(true);
    try {
      await api.put("/cms/landing-sections", sections);
      toast.success("Landing layout saved.");
    } catch (e) {
      toast.error(`Save failed: ${e.response?.data?.detail || e.message}`);
    } finally { setSaving(false); }
  };

  return (
    <section className="bg-white rounded-xl border border-slate-200 p-5" data-testid="cms-landing-sections">
      <h2 className="font-heading text-base font-semibold text-slate-900 flex items-center gap-2">
        <Layout className="w-4 h-4 text-slate-500" /> Landing page sections
      </h2>
      <p className="text-xs text-slate-500 mt-1">Reorder and toggle sections shown on the public landing page.</p>
      <div className="mt-3 space-y-1.5">
        {sections.map((s, idx) => (
          <div
            key={s.id}
            className={`flex items-center gap-2 px-3 py-2 rounded border ${s.enabled ? "bg-emerald-50/40 border-emerald-200" : "bg-slate-50 border-slate-200"}`}
            data-testid={`landing-section-${s.id}`}
          >
            <span className="text-[10px] font-mono w-6 text-slate-400">#{idx + 1}</span>
            <input
              type="checkbox" checked={s.enabled}
              onChange={() => toggle(s.id)}
              data-testid={`landing-toggle-${s.id}`}
              className="w-4 h-4"
            />
            <span className="flex-1 text-sm font-semibold text-slate-800">{s.label}</span>
            <button onClick={() => move(idx, -1)} disabled={idx === 0}
              className="text-slate-400 hover:text-slate-800 disabled:opacity-30" title="Move up">
              <ArrowUp className="w-4 h-4" />
            </button>
            <button onClick={() => move(idx, 1)} disabled={idx === sections.length - 1}
              className="text-slate-400 hover:text-slate-800 disabled:opacity-30" title="Move down">
              <ArrowDown className="w-4 h-4" />
            </button>
          </div>
        ))}
      </div>
      <div className="mt-3 flex justify-end">
        <button
          onClick={save} disabled={saving}
          data-testid="save-landing-sections"
          className="inline-flex items-center gap-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold px-4 py-2 hover:bg-blue-600 disabled:opacity-40"
        >
          {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          Save order
        </button>
      </div>
    </section>
  );
}

// -----------------------------------------------------------------------------
// Announcement banner card
// -----------------------------------------------------------------------------
function AnnouncementCard() {
  const [ann, setAnn] = useState({ active: false, text: "", variant: "info", href: "", dismissable: true, expires_at: "" });
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    api.get("/cms/announcement").then(({ data }) => {
      if (data && Object.keys(data).length > 1) setAnn({ ...ann, ...data, href: data.href || "", expires_at: data.expires_at || "" });
    }).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const payload = { ...ann };
      if (!payload.href) payload.href = null;
      if (!payload.expires_at) payload.expires_at = null;
      await api.put("/cms/announcement", payload);
      toast.success(ann.active ? "Announcement live." : "Announcement saved (inactive).");
    } catch (e) {
      toast.error(`Save failed: ${e.response?.data?.detail || e.message}`);
    } finally { setSaving(false); }
  };

  return (
    <section className="bg-white rounded-xl border border-slate-200 p-5" data-testid="cms-announcement">
      <h2 className="font-heading text-base font-semibold text-slate-900 flex items-center gap-2">
        <Megaphone className="w-4 h-4 text-slate-500" /> Top-bar announcement
      </h2>
      <p className="text-xs text-slate-500 mt-1">Show a dismissable banner across all public pages. Optional link + expiry.</p>
      <div className="mt-4 space-y-3">
        <label className="inline-flex items-center gap-2">
          <input type="checkbox" checked={ann.active} onChange={(e) => setAnn({ ...ann, active: e.target.checked })} data-testid="ann-active" />
          <span className="text-sm text-slate-700 font-semibold">Active</span>
        </label>
        <input
          type="text" value={ann.text} onChange={(e) => setAnn({ ...ann, text: e.target.value })}
          placeholder="e.g. NivX Forge v3 is live 🚀"
          data-testid="ann-text" className={inputCls}
        />
        <div className="grid grid-cols-2 gap-3">
          <select value={ann.variant} onChange={(e) => setAnn({ ...ann, variant: e.target.value })} data-testid="ann-variant" className={inputCls}>
            <option value="info">Info (blue)</option>
            <option value="success">Success (green)</option>
            <option value="warning">Warning (amber)</option>
            <option value="promo">Promo (purple)</option>
          </select>
          <input
            type="text" value={ann.href} onChange={(e) => setAnn({ ...ann, href: e.target.value })}
            placeholder="Optional link (https://…)"
            data-testid="ann-href" className={inputCls}
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <label className="inline-flex items-center gap-2 text-sm text-slate-700">
            <input type="checkbox" checked={ann.dismissable} onChange={(e) => setAnn({ ...ann, dismissable: e.target.checked })} data-testid="ann-dismissable" />
            Dismissable
          </label>
          <input
            type="datetime-local" value={ann.expires_at ? ann.expires_at.slice(0, 16) : ""}
            onChange={(e) => setAnn({ ...ann, expires_at: e.target.value ? new Date(e.target.value).toISOString() : "" })}
            data-testid="ann-expires"
            className={inputCls}
          />
        </div>
        <div className="flex justify-end">
          <button onClick={save} disabled={saving}
            data-testid="save-announcement"
            className="inline-flex items-center gap-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold px-4 py-2 hover:bg-blue-600 disabled:opacity-40">
            {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            Save
          </button>
        </div>
      </div>
    </section>
  );
}

// -----------------------------------------------------------------------------
// Custom pages CRUD
// -----------------------------------------------------------------------------
function PagesCard() {
  const [pages, setPages] = useState([]);
  const [editing, setEditing] = useState(null);
  const load = useCallback(async () => {
    const { data } = await api.get("/cms/pages");
    setPages(data);
  }, []);
  useEffect(() => { load(); }, [load]);

  const openCreate = () => setEditing({ slug: "", title: "", markdown_body: "# New page\n\nWrite in **Markdown**.", published: false, show_in_nav: false });
  const openEdit = (p) => setEditing({ ...p });

  const save = async (e) => {
    e.preventDefault();
    try {
      if (editing.id) {
        await api.patch(`/cms/pages/${editing.slug}`, {
          title: editing.title,
          markdown_body: editing.markdown_body,
          published: editing.published,
          show_in_nav: editing.show_in_nav,
        });
        toast.success("Page updated.");
      } else {
        await api.post("/cms/pages", editing);
        toast.success("Page created — visit /pages/" + editing.slug);
      }
      setEditing(null);
      load();
    } catch (err) {
      toast.error(`Save failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  const remove = async (slug) => {
    if (!window.confirm(`Delete page "${slug}"?`)) return;
    try {
      await api.delete(`/cms/pages/${slug}`);
      toast.success("Page deleted.");
      load();
    } catch (err) {
      toast.error(`Delete failed: ${err.response?.data?.detail || err.message}`);
    }
  };

  return (
    <section className="bg-white rounded-xl border border-slate-200 p-5 col-span-full" data-testid="cms-pages">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-heading text-base font-semibold text-slate-900 flex items-center gap-2">
            <FileText className="w-4 h-4 text-slate-500" /> Custom pages
          </h2>
          <p className="text-xs text-slate-500 mt-1">Publish Markdown pages under <code>/pages/&lt;slug&gt;</code>. Great for pricing, about, changelog etc.</p>
        </div>
        <button onClick={openCreate} data-testid="new-page-btn" className="inline-flex items-center gap-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold px-3 py-2 hover:bg-blue-600">
          <Plus className="w-4 h-4" /> New page
        </button>
      </div>

      <div className="mt-3 divide-y divide-slate-100">
        {pages.length === 0 && (
          <div className="py-6 text-sm text-slate-400 text-center">No custom pages yet.</div>
        )}
        {pages.map((p) => (
          <div key={p.id} className="py-2 flex items-center gap-3 text-sm" data-testid={`page-row-${p.slug}`}>
            <div className="flex-1 min-w-0">
              <div className="font-semibold text-slate-800 truncate">{p.title}</div>
              <a href={`/pages/${p.slug}`} target="_blank" rel="noreferrer" className="text-xs text-slate-400 hover:text-[#2E7DF5] font-mono inline-flex items-center gap-1">
                /pages/{p.slug} <ExternalLink className="w-3 h-3" />
              </a>
            </div>
            <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${p.published ? "bg-emerald-50 text-emerald-700 border border-emerald-200" : "bg-slate-100 text-slate-500 border border-slate-200"}`}>
              {p.published ? "live" : "draft"}
            </span>
            <button onClick={() => openEdit(p)} data-testid={`edit-page-${p.slug}`} className="text-xs font-semibold text-slate-700 hover:bg-slate-100 border border-slate-200 rounded px-2 py-1">Edit</button>
            <button onClick={() => remove(p.slug)} data-testid={`delete-page-${p.slug}`} className="text-xs text-rose-600 hover:bg-rose-50 border border-rose-200 rounded px-2 py-1"><Trash2 className="w-3 h-3" /></button>
          </div>
        ))}
      </div>

      {editing && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 flex items-start justify-center p-6 overflow-y-auto" onClick={() => setEditing(null)}>
          <form onSubmit={save} onClick={(e) => e.stopPropagation()} className="bg-white rounded-xl shadow-2xl max-w-3xl w-full my-6 p-6 space-y-4" data-testid="page-editor">
            <h2 className="font-heading text-lg font-semibold text-slate-900">
              {editing.id ? `Edit "${editing.title}"` : "New page"}
            </h2>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">Slug</label>
                <input required disabled={!!editing.id} value={editing.slug}
                  onChange={(e) => setEditing({ ...editing, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-") })}
                  data-testid="page-slug" placeholder="pricing"
                  className={inputCls + " font-mono disabled:bg-slate-100"} />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1">Title</label>
                <input required value={editing.title}
                  onChange={(e) => setEditing({ ...editing, title: e.target.value })}
                  data-testid="page-title" placeholder="Pricing"
                  className={inputCls} />
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1">Markdown body</label>
              <textarea required value={editing.markdown_body}
                onChange={(e) => setEditing({ ...editing, markdown_body: e.target.value })}
                rows={14} data-testid="page-body"
                className={inputCls + " font-mono text-xs"} />
            </div>
            <div className="flex items-center gap-4">
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={editing.published} onChange={(e) => setEditing({ ...editing, published: e.target.checked })} data-testid="page-published" />
                <span className="text-sm text-slate-700">Published</span>
              </label>
              <label className="inline-flex items-center gap-2">
                <input type="checkbox" checked={editing.show_in_nav} onChange={(e) => setEditing({ ...editing, show_in_nav: e.target.checked })} data-testid="page-in-nav" />
                <span className="text-sm text-slate-700">Show in nav</span>
              </label>
            </div>
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
              <button type="button" onClick={() => setEditing(null)} className="px-4 py-2 text-sm text-slate-600 hover:text-slate-900">Cancel</button>
              <button type="submit" data-testid="save-page" className="inline-flex items-center gap-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold px-5 py-2 hover:bg-blue-600">
                <Save className="w-4 h-4" /> {editing.id ? "Save" : "Create page"}
              </button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}

// -----------------------------------------------------------------------------
// Main export
// -----------------------------------------------------------------------------
export default function AdminSiteCMS() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-10 space-y-6" data-testid="admin-cms">
      <div>
        <h1 className="font-heading text-2xl font-semibold text-slate-900 flex items-center gap-2">
          <Layout className="w-6 h-6 text-[#2E7DF5]" /> Developer
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Show/hide admin tabs, reorder landing sections, run a top-bar announcement,
          publish custom Markdown pages, upload any file/logo/image, and inject
          custom CSS/JS — <strong>all offline, no LLM required</strong>.
        </p>
      </div>
      <FilesCard />
      <BrandingCard />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AdminTabsCard />
        <LandingSectionsCard />
        <AnnouncementCard />
      </div>
      <PagesCard />
    </main>
  );
}
