import React, { useEffect, useMemo, useState } from "react";
import {
  Plug,
  Plus,
  ShieldCheck,
  RefreshCw,
  Power,
  Trash2,
  X,
  Eye,
  EyeOff,
  Search,
  ListChecks,
  Users,
  ScrollText,
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  ExternalLink,
} from "lucide-react";
import { SpecialistAgent, ToolDefinition, ToolExecutionLog } from "../../types";
import { PageShell, Panel, StatTile, Pill, severityTone } from "./PageShell";
import { secureFetchWithRecovery } from "../../utils/apiClient";

const btn =
  "flex items-center gap-1.5 rounded-md border border-purple-500/40 bg-purple-500/10 px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-purple-200 transition-colors hover:bg-purple-500/20 disabled:opacity-40 disabled:cursor-not-allowed";
const btnPrimary =
  "flex items-center gap-1.5 rounded-md border border-purple-400 bg-purple-600 hover:bg-purple-500 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed";
const btnDanger =
  "flex items-center gap-1.5 rounded-md border border-rose-500/40 bg-rose-500/10 px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-rose-300 transition-colors hover:bg-rose-500/20";

function healthTone(status: ToolDefinition["health"]["status"]): string {
  if (status === "HEALTHY") return "border-emerald-500/40 text-emerald-300 bg-emerald-500/10";
  if (status === "DEGRADED") return "border-amber-500/40 text-amber-300 bg-amber-500/10";
  if (status === "DISCONNECTED") return "border-slate-500/40 text-slate-400 bg-slate-500/10";
  return "border-purple-500/40 text-purple-300 bg-purple-500/10";
}

const TABS = [
  { id: "overview", label: "Overview", icon: Plug },
  { id: "capabilities", label: "Capabilities", icon: ListChecks },
  { id: "permissions", label: "Permissions", icon: Users },
  { id: "logs", label: "Logs", icon: ScrollText },
] as const;
type TabId = (typeof TABS)[number]["id"];

export const ToolsPage: React.FC<{ agents: SpecialistAgent[] }> = ({ agents }) => {
  const [tools, setTools] = useState<ToolDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [selectedToolId, setSelectedToolId] = useState<string | null>(null);
  const [connectTarget, setConnectTarget] = useState<ToolDefinition | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [logs, setLogs] = useState<ToolExecutionLog[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [toast, setToast] = useState<{ tone: "success" | "error"; message: string } | null>(null);

  const fetchTools = async () => {
    try {
      const res = await secureFetchWithRecovery("/api/tools");
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        setTools(data.tools);
        setError(null);
      } else {
        setError(data.error || "Failed to load connected tools.");
      }
    } catch {
      setError("Network error while loading tools.");
    } finally {
      setLoading(false);
    }
  };

  const fetchLogs = async (toolId?: string) => {
    setLogsLoading(true);
    try {
      const qs = toolId ? `?toolId=${encodeURIComponent(toolId)}` : "";
      const res = await secureFetchWithRecovery(`/api/tools/logs/recent${qs}`);
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) setLogs(data.logs);
    } finally {
      setLogsLoading(false);
    }
  };

  useEffect(() => {
    fetchTools();
  }, []);

  useEffect(() => {
    if (activeTab === "logs") fetchLogs(selectedToolId || undefined);
  }, [activeTab, selectedToolId]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  const connectedCount = tools.filter((t) => t.connected && t.enabled).length;
  const healthyCount = tools.filter((t) => t.health.status === "HEALTHY").length;
  const selectedTool = tools.find((t) => t.id === selectedToolId) || null;

  const handleTest = async (toolId: string) => {
    setTestingId(toolId);
    try {
      const res = await secureFetchWithRecovery(`/api/tools/${toolId}/test`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        setToast({ tone: data.test.ok ? "success" : "error", message: `${data.test.ok ? "Connection: SUCCESS" : "Connection: FAILED"} • ${data.test.message} (${data.test.latencyMs}ms)` });
        await fetchTools();
      } else {
        setToast({ tone: "error", message: data.error || "Test failed." });
      }
    } catch {
      setToast({ tone: "error", message: "Network error while testing connection." });
    } finally {
      setTestingId(null);
    }
  };

  const handleToggleEnabled = async (tool: ToolDefinition) => {
    setBusyId(tool.id);
    try {
      const res = await secureFetchWithRecovery(`/api/tools/${tool.id}/${tool.enabled ? "disable" : "enable"}`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        await fetchTools();
      } else {
        setToast({ tone: "error", message: data.error || "Could not update tool status." });
      }
    } finally {
      setBusyId(null);
    }
  };

  const handleDisconnect = async (tool: ToolDefinition) => {
    setBusyId(tool.id);
    try {
      const res = await secureFetchWithRecovery(`/api/tools/${tool.id}`, { method: "DELETE" });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        setToast({ tone: "success", message: `${tool.name} disconnected. Credential purged from server storage.` });
        await fetchTools();
      } else {
        setToast({ tone: "error", message: data.error || "Could not disconnect tool." });
      }
    } finally {
      setBusyId(null);
    }
  };

  const handleUpdatePermissions = async (toolId: string, allowedAgents: string[], enabledCapabilities: string[]) => {
    setBusyId(toolId);
    try {
      const res = await secureFetchWithRecovery(`/api/tools/${toolId}/permissions`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ allowedAgents, enabledCapabilities }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        setToast({ tone: "success", message: "Permissions saved." });
        await fetchTools();
      } else {
        setToast({ tone: "error", message: data.error || "Could not save permissions." });
      }
    } finally {
      setBusyId(null);
    }
  };

  return (
    <PageShell
      title="Tools & Integrations"
      subtitle="Connect cybersecurity APIs once, expose their capabilities to authorized agents, execute them through a controlled gateway, and keep a complete execution/health/audit history."
      icon={<Plug className="h-4 w-4" />}
      actions={
        <button className={btn} onClick={fetchTools} title="Refresh">
          <RefreshCw className="h-3 w-3" /> Refresh
        </button>
      }
    >
      {toast && (
        <div
          className={`flex items-center gap-2 rounded-lg border px-3 py-2 font-mono text-[11px] ${
            toast.tone === "success" ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300" : "border-rose-500/40 bg-rose-500/10 text-rose-300"
          }`}
        >
          {toast.tone === "success" ? <CheckCircle2 className="h-3.5 w-3.5 shrink-0" /> : <AlertTriangle className="h-3.5 w-3.5 shrink-0" />}
          <span>{toast.message}</span>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatTile label="Registered Tools" value={tools.length} />
        <StatTile label="Connected" value={connectedCount} tone="text-emerald-300" />
        <StatTile label="Healthy" value={healthyCount} tone="text-emerald-300" />
        <StatTile label="Capabilities Exposed" value={tools.reduce((sum, t) => sum + t.capabilities.length, 0)} />
      </div>

      <div className="flex items-center gap-1.5 border-b border-purple-500/20 pb-0.5">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 rounded-t-md border-b-2 px-3 py-2 font-mono text-[10px] uppercase tracking-wider transition-colors ${
                isActive ? "border-purple-400 text-white" : "border-transparent text-purple-300/60 hover:text-purple-200"
              }`}
            >
              <Icon className="h-3 w-3" /> {tab.label}
            </button>
          );
        })}
      </div>

      {loading ? (
        <Panel>
          <div className="flex items-center justify-center gap-2 py-10 font-mono text-xs text-purple-300/60">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading tool registry…
          </div>
        </Panel>
      ) : error ? (
        <Panel>
          <div className="flex items-center gap-2 py-6 font-mono text-xs text-rose-300">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        </Panel>
      ) : activeTab === "overview" ? (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {tools.map((tool) => (
            <ToolCard
              key={tool.id}
              tool={tool}
              onConnect={() => setConnectTarget(tool)}
              onTest={() => handleTest(tool.id)}
              onToggleEnabled={() => handleToggleEnabled(tool)}
              onDisconnect={() => handleDisconnect(tool)}
              testing={testingId === tool.id}
              busy={busyId === tool.id}
            />
          ))}
        </div>
      ) : activeTab === "capabilities" ? (
        <CapabilitiesTab tools={tools} />
      ) : activeTab === "permissions" ? (
        <PermissionsTab
          tools={tools}
          agents={agents}
          selectedToolId={selectedToolId}
          onSelectTool={setSelectedToolId}
          onSave={handleUpdatePermissions}
          busy={busyId}
        />
      ) : (
        <LogsTab tools={tools} logs={logs} loading={logsLoading} selectedToolId={selectedToolId} onSelectTool={setSelectedToolId} onRefresh={() => fetchLogs(selectedToolId || undefined)} />
      )}

      {connectTarget && (
        <ConnectToolModal
          tool={connectTarget}
          onClose={() => setConnectTarget(null)}
          onConnected={async (message, tone) => {
            setConnectTarget(null);
            setToast({ tone, message });
            await fetchTools();
          }}
        />
      )}
    </PageShell>
  );
};

/* ------------------------------------------------------------------ */
/* OVERVIEW: Tool Card                                                */
/* ------------------------------------------------------------------ */

const ToolCard: React.FC<{
  tool: ToolDefinition;
  onConnect: () => void;
  onTest: () => void;
  onToggleEnabled: () => void;
  onDisconnect: () => void;
  testing: boolean;
  busy: boolean;
}> = ({ tool, onConnect, onTest, onToggleEnabled, onDisconnect, testing, busy }) => (
  <Panel
    title={tool.name}
    right={
      <Pill tone={healthTone(tool.health.status)}>
        <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-current align-middle" />
        {tool.health.status}
      </Pill>
    }
  >
    <div className="space-y-2.5">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[9px] uppercase tracking-widest text-purple-300/50">{tool.category}</span>
        <span className="font-mono text-[9px] text-purple-300/40">{tool.vendor}</span>
      </div>
      <p className="font-mono text-[11px] leading-relaxed text-purple-200/70">{tool.description}</p>

      <div className="flex flex-wrap gap-1">
        {tool.capabilities.map((c) => (
          <Pill
            key={c.id}
            tone={
              tool.connected && (tool.enabledCapabilities.length === 0 || tool.enabledCapabilities.includes(c.id))
                ? "border-purple-500/40 text-purple-300 bg-purple-500/10"
                : "border-slate-600/40 text-slate-500 bg-slate-500/5"
            }
          >
            {c.label}
          </Pill>
        ))}
      </div>

      <div className="rounded-lg border border-purple-500/15 bg-black/25 p-2 font-mono text-[9.5px] text-purple-200/75 space-y-1">
        <div className="truncate">
          <span className="text-purple-400">API URL:</span> {tool.baseUrl || tool.defaultBaseUrl}
        </div>
        <div>
          <span className="text-purple-400">Supported IOCs:</span>{" "}
          {(tool.supportedIocTypes || ["sha256", "ipv4", "domain", "url"]).map((t) => t.toUpperCase()).join(", ")}
        </div>
        <div className="flex items-center justify-between">
          <span>
            <span className="text-purple-400">Rate limit:</span>{" "}
            {tool.rateLimit || `${tool.planLimits?.[tool.planTier || "free"]?.requestsPerMinute ?? 10} req/min`}
          </span>
          <span>
            <span className="text-purple-400">Timeout:</span> {tool.timeoutMs ?? 5000}ms
          </span>
        </div>
      </div>

      {tool.connected && (
        <div className="grid grid-cols-2 gap-2 rounded-lg border border-purple-500/15 bg-purple-950/10 p-2 font-mono text-[10px] text-purple-200/60">
          <div>
            Plan: <span className="text-purple-100 uppercase">{tool.planTier || "free"}</span> ({tool.planLimits?.[tool.planTier || "free"]?.requestsPerMinute ?? 10}/min)
          </div>
          <div>
            Latency: <span className="text-purple-100">{tool.health.latencyMs != null ? `${tool.health.latencyMs}ms` : "—"}</span>
          </div>
          <div>
            Last check:{" "}
            <span className="text-purple-100">{tool.health.lastCheckedAt ? new Date(tool.health.lastCheckedAt).toLocaleTimeString() : "never"}</span>
          </div>
          {tool.health.lastError && <div className="col-span-2 truncate text-rose-300" title={tool.health.lastError}>Error: {tool.health.lastError}</div>}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-1.5 pt-1">
        {!tool.connected ? (
          <button className={btnPrimary} onClick={onConnect}>
            <Plus className="h-3 w-3" /> Connect
          </button>
        ) : (
          <>
            <button className={btn} onClick={onTest} disabled={testing}>
              {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Activity className="h-3 w-3" />} Test
            </button>
            <button className={btn} onClick={onToggleEnabled} disabled={busy}>
              <Power className="h-3 w-3" /> {tool.enabled ? "Disable" : "Enable"}
            </button>
            <button className={btn} onClick={onConnect}>
              <ShieldCheck className="h-3 w-3" /> Reconfigure
            </button>
            <button className={btnDanger} onClick={onDisconnect} disabled={busy}>
              <Trash2 className="h-3 w-3" /> Disconnect
            </button>
          </>
        )}
        <a href={tool.docsUrl} target="_blank" rel="noreferrer" className={`${btn} ml-auto`}>
          <ExternalLink className="h-3 w-3" /> Docs
        </a>
      </div>
    </div>
  </Panel>
);

/* ------------------------------------------------------------------ */
/* CONNECT / RECONFIGURE MODAL                                        */
/* ------------------------------------------------------------------ */

const ConnectToolModal: React.FC<{
  tool: ToolDefinition;
  onClose: () => void;
  onConnected: (message: string, tone: "success" | "error") => void;
}> = ({ tool, onClose, onConnected }) => {
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [baseUrl, setBaseUrl] = useState(tool.baseUrl || "");
  const [planTier, setPlanTier] = useState<"free" | "premium">(tool.planTier || "free");
  const [enabledCapabilities, setEnabledCapabilities] = useState<string[]>(
    tool.enabledCapabilities.length ? tool.enabledCapabilities : tool.capabilities.map((c) => c.id),
  );
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const toggleCapability = (id: string) =>
    setEnabledCapabilities((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) {
      setFormError("An API key is required.");
      return;
    }
    setSubmitting(true);
    setFormError(null);
    try {
      const res = await secureFetchWithRecovery(`/api/tools/${tool.id}/connect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: apiKey.trim(), baseUrl: baseUrl.trim() || undefined, planTier, enabledCapabilities }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        onConnected(
          data.test?.ok
            ? `${tool.name} connected. Connection: SUCCESS • Latency: ${data.test.latencyMs}ms • Authentication: VALID`
            : `${tool.name} saved, but the connectivity test failed: ${data.test?.message || "unknown error"}. Check the API key.`,
          data.test?.ok ? "success" : "error",
        );
      } else {
        setFormError(data.error || "Failed to save this tool.");
      }
    } catch {
      setFormError("Network error while saving this tool.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <form
        onSubmit={handleSubmit}
        className="flex max-h-[90vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl border border-purple-500/40 bg-gradient-to-b from-[#12082b] via-[#0d0520] to-[#070214] shadow-[0_0_50px_rgba(168,85,247,0.25)]"
      >
        <div className="flex items-center justify-between border-b border-purple-500/20 bg-[#160b36]/90 p-4">
          <div>
            <h2 className="font-cyber text-sm font-bold tracking-wide text-white">ADD SECURITY TOOL</h2>
            <p className="mt-0.5 font-mono text-[10px] text-purple-300/70">{tool.name} · {tool.vendor}</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-lg p-1.5 text-slate-400 hover:bg-purple-950/60 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 space-y-3.5 overflow-y-auto p-4">
          <div>
            <label className="mb-1 block font-mono text-[10px] uppercase tracking-widest text-purple-300/70">API Key</label>
            <div className="relative">
              <input
                type={showKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={tool.connected ? "•••••••••••••••••••••  (enter a new key to rotate)" : "Paste your API key"}
                className="w-full rounded-lg border border-purple-500/30 bg-[#0e0622] px-3 py-2 pr-9 font-mono text-xs text-white outline-none focus:border-purple-400"
                autoComplete="off"
              />
              <button type="button" onClick={() => setShowKey((s) => !s)} className="absolute right-2 top-1/2 -translate-y-1/2 text-purple-300/60 hover:text-purple-200">
                {showKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              </button>
            </div>
            <p className="mt-1 font-mono text-[9px] text-purple-300/40">Stored encrypted server-side. Never sent to or cached in the browser.</p>
          </div>

          <div>
            <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-widest text-purple-300/70">API Key Plan</label>
            <div className="grid grid-cols-2 gap-2">
              {(["free", "premium"] as const).map((tier) => (
                <button
                  type="button"
                  key={tier}
                  onClick={() => setPlanTier(tier)}
                  className={`rounded-lg border p-2.5 text-left font-mono text-[11px] transition-colors ${
                    planTier === tier ? "border-purple-400 bg-purple-500/15 text-white" : "border-purple-500/20 bg-purple-950/10 text-purple-300/60 hover:border-purple-500/40"
                  }`}
                >
                  <span className="block font-bold uppercase tracking-wide">{tier}</span>
                  <span className="mt-1 block text-[9px] leading-snug text-purple-300/50">{tool.planLimits[tier].note}</span>
                  <span className="mt-1 block text-[9px] text-purple-300/70">{tool.planLimits[tier].requestsPerMinute} req/min cap</span>
                </button>
              ))}
            </div>
            <p className="mt-1 font-mono text-[9px] text-purple-300/40">
              Sets the internal rate limit to match your key's real quota — same endpoints either way, this just stops NEXSUS from over-calling a free-tier key.
            </p>
          </div>

          <div>
            <label className="mb-1 block font-mono text-[10px] uppercase tracking-widest text-purple-300/70">Base URL</label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder={tool.defaultBaseUrl}
              className="w-full rounded-lg border border-purple-500/30 bg-[#0e0622] px-3 py-2 font-mono text-xs text-white outline-none focus:border-purple-400"
            />
            <p className="mt-1 font-mono text-[9px] text-purple-300/40">Optional — only a regional endpoint for the same vendor is accepted.</p>
          </div>

          <div>
            <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-widest text-purple-300/70">Capabilities</label>
            <div className="space-y-1.5">
              {tool.capabilities.map((c) => (
                <label key={c.id} className="flex items-start gap-2 rounded-lg border border-purple-500/15 bg-purple-950/10 p-2 font-mono text-[11px] text-purple-200/80">
                  <input
                    type="checkbox"
                    checked={enabledCapabilities.includes(c.id)}
                    onChange={() => toggleCapability(c.id)}
                    className="mt-0.5 accent-purple-500"
                  />
                  <span>
                    <span className="text-white">{c.label}</span>
                    <span className="block text-[10px] text-purple-300/50">{c.description}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          {formError && (
            <div className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 p-2 font-mono text-[10px] text-rose-300">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> {formError}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-purple-500/20 bg-[#0e0622] p-3">
          <button type="button" onClick={onClose} className={btn}>
            Cancel
          </button>
          <button type="submit" className={btnPrimary} disabled={submitting}>
            {submitting ? <Loader2 className="h-3 w-3 animate-spin" /> : <ShieldCheck className="h-3 w-3" />} Save Tool
          </button>
        </div>
      </form>
    </div>
  );
};

/* ------------------------------------------------------------------ */
/* CAPABILITIES TAB                                                    */
/* ------------------------------------------------------------------ */

const CapabilitiesTab: React.FC<{ tools: ToolDefinition[] }> = ({ tools }) => {
  const byCapability = useMemo(() => {
    const map = new Map<string, { label: string; tools: ToolDefinition[] }>();
    tools.forEach((tool) => {
      tool.capabilities.forEach((c) => {
        const entry = map.get(c.id) || { label: c.label, tools: [] };
        entry.tools.push(tool);
        map.set(c.id, entry);
      });
    });
    return Array.from(map.entries()).sort((a, b) => a[1].label.localeCompare(b[1].label));
  }, [tools]);

  return (
    <Panel title="Capability → Tool Resolution">
      <p className="mb-3 font-mono text-[10px] leading-relaxed text-purple-300/50">
        The rest of NEXSUS never calls a vendor API directly — it asks the Tool Registry for a capability (e.g. "I need hash.lookup") and the
        registry resolves it to the first connected, enabled tool that supports it, in this order.
      </p>
      <div className="space-y-2">
        {byCapability.map(([capId, entry]) => (
          <div key={capId} className="flex flex-wrap items-center gap-2 rounded-lg border border-purple-500/15 bg-purple-950/10 p-2.5">
            <span className="w-40 shrink-0 font-mono text-[11px] font-bold text-white">{entry.label}</span>
            <span className="font-mono text-[9px] text-purple-300/40">{capId}</span>
            <div className="ml-auto flex flex-wrap gap-1.5">
              {entry.tools.map((t, idx) => (
                <Pill
                  key={t.id}
                  tone={
                    t.connected && t.enabled
                      ? idx === 0 || !entry.tools.slice(0, idx).some((x) => x.connected && x.enabled)
                        ? "border-emerald-500/40 text-emerald-300 bg-emerald-500/10"
                        : "border-purple-500/40 text-purple-300 bg-purple-500/10"
                      : "border-slate-600/40 text-slate-500 bg-slate-500/5"
                  }
                >
                  {t.name}
                </Pill>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
};

/* ------------------------------------------------------------------ */
/* PERMISSIONS TAB                                                     */
/* ------------------------------------------------------------------ */

const PermissionsTab: React.FC<{
  tools: ToolDefinition[];
  agents: SpecialistAgent[];
  selectedToolId: string | null;
  onSelectTool: (id: string) => void;
  onSave: (toolId: string, allowedAgents: string[], enabledCapabilities: string[]) => void;
  busy: string | null;
}> = ({ tools, agents, selectedToolId, onSelectTool, onSave, busy }) => {
  const activeTool = tools.find((t) => t.id === selectedToolId) || tools[0] || null;
  const [allowedAgents, setAllowedAgents] = useState<string[]>(activeTool?.allowedAgents || []);
  const [enabledCapabilities, setEnabledCapabilities] = useState<string[]>(activeTool?.enabledCapabilities || []);

  useEffect(() => {
    setAllowedAgents(activeTool?.allowedAgents || []);
    setEnabledCapabilities(activeTool?.enabledCapabilities.length ? activeTool.enabledCapabilities : activeTool?.capabilities.map((c) => c.id) || []);
  }, [activeTool?.id]);

  if (!activeTool) {
    return (
      <Panel>
        <p className="py-6 text-center font-mono text-xs text-purple-300/50">Connect a tool to configure permissions.</p>
      </Panel>
    );
  }

  const toggleAgent = (name: string) => setAllowedAgents((prev) => (prev.includes(name) ? prev.filter((a) => a !== name) : [...prev, name]));
  const toggleCapability = (id: string) => setEnabledCapabilities((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]));

  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-4">
      <Panel title="Tool" className="lg:col-span-1">
        <div className="space-y-1">
          {tools.map((t) => (
            <button
              key={t.id}
              onClick={() => onSelectTool(t.id)}
              className={`flex w-full items-center justify-between rounded-md px-2.5 py-2 font-mono text-[11px] transition-colors ${
                activeTool.id === t.id ? "bg-purple-500/20 text-white" : "text-purple-300/60 hover:bg-purple-500/10 hover:text-purple-200"
              }`}
            >
              {t.name}
              {!t.connected && <span className="text-[9px] text-slate-500">not connected</span>}
            </button>
          ))}
        </div>
      </Panel>

      <Panel title={activeTool.name} right={<span className="font-mono text-[9px] text-purple-300/40">Allowed Agents</span>} className="lg:col-span-1">
        <div className="space-y-1">
          {agents.map((agent) => (
            <label key={agent.id} className="flex items-center gap-2 rounded-md px-1.5 py-1.5 font-mono text-[11px] text-purple-200/80 hover:bg-purple-500/5">
              <input type="checkbox" checked={allowedAgents.includes(agent.name)} onChange={() => toggleAgent(agent.name)} className="accent-purple-500" />
              {agent.name} Agent
            </label>
          ))}
          {allowedAgents.length === 0 && (
            <p className="mt-1 font-mono text-[9px] text-amber-300/70">No agents selected = every agent is allowed (open access).</p>
          )}
        </div>
      </Panel>

      <Panel title="Allowed Actions" className="lg:col-span-1">
        <div className="space-y-1">
          {activeTool.capabilities.map((c) => (
            <label key={c.id} className="flex items-center gap-2 rounded-md px-1.5 py-1.5 font-mono text-[11px] text-purple-200/80 hover:bg-purple-500/5">
              <input type="checkbox" checked={enabledCapabilities.includes(c.id)} onChange={() => toggleCapability(c.id)} className="accent-purple-500" />
              {c.label}
            </label>
          ))}
        </div>
      </Panel>

      <Panel title="Summary" className="lg:col-span-1">
        <div className="space-y-2 font-mono text-[10px] text-purple-200/70">
          <p>
            <span className="text-purple-300/50">Agents:</span> {allowedAgents.length === 0 ? "All" : allowedAgents.join(", ")}
          </p>
          <p>
            <span className="text-purple-300/50">Actions:</span> {enabledCapabilities.length === 0 ? "None" : enabledCapabilities.length}
          </p>
          <button
            className={`${btnPrimary} mt-2 w-full justify-center`}
            disabled={busy === activeTool.id || !activeTool.connected}
            onClick={() => onSave(activeTool.id, allowedAgents, enabledCapabilities)}
          >
            {busy === activeTool.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <ShieldCheck className="h-3 w-3" />} Save Permissions
          </button>
          {!activeTool.connected && <p className="text-amber-300/70">Connect this tool before assigning permissions.</p>}
        </div>
      </Panel>
    </div>
  );
};

/* ------------------------------------------------------------------ */
/* LOGS TAB                                                            */
/* ------------------------------------------------------------------ */

const statusTone = (status: ToolExecutionLog["status"]) => {
  if (status === "SUCCESS") return "border-emerald-500/40 text-emerald-300 bg-emerald-500/10";
  if (status === "DENIED") return "border-amber-500/40 text-amber-300 bg-amber-500/10";
  return "border-rose-500/40 text-rose-300 bg-rose-500/10";
};

const LogsTab: React.FC<{
  tools: ToolDefinition[];
  logs: ToolExecutionLog[];
  loading: boolean;
  selectedToolId: string | null;
  onSelectTool: (id: string | null) => void;
  onRefresh: () => void;
}> = ({ tools, logs, loading, selectedToolId, onSelectTool, onRefresh }) => (
  <Panel
    title="Tool Execution Log"
    right={
      <div className="flex items-center gap-2">
        <select
          value={selectedToolId || ""}
          onChange={(e) => onSelectTool(e.target.value || null)}
          className="rounded-md border border-purple-500/30 bg-[#0e0622] px-2 py-1 font-mono text-[10px] text-purple-200 outline-none"
        >
          <option value="">All Tools</option>
          {tools.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
        <button className={btn} onClick={onRefresh}>
          <RefreshCw className="h-3 w-3" /> Refresh
        </button>
      </div>
    }
  >
    {loading ? (
      <div className="flex items-center justify-center gap-2 py-8 font-mono text-xs text-purple-300/60">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading execution log…
      </div>
    ) : logs.length === 0 ? (
      <div className="flex items-center gap-2 py-8 justify-center font-mono text-xs text-purple-300/50">
        <Search className="h-4 w-4" /> No tool executions recorded yet.
      </div>
    ) : (
      <div className="overflow-x-auto">
        <table className="w-full font-mono text-[11px]">
          <thead>
            <tr className="border-b border-purple-500/20 text-left text-[9px] uppercase tracking-widest text-purple-300/50">
              <th className="py-1.5 pr-3">Tool</th>
              <th className="py-1.5 pr-3">Action</th>
              <th className="py-1.5 pr-3">Requested By</th>
              <th className="py-1.5 pr-3">Case</th>
              <th className="py-1.5 pr-3">Status</th>
              <th className="py-1.5 pr-3">Verdict</th>
              <th className="py-1.5 pr-3">Latency</th>
              <th className="py-1.5">Time</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id} className="border-b border-purple-500/10 text-purple-200/80">
                <td className="py-1.5 pr-3 text-white">{tools.find((t) => t.id === log.toolId)?.name || log.toolId}</td>
                <td className="py-1.5 pr-3">{log.action}</td>
                <td className="py-1.5 pr-3">{log.requestedBy}</td>
                <td className="py-1.5 pr-3">{log.caseId || "—"}</td>
                <td className="py-1.5 pr-3">
                  <Pill tone={statusTone(log.status)}>
                    {log.status === "SUCCESS" ? <CheckCircle2 className="mr-1 inline h-2.5 w-2.5" /> : log.status === "DENIED" ? <AlertTriangle className="mr-1 inline h-2.5 w-2.5" /> : <XCircle className="mr-1 inline h-2.5 w-2.5" />}
                    {log.status}
                  </Pill>
                </td>
                <td className="py-1.5 pr-3">
                  {log.verdict ? <Pill tone={severityTone(log.verdict)}>{log.verdict}</Pill> : <span className="text-purple-300/30">—</span>}
                </td>
                <td className="py-1.5 pr-3">{log.latencyMs}ms</td>
                <td className="py-1.5 text-purple-300/50">{new Date(log.createdAt).toLocaleTimeString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </Panel>
);
