import React, { useMemo, useState } from "react";
import {
  FolderArchive,
  FileText,
  Clock,
  Download,
  Plus,
  Search,
  Radar,
  UploadCloud,
  Bot,
  FolderOpen,
  Paperclip,
  Trash2,
  ExternalLink,
  CheckCircle2,
  XCircle,
  ShieldAlert,
  GitCommit,
} from "lucide-react";
import { CaseItem, ActivityItem, StreamEvent, SpecialistAgent, EvidenceArtifact } from "../../types";
import { PageShell, Panel, StatTile, Pill, severityTone } from "./PageShell";
import { AgentCard } from "../command-center/AgentCard";
import {
  correlateFindingsAcrossAgents,
  buildVerificationMatrix,
  buildAgentConsensus,
  buildFinalVerdictDetail,
} from "../../utils/multiAgentAnalysis";
import { extractIOCs, formatNumberedIOCList } from "../../utils/iocExtraction";

const btn =
  "flex items-center gap-1.5 rounded-md border border-purple-500/40 bg-purple-500/10 px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-purple-200 transition-colors hover:bg-purple-500/20";

export const CasesPage: React.FC<{
  cases: CaseItem[];
  onSelectCase: (c: CaseItem) => void;
  onNewCase: () => void;
}> = ({ cases, onSelectCase, onNewCase }) => {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");

  const filtered = useMemo(
    () =>
      cases.filter(
        (c) =>
          (severity === "ALL" || (c.severity || "").toLowerCase() === severity.toLowerCase()) &&
          `${c.title} ${c.caseNumber} ${c.assignedAgent}`
            .toLowerCase()
            .includes(query.toLowerCase()),
      ),
    [cases, query, severity],
  );

  return (
    <PageShell
      title="CASE REGISTRY"
      subtitle="Every incident intake tracked by the ARCHON orchestrator, with assigned specialist, IOC yield and verification confidence."
      icon={<FolderArchive className="h-4 w-4" />}
      actions={
        <button onClick={onNewCase} className={btn}>
          <Plus className="h-3 w-3" /> New Case
        </button>
      }
    >
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Total Cases" value={cases.length} />
        <StatTile
          label="Critical"
          value={cases.filter((c) => (c.severity || "").toLowerCase() === "critical").length}
          tone="text-rose-300"
        />
        <StatTile
          label="In Progress"
          value={cases.filter((c) => (c.status || "").toLowerCase().includes("progress")).length}
          tone="text-amber-300"
        />
        <StatTile
          label="Avg Confidence"
          value={`${Math.round(cases.reduce((a, c) => a + (c.confidence || 0), 0) / Math.max(cases.length, 1))}%`}
          tone="text-emerald-300"
        />
      </div>

      <Panel
        title={`CASES (${filtered.length})`}
        right={
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 rounded border border-purple-500/30 bg-black/40 px-2 py-1">
              <Search className="h-3 w-3 text-purple-400" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter cases…"
                className="w-36 bg-transparent font-mono text-[10px] text-purple-100 outline-none placeholder:text-purple-300/40"
              />
            </div>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="rounded border border-purple-500/30 bg-black/40 px-2 py-1 font-mono text-[10px] text-purple-200 outline-none"
            >
              {["ALL", "Critical", "High", "Medium", "Low"].map((s) => (
                <option key={s} value={s} className="bg-[#0b0418]">
                  {s}
                </option>
              ))}
            </select>
          </div>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left">
            <thead>
              <tr className="border-b border-purple-500/20 font-mono text-[9px] uppercase tracking-[0.15em] text-purple-300/60">
                <th className="py-2">Case</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Assigned</th>
                <th>IOCs</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((c) => (
                <tr
                  key={c.id}
                  onClick={() => onSelectCase(c)}
                  className="cursor-pointer border-b border-purple-500/10 transition-colors hover:bg-purple-500/10"
                >
                  <td className="py-2 font-mono text-[10px] text-purple-300">{c.caseNumber}</td>
                  <td className="pr-3 font-mono text-[11px] text-white">{c.title}</td>
                  <td>
                    <Pill tone={severityTone(c.severity)}>{c.severity}</Pill>
                  </td>
                  <td className="font-mono text-[10px] text-purple-200/70">{c.status}</td>
                  <td className="font-mono text-[10px] text-purple-200/70">{c.assignedAgent}</td>
                  <td className="font-mono text-[10px] text-rose-300">{c.iocCount}</td>
                  <td className="font-mono text-[10px] text-emerald-300">{c.confidence}%</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="py-6 text-center font-mono text-[10px] text-purple-300/50"
                  >
                    No cases match the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </PageShell>
  );
};

export const ReportsPage: React.FC<{
  cases: CaseItem[];
  onSelectCase: (c: CaseItem) => void;
  onExportLogs: () => void;
}> = ({ cases, onSelectCase, onExportLogs }) => {
  const [selected, setSelected] = useState<CaseItem | undefined>(cases[0]);
  const active = selected || cases[0];

  return (
    <PageShell
      title="INVESTIGATION REPORTS"
      subtitle="Auto-generated incident write-ups assembled from correlated agent findings, verified IOCs and MITRE mappings."
      icon={<FileText className="h-4 w-4" />}
      actions={
        <button onClick={onExportLogs} className={btn}>
          <Download className="h-3 w-3" /> Export Logs
        </button>
      }
    >
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Panel title="REPORT INDEX" className="lg:col-span-1">
          <div className="space-y-1.5">
            {cases.map((c) => (
              <button
                key={c.id}
                onClick={() => setSelected(c)}
                className={`w-full rounded-lg border p-2 text-left transition-colors ${
                  active?.id === c.id
                    ? "border-purple-400/60 bg-purple-500/15"
                    : "border-purple-500/20 hover:bg-purple-500/10"
                }`}
              >
                <p className="font-mono text-[9px] text-purple-300/70">
                  RPT-{c.caseNumber} · {c.timestamp}
                </p>
                <p className="font-mono text-[11px] text-white">{c.title}</p>
              </button>
            ))}
          </div>
        </Panel>

        <Panel title={active ? `RPT-${active.caseNumber}` : "REPORT"} className="lg:col-span-2">
          {active ? (
            <div className="space-y-3 font-mono text-[11px] leading-relaxed text-purple-100/80">
              <div className="flex flex-wrap gap-2">
                <Pill tone={severityTone(active.severity)}>{active.severity}</Pill>
                <Pill>{active.status}</Pill>
                <Pill>Confidence {active.confidence}%</Pill>
                <Pill>{active.iocCount} IOCs</Pill>
              </div>
              <div>
                <p className="mb-1 font-cyber text-[10px] tracking-[0.2em] text-purple-300">
                  EXECUTIVE SUMMARY
                </p>
                <p>
                  Incident <span className="text-white">{active.title}</span> was escalated to
                  Commander ARCHON and delegated to{" "}
                  <span className="text-white">{active.assignedAgent}</span>. Specialist analysis
                  correlated {active.iocCount} indicators across telemetry, threat intel and
                  forensic artifacts, producing a verified verdict at {active.confidence}%
                  confidence.
                </p>
              </div>
              <div>
                <p className="mb-1 font-cyber text-[10px] tracking-[0.2em] text-purple-300">
                  METHODOLOGY
                </p>
                <ul className="list-disc space-y-1 pl-4">
                  <li>Intake triage and severity scoring by the orchestrator.</li>
                  <li>Task decomposition into malware, network and intel work packages.</li>
                  <li>Parallel specialist execution with streamed progress telemetry.</li>
                  <li>Cross-agent IOC correlation and verification pass.</li>
                </ul>
              </div>
              <div>
                <p className="mb-1 font-cyber text-[10px] tracking-[0.2em] text-purple-300">
                  RECOMMENDED ACTIONS
                </p>
                <ul className="list-disc space-y-1 pl-4">
                  <li>Block all malicious indicators at the perimeter and DNS layer.</li>
                  <li>Isolate affected hosts and capture volatile memory for deep forensics.</li>
                  <li>Rotate credentials for identities observed in the attack path.</li>
                </ul>
              </div>
              <button onClick={() => onSelectCase(active)} className={btn}>
                Open Full Case File
              </button>
            </div>
          ) : (
            <p className="font-mono text-[10px] text-purple-300/50">No reports available.</p>
          )}
        </Panel>
      </div>
    </PageShell>
  );
};

export const TimelinePage: React.FC<{
  activities: ActivityItem[];
  streamEvents: StreamEvent[];
}> = ({ activities, streamEvents }) => {
  const entries = useMemo(
    () => [
      ...activities.map((a) => ({
        id: a.id,
        time: a.timestamp,
        source: a.agentName || a.agent || "AGENT",
        message: a.action,
        kind: a.type || "activity",
      })),
      ...streamEvents.map((s) => ({
        id: s.id,
        time: s.timestamp || s.time || "",
        source: s.source || "SYSTEM",
        message: s.message,
        kind: s.type || "event",
      })),
    ],
    [activities, streamEvents],
  );

  return (
    <PageShell
      title="OPERATION TIMELINE"
      subtitle="Chronological reconstruction of every orchestration decision, specialist action and system event."
      icon={<Clock className="h-4 w-4" />}
    >
      <Panel title={`TIMELINE (${entries.length} EVENTS)`}>
        <div className="relative space-y-3 pl-5">
          <span className="absolute left-1.5 top-1 h-[calc(100%-0.5rem)] w-px bg-gradient-to-b from-purple-500/60 to-transparent" />
          {entries.map((e) => (
            <div key={`${e.id}-${e.time}`} className="relative">
              <span className="absolute -left-[15px] top-1.5 h-2 w-2 rounded-full border border-purple-400/60 bg-purple-500/60" />
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[9px] text-purple-300/60">{e.time}</span>
                <Pill>{e.source}</Pill>
                <Pill tone={severityTone(String(e.kind))}>{String(e.kind)}</Pill>
              </div>
              <p className="mt-0.5 font-mono text-[11px] text-purple-100/85">{e.message}</p>
            </div>
          ))}
        </div>
      </Panel>
    </PageShell>
  );
};

const artifactTypeIcon: Record<string, string> = {
  file: "📄",
  image: "🖼️",
  link: "🔗",
  pcap: "📡",
  code: "💻",
  log: "🧾",
};

const verdictStyle: Record<string, { pill: string; label: string }> = {
  Malicious: { pill: "border-rose-500/50 text-rose-300 bg-rose-500/15", label: "🔴 MALICIOUS" },
  Suspicious: { pill: "border-amber-500/50 text-amber-300 bg-amber-500/15", label: "🟡 SUSPICIOUS" },
  Safe: { pill: "border-emerald-500/50 text-emerald-300 bg-emerald-500/15", label: "🟢 SAFE" },
  Unknown: { pill: "border-purple-500/40 text-purple-300 bg-purple-500/10", label: "⏳ ANALYZING…" },
};

const findingStatusIcon: Record<string, string> = {
  pending: "⏳",
  analyzing: "🔄",
  complete: "✅",
};

export const InvestigationPage: React.FC<{
  cases: CaseItem[];
  agents: SpecialistAgent[];
  artifacts: EvidenceArtifact[];
  streamEvents: StreamEvent[];
  onOpenEvidenceModal: (caseId?: string) => void;
  onSelectCase: (c: CaseItem) => void;
  onSelectAgent: (a: SpecialistAgent) => void;
  onNewCase: () => void;
  onDeleteArtifact?: (id: string) => void;
}> = ({
  cases,
  agents,
  artifacts,
  streamEvents,
  onOpenEvidenceModal,
  onSelectCase,
  onSelectAgent,
  onNewCase,
  onDeleteArtifact,
}) => {
  const activeCases = useMemo(
    () =>
      cases.filter(
        (c) => !["completed", "resolved", "closed"].includes((c.status || "").toLowerCase()),
      ),
    [cases],
  );

  const [selectedId, setSelectedId] = useState<string | undefined>(
    (activeCases[0] || cases[0])?.id,
  );
  const selected = useMemo(
    () => cases.find((c) => c.id === selectedId) || activeCases[0] || cases[0],
    [cases, selectedId, activeCases],
  );

  // Which evidence cards have their specialist pipeline breakdown expanded.
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const toggleExpanded = (id: string) =>
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  // Evidence artifacts attached to the case currently being investigated.
  const caseArtifacts = useMemo(
    () => (selected ? artifacts.filter((a) => a.caseId === selected.id) : []),
    [artifacts, selected],
  );

  // Every specialist agent actually touching this investigation: the case's
  // primary assignee, plus every specialist in each artifact's analysis
  // pipeline (pending, actively working, or already finished) so the full
  // roster that's working — or about to work — this file is visible, not
  // just whoever was originally assigned.
  const linkedAgents = useMemo(() => {
    if (!selected) return [];
    const ids = new Set<string>();
    const names = new Set<string>();
    if (selected.assignedAgent) names.add(selected.assignedAgent.toLowerCase());
    caseArtifacts.forEach((a) => {
      if (a.assignedAgent) names.add(a.assignedAgent.toLowerCase());
      (a.agentFindings || []).forEach((f) => ids.add(f.agentId));
    });
    return agents.filter((a) => ids.has(a.id) || names.has(a.name.toLowerCase()));
  }, [agents, selected, caseArtifacts]);

  const workingAgents = useMemo(
    () => linkedAgents.filter((a) => a.status === "ANALYZING" || a.status === "BUSY"),
    [linkedAgents],
  );

  // Live "what is happening" feed, scoped to this investigation: anything
  // mentioning the case number or one of the linked specialists, falling
  // back to the most recent global events for a brand-new investigation
  // that hasn't generated its own activity yet.
  const liveFeed = useMemo(() => {
    if (!selected) return streamEvents.slice(0, 10);
    const agentTokens = linkedAgents.map((a) => a.name.toUpperCase());
    const scoped = streamEvents.filter(
      (e) =>
        e.message.includes(selected.caseNumber) ||
        agentTokens.some((t) => (e.source || "").toUpperCase().includes(t)),
    );
    return (scoped.length > 0 ? scoped : streamEvents).slice(0, 12);
  }, [streamEvents, selected, linkedAgents]);

  const extractedIOCs = caseArtifacts.reduce((sum, a) => sum + (a.extractedIOCsCount || 0), 0);

  const threatLevel = useMemo(() => {
    if (caseArtifacts.some((a) => a.verdict === "Malicious")) return "Malicious";
    if (caseArtifacts.some((a) => a.verdict === "Suspicious")) return "Suspicious";
    if (caseArtifacts.length > 0 && caseArtifacts.every((a) => a.verdict === "Safe")) return "Safe";
    if (caseArtifacts.some((a) => a.verdict === "Unknown" || !a.verdict)) return "Analyzing…";
    return "—";
  }, [caseArtifacts]);

  const threatLevelTone =
    threatLevel === "Malicious"
      ? "text-rose-300"
      : threatLevel === "Suspicious"
        ? "text-amber-300"
        : threatLevel === "Safe"
          ? "text-emerald-300"
          : "text-purple-300";

  return (
    <PageShell
      title="LIVE INVESTIGATION"
      subtitle="Upload evidence into an active case and watch the specialist fleet work it in real time — who's on it, and exactly what they're doing right now."
      icon={<Radar className="h-4 w-4" />}
      actions={
        <>
          <button onClick={onNewCase} className={btn}>
            <Plus className="h-3 w-3" /> New Investigation
          </button>
          <button
            onClick={() => onOpenEvidenceModal(selected?.id)}
            className="flex items-center gap-1.5 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-emerald-200 transition-colors hover:bg-emerald-500/20"
          >
            <UploadCloud className="h-3 w-3" /> Upload Evidence
          </button>
        </>
      }
    >
      {cases.length === 0 ? (
        <Panel title="NO INVESTIGATIONS YET">
          <div className="flex flex-col items-center gap-3 py-10 text-center">
            <Radar className="h-8 w-8 text-purple-400/50" />
            <p className="max-w-sm font-mono text-[11px] text-purple-200/60">
              No active investigations on file. Upload a piece of evidence or open a new case to
              start one — the assigned specialist and live progress will appear here.
            </p>
            <button onClick={() => onOpenEvidenceModal()} className={btn}>
              <UploadCloud className="h-3 w-3" /> Upload Evidence to Start
            </button>
          </div>
        </Panel>
      ) : (
        <>
          {/* Investigation picker */}
          <Panel title={`INVESTIGATIONS (${cases.length})`}>
            <div className="flex gap-2 overflow-x-auto pb-1">
              {cases.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setSelectedId(c.id)}
                  className={`shrink-0 rounded-lg border px-3 py-2 text-left transition-colors ${
                    selected?.id === c.id
                      ? "border-purple-400/60 bg-purple-500/15"
                      : "border-purple-500/20 hover:bg-purple-500/10"
                  }`}
                >
                  <p className="font-mono text-[9px] text-purple-300/70">{c.caseNumber}</p>
                  <p className="max-w-[180px] truncate font-mono text-[11px] text-white">
                    {c.title}
                  </p>
                  <div className="mt-1 flex items-center gap-1.5">
                    <Pill tone={severityTone(c.severity)}>{c.severity}</Pill>
                    <Pill>{c.status}</Pill>
                  </div>
                </button>
              ))}
            </div>
          </Panel>

          {selected && (
            <>
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
                <StatTile label="Case Status" value={selected.status} />
                <StatTile label="Threat Level" value={threatLevel} tone={threatLevelTone} />
                <StatTile
                  label="Agents Working"
                  value={workingAgents.length}
                  tone={workingAgents.length > 0 ? "text-emerald-300" : "text-purple-300"}
                />
                <StatTile label="Evidence Uploaded" value={caseArtifacts.length} tone="text-amber-300" />
                <StatTile label="IOCs Extracted" value={extractedIOCs} tone="text-rose-300" />
              </div>

              <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
                {/* Which agent is working, and on what */}
                <Panel
                  title={`SPECIALISTS ON ${selected.caseNumber}`}
                  right={<Bot className="h-3.5 w-3.5 text-purple-400" />}
                  className="xl:col-span-8"
                >
                  {linkedAgents.length > 0 ? (
                    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-4">
                      {linkedAgents.map((a) => (
                        <AgentCard key={a.id} agent={a} onSelect={onSelectAgent} />
                      ))}
                    </div>
                  ) : (
                    <p className="py-8 text-center font-mono text-[10px] text-purple-300/50">
                      No specialist has picked up this investigation yet. Upload evidence to
                      dispatch one automatically.
                    </p>
                  )}
                </Panel>

                {/* What is happening, live */}
                <Panel
                  title="LIVE ACTIVITY"
                  right={
                    <span className="flex items-center gap-1 font-mono text-[9px] text-emerald-300">
                      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                      LIVE
                    </span>
                  }
                  className="xl:col-span-4"
                >
                  <div className="max-h-[360px] space-y-2 overflow-y-auto pr-1">
                    {liveFeed.length > 0 ? (
                      liveFeed.map((e) => (
                        <div
                          key={e.id}
                          className="rounded-lg border border-purple-500/15 bg-purple-950/10 p-2"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-[8.5px] uppercase tracking-wider text-purple-300/60">
                              {e.source || "SYSTEM"}
                            </span>
                            <span className="font-mono text-[8.5px] text-purple-300/50">
                              {e.timestamp || e.time}
                            </span>
                          </div>
                          <p className="mt-0.5 font-mono text-[10.5px] leading-snug text-purple-100/85">
                            {e.message}
                          </p>
                        </div>
                      ))
                    ) : (
                      <p className="py-6 text-center font-mono text-[10px] text-purple-300/50">
                        No activity recorded yet.
                      </p>
                    )}
                  </div>
                </Panel>
              </div>

              {/* Evidence attached to this investigation */}
              <Panel
                title={`EVIDENCE (${caseArtifacts.length})`}
                right={
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onOpenEvidenceModal(selected.id)}
                      className="flex items-center gap-1 font-mono text-[9.5px] uppercase tracking-wider text-purple-300 hover:text-white"
                    >
                      <Paperclip className="h-3 w-3" /> Add More
                    </button>
                    <button
                      onClick={() => onSelectCase(selected)}
                      className="flex items-center gap-1 font-mono text-[9.5px] uppercase tracking-wider text-purple-300 hover:text-white"
                    >
                      <FolderOpen className="h-3 w-3" /> Open Full Case File
                    </button>
                  </div>
                }
              >
                {caseArtifacts.length > 0 ? (
                  <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                    {caseArtifacts.map((art) => {
                      const vs = verdictStyle[art.verdict || "Unknown"] || verdictStyle.Unknown;
                      const isExpanded = expandedIds.has(art.id);
                      const findings = art.agentFindings || [];
                      const completedCount = findings.filter((f) => f.status === "complete").length;

                      return (
                        <div
                          key={art.id}
                          className="rounded-lg border border-purple-500/20 bg-black/20 p-2.5"
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="min-w-0">
                              <p className="truncate font-mono text-[11px] text-white" title={art.name}>
                                {artifactTypeIcon[art.type] || "📄"} {art.name}
                              </p>
                              <p className="mt-0.5 font-mono text-[9px] text-purple-300/60">
                                {art.uploadedAt} · {art.size || "—"}
                              </p>
                            </div>
                            {onDeleteArtifact && (
                              <button
                                onClick={() => onDeleteArtifact(art.id)}
                                className="shrink-0 rounded p-1 text-rose-400/70 transition-colors hover:bg-rose-950/40 hover:text-rose-300"
                                title="Delete artifact"
                              >
                                <Trash2 className="h-3 w-3" />
                              </button>
                            )}
                          </div>

                          {/* Threat verdict — the "is this safe or malicious" answer */}
                          <div className="mt-2 flex items-center justify-between gap-2 rounded-md border border-purple-500/15 bg-purple-950/10 px-2 py-1.5">
                            <span className={`rounded px-1.5 py-0.5 font-mono text-[9.5px] font-bold border ${vs.pill}`}>
                              {vs.label}
                            </span>
                            {typeof art.maliciousScore === "number" && art.verdict !== "Unknown" ? (
                              <span className="font-mono text-[11px] font-bold text-white">
                                {art.maliciousScore}% malicious
                              </span>
                            ) : (
                              <span className="font-mono text-[9.5px] text-purple-300/60">
                                {completedCount}/{findings.length || 8} specialists done
                              </span>
                            )}
                          </div>

                          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                            <Pill>{art.status}</Pill>
                            <Pill tone="border-emerald-500/40 text-emerald-300 bg-emerald-500/10">
                              {art.assignedAgent || "Unassigned"}
                            </Pill>
                            {typeof art.extractedIOCsCount === "number" && (
                              <Pill tone="border-rose-500/40 text-rose-300 bg-rose-500/10">
                                {art.extractedIOCsCount} IOCs
                              </Pill>
                            )}
                          </div>
                          {(typeof art.evidenceCoverage === "number" || art.evidenceQuality || typeof art.investigationConfidence === "number") && (
                            <div className="mt-1.5 flex flex-wrap gap-1 font-mono text-[8px] uppercase tracking-wider">
                              {typeof art.investigationConfidence === "number" && (
                                <Pill tone="border-cyan-500/30 text-cyan-300 bg-cyan-500/10">
                                  Investigation confidence {art.investigationConfidence}%
                                </Pill>
                              )}
                              {typeof art.evidenceCoverage === "number" && (
                                <Pill tone="border-cyan-500/30 text-cyan-300 bg-cyan-500/10">
                                  Evidence coverage {art.evidenceCoverage}%
                                </Pill>
                              )}
                              {art.evidenceQuality && (
                                <Pill tone="border-amber-500/30 text-amber-200 bg-amber-500/10">
                                  Evidence quality {art.evidenceQuality}
                                </Pill>
                              )}
                            </div>
                          )}

                          {art.url && (
                            <a
                              href={art.url}
                              target="_blank"
                              rel="noreferrer"
                              className="mt-1.5 flex items-center gap-1 font-mono text-[9.5px] text-purple-300 hover:text-white"
                            >
                              <ExternalLink className="h-3 w-3" /> Open source
                            </a>
                          )}

                          {/* Per-specialist outcome — "give me the outcome so I know everything" */}
                          {findings.length > 0 && (
                            <div className="mt-2 border-t border-purple-500/15 pt-1.5">
                              <button
                                onClick={() => toggleExpanded(art.id)}
                                className="flex w-full items-center justify-between font-mono text-[9.5px] uppercase tracking-wider text-purple-300 hover:text-white"
                              >
                                <span>Specialist Pipeline ({completedCount}/{findings.length})</span>
                                <span>{isExpanded ? "▲ Hide" : "▼ Show"}</span>
                              </button>
                              {isExpanded && (
                                <div className="mt-1.5 space-y-1">
                                  {findings.map((f) => (
                                    <div
                                      key={f.agentId}
                                      className={`rounded border px-1.5 py-1 ${
                                        f.status === "analyzing"
                                          ? "border-purple-400/40 bg-purple-500/10"
                                          : "border-purple-500/10 bg-black/10"
                                      }`}
                                    >
                                      <div className="flex items-center justify-between gap-1.5">
                                        <span className="flex items-center gap-1 font-mono text-[9.5px] text-white">
                                          <span className={f.status === "analyzing" ? "animate-spin" : ""}>
                                            {findingStatusIcon[f.status]}
                                          </span>
                                          {f.agentName}
                                        </span>
                                        {f.status === "complete" && f.verdict && f.verdict !== "Informational" && (
                                          <span
                                            className={`rounded px-1 py-0.5 text-[8.5px] font-bold ${
                                              f.verdict === "Malicious"
                                                ? "text-rose-300"
                                                : f.verdict === "Suspicious"
                                                  ? "text-amber-300"
                                                  : f.verdict === "Insufficient Evidence" || f.verdict === "Not Applicable"
                                                    ? "text-purple-300/70"
                                                    : "text-emerald-300"
                                            }`}
                                          >
                                            {f.verdict}
                                            {typeof f.maliciousScore === "number" ? ` ${f.maliciousScore}%` : ""}
                                          </span>
                                        )}
                                      </div>
                                      {f.status === "complete" && f.summary && (
                                        <p className="mt-0.5 font-mono text-[9px] leading-snug text-purple-200/70">
                                          {f.summary}
                                        </p>
                                      )}
                                      {f.status === "complete" && (typeof f.evidenceCoverage === "number" || f.evidenceQuality) && (
                                        <div className="mt-1 flex flex-wrap gap-1 font-mono text-[8px] uppercase tracking-wider">
                                          {typeof f.evidenceCoverage === "number" && (
                                            <span className="rounded border border-cyan-500/25 px-1 py-0.5 text-cyan-300/75">
                                              Evidence coverage {f.evidenceCoverage}%
                                            </span>
                                          )}
                                          {f.evidenceQuality && (
                                            <span className="rounded border border-amber-500/25 px-1 py-0.5 text-amber-200/75">
                                              Quality {f.evidenceQuality}
                                            </span>
                                          )}
                                        </div>
                                      )}
                                      {f.status === "complete" && f.findings && f.findings.length > 0 && (
                                        <ul className="mt-1 space-y-1 border-l border-purple-500/20 pl-1.5">
                                          {f.findings.slice(0, 8).map((ev, i) => (
                                            <li key={i} className="font-mono text-[8.5px] leading-snug text-purple-200/60">
                                              <details className="group cursor-pointer">
                                                <summary className="list-none">
                                                  <span className="text-purple-300/80 font-semibold">{ev.claim}:</span>{" "}
                                                  {ev.evidence}
                                                  <span className="text-purple-400/50">
                                                    {" "}— {ev.source} ({Math.round(ev.confidence * 100)}%)
                                                  </span>
                                                  {ev.evidenceType && (
                                                    <span className="ml-1 text-cyan-300/70">[{ev.evidenceType}]</span>
                                                  )}
                                                  <span className="ml-1.5 text-[7.5px] text-purple-400/70 underline group-open:text-cyan-300">
                                                    Why detected?
                                                  </span>
                                                </summary>
                                                <div className="mt-1 rounded border border-purple-500/20 bg-black/50 p-1.5 text-[8px] text-purple-200/80 space-y-0.5">
                                                  <p className="text-cyan-300 font-semibold">Why was this detected?</p>
                                                  <p><span className="text-purple-400">Evidence:</span> {ev.whyDetected?.evidence || ev.evidence}</p>
                                                  <p><span className="text-purple-400">↓ Extraction method:</span> {ev.whyDetected?.extractionMethod || ev.analysis_method || ev.source} ({ev.location || "0x0000"})</p>
                                                  <p><span className="text-purple-400">↓ Agent reasoning:</span> {ev.whyDetected?.agentReasoning || ev.reason || ev.claim}</p>
                                                  <p><span className="text-purple-400">↓ External confirmation:</span> {ev.whyDetected?.externalConfirmation || "Pending external threat-intel confirmation"}</p>
                                                  {ev.limitation && (
                                                    <p className="text-amber-200/70">Limitation: {ev.limitation}</p>
                                                  )}
                                                </div>
                                              </details>
                                            </li>
                                          ))}
                                        </ul>
                                      )}
                                      {f.status === "complete" && f.evidenceGaps && f.evidenceGaps.length > 0 && (
                                        <ul className="mt-1 space-y-0.5">
                                          {f.evidenceGaps.map((gap, i) => (
                                            <li key={i} className="font-mono text-[8.5px] leading-snug text-amber-200/60">
                                              ⚠ {gap}
                                            </li>
                                          ))}
                                        </ul>
                                      )}
                                      {f.status === "analyzing" && (
                                        <p className="mt-0.5 font-mono text-[9px] text-purple-300/60">
                                          Working now...
                                        </p>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              )}

                              {/* Phase 2 Step 5, Phase 7, Phase 8, Phase 9: Discovered IOCs, Agent Consensus, Final Verdict, Correlation & Verification */}
                              {isExpanded && art.agentFindings && art.agentFindings.some((f) => f.status === "complete") && (() => {
                                const correlations = correlateFindingsAcrossAgents(art, art.agentFindings || []);
                                const verifications = buildVerificationMatrix(art, art.agentFindings || [], correlations);
                                const consensus = buildAgentConsensus(art.agentFindings || []);
                                const finalVerdict = buildFinalVerdictDetail(art, art.agentFindings || []);
                                const allArtifactIOCs = extractIOCs({
                                  fileName: art.name,
                                  previewContent: art.analysisContent || art.previewContent,
                                  staticStrings: art.malwareIntelSample?.features
                                    ? {
                                        suspicious: art.malwareIntelSample.features.suspiciousStrings,
                                        network: art.malwareIntelSample.features.networkIndicatorStrings,
                                        persistence: art.malwareIntelSample.features.persistenceIndicatorStrings,
                                      }
                                    : undefined,
                                });
                                const numberedIOCLines = formatNumberedIOCList(allArtifactIOCs);

                                return (
                                  <div className="mt-2.5 space-y-2 border-t border-purple-500/15 pt-2">
                                    {/* Phase 2 Step 5: Show ALL discovered IOCs in the UI */}
                                    <div className="rounded border border-rose-500/20 bg-rose-950/15 p-2">
                                      <div className="flex items-center justify-between">
                                        <span className="font-mono text-[9px] uppercase tracking-wider text-rose-300 font-semibold">
                                          {allArtifactIOCs.length} IOCs detected
                                        </span>
                                      </div>
                                      {numberedIOCLines.length > 0 ? (
                                        <div className="mt-1.5 max-h-36 overflow-y-auto space-y-0.5 rounded bg-black/40 p-1.5 font-mono text-[8.5px] text-purple-100">
                                          {allArtifactIOCs.map((ioc, idx) => (
                                            <div key={`${ioc.type}-${ioc.value}-${idx}`} className="flex items-center justify-between gap-2 border-b border-purple-500/10 py-0.5 last:border-0">
                                              <span className="truncate">
                                                <span className="text-purple-400 mr-1.5">{String(idx + 1).padStart(2, "0")}</span>
                                                <span className="text-cyan-300 mr-1.5 font-bold">{ioc.type.toUpperCase()}</span>
                                                <span className="text-white">{ioc.normalizedValue || ioc.value}</span>
                                              </span>
                                              <span className="shrink-0 text-[7.5px] text-purple-300/60">
                                                Src: {ioc.source} · Occ: {ioc.occurrences || 1} · {Math.round(ioc.confidence * 100)}%
                                              </span>
                                            </div>
                                          ))}
                                        </div>
                                      ) : (
                                        <p className="mt-1 font-mono text-[8.5px] text-purple-300/50">0 IOCs discovered in static content.</p>
                                      )}
                                    </div>

                                    {/* Phase 7 & Phase 9: Agent Consensus & Final Verdict Breakdown */}
                                    <div className="rounded border border-emerald-500/20 bg-emerald-950/10 p-2 font-mono text-[8.5px]">
                                      <div className="flex items-center justify-between border-b border-emerald-500/15 pb-1">
                                        <span className="text-[9px] uppercase tracking-wider text-emerald-300 font-semibold">
                                          AGENT CONSENSUS & FINAL VERDICT
                                        </span>
                                        <span className="rounded bg-purple-500/20 px-1.5 py-0.5 font-bold text-white">
                                          {finalVerdict.verdict} ({finalVerdict.confidence}%)
                                        </span>
                                      </div>
                                      <div className="mt-1.5 grid grid-cols-2 gap-1 text-[8px]">
                                        <div><span className="text-purple-300/70">Malware Analysis:</span> <span className="text-white font-bold">{consensus.malwareAnalysis}</span></div>
                                        <div><span className="text-purple-300/70">IOC Extraction:</span> <span className="text-white font-bold">{consensus.iocExtraction}</span></div>
                                        <div><span className="text-purple-300/70">Threat Intelligence:</span> <span className="text-white font-bold">{consensus.threatIntelligence}</span></div>
                                        <div><span className="text-purple-300/70">Verification:</span> <span className="text-amber-300 font-bold">{consensus.verification}</span></div>
                                      </div>
                                      <div className="mt-1.5 space-y-0.5 border-t border-purple-500/10 pt-1 text-[8px] text-purple-200/80">
                                        <p><span className="text-purple-400">Primary evidence:</span> {finalVerdict.primaryEvidence.slice(0, 2).join(" • ")}</p>
                                        <p><span className="text-purple-400">Supporting agents:</span> {finalVerdict.supportingAgents.join(", ") || "None"}</p>
                                        <p><span className="text-purple-400">Contradictions:</span> {finalVerdict.contradictions.join(" ")}</p>
                                        <p><span className="text-purple-400">Limitations:</span> {finalVerdict.limitations.slice(0, 2).join(" ")}</p>
                                      </div>
                                    </div>
                                    {correlations.length > 0 && (
                                      <div className="rounded border border-cyan-500/20 bg-cyan-950/20 p-2">
                                        <div className="flex items-center justify-between">
                                          <span className="font-mono text-[9px] uppercase tracking-wider text-cyan-300 font-semibold flex items-center gap-1">
                                            <GitCommit className="h-3 w-3" /> Cross-Agent Correlation ({correlations.length})
                                          </span>
                                        </div>
                                        <div className="mt-1.5 space-y-1.5">
                                          {correlations.slice(0, 3).map((c) => (
                                            <div key={c.id} className="rounded bg-black/40 p-1.5 border border-cyan-500/10">
                                              <div className="flex items-center justify-between">
                                                <span className="font-mono text-[9.5px] text-white font-medium truncate max-w-[200px]" title={c.indicatorOrClaim}>
                                                  {c.indicatorOrClaim}
                                                </span>
                                                <span className={`text-[8px] font-mono px-1 py-0.5 rounded font-bold ${
                                                  c.status === 'HIGH' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                                                  c.status === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                                                  'bg-slate-500/20 text-slate-300 border border-slate-500/30'
                                                }`}>
                                                  {c.status} CONFIDENCE
                                                </span>
                                              </div>
                                              <div className="mt-1 grid grid-cols-2 gap-1 text-[8px] font-mono">
                                                {c.evidenceChecklist.map((chk, i) => (
                                                  <div key={i} className={`flex items-center gap-1 ${chk.checked ? 'text-emerald-300' : 'text-slate-500'}`}>
                                                    {chk.checked ? <CheckCircle2 className="h-2.5 w-2.5 shrink-0" /> : <XCircle className="h-2.5 w-2.5 shrink-0" />} {chk.label}
                                                  </div>
                                                ))}
                                              </div>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {verifications.length > 0 && (
                                      <div className="rounded border border-purple-500/20 bg-purple-950/20 p-2">
                                        <span className="font-mono text-[9px] uppercase tracking-wider text-purple-300 font-semibold flex items-center gap-1">
                                          <ShieldAlert className="h-3 w-3 text-purple-400" /> Verification Matrix ({verifications.length})
                                        </span>
                                        <div className="mt-1.5 space-y-1">
                                          {verifications.slice(0, 3).map((v, i) => (
                                            <div key={i} className="flex items-start justify-between gap-2 rounded bg-black/40 p-1.5 border border-purple-500/10 text-[8.5px] font-mono">
                                              <div className="min-w-0">
                                                <p className="text-purple-200 truncate">{v.claim}</p>
                                                <p className="text-purple-300/60 truncate">{v.sourceCheck} · {v.agentAgreement}</p>
                                              </div>
                                              <span className={`shrink-0 font-bold px-1 py-0.5 rounded text-[8px] ${
                                                v.status === 'VERIFIED' ? 'text-emerald-300 bg-emerald-500/10 border border-emerald-500/30' :
                                                v.status === 'CONTRADICTED' ? 'text-rose-300 bg-rose-500/10 border border-rose-500/30' :
                                                'text-amber-300 bg-amber-500/10 border border-amber-500/30'
                                              }`}>
                                                {v.status}
                                              </span>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                );
                              })()}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="flex flex-col items-center gap-2 py-8 text-center">
                    <UploadCloud className="h-6 w-6 text-purple-400/40" />
                    <p className="font-mono text-[10px] text-purple-300/50">
                      No evidence uploaded to this investigation yet.
                    </p>
                    <button onClick={() => onOpenEvidenceModal(selected.id)} className={btn}>
                      <UploadCloud className="h-3 w-3" /> Upload Evidence
                    </button>
                  </div>
                )}
              </Panel>
            </>
          )}
        </>
      )}
    </PageShell>
  );
};
