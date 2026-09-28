import React, { useState, useRef, useMemo } from 'react';
import { 
  Radio, 
  Terminal, 
  ChevronRight, 
  Eye, 
  Sparkles,
  LayoutGrid,
  Columns,
  Layers,
  Network
} from 'lucide-react';
import { SpecialistAgent } from '../../types';
import { CustomAgentIcon } from '../common/CustomAgentIcon';
import { AgentTelemetryModal } from '../modals/AgentTelemetryModal';
import { AgentSparkline } from './AgentSparkline';
import { 
  useAgentHierarchyConnections, 
  PipelineLinkDefinition,
  CardGeometry,
  SnapPoint 
} from '../../hooks/useAgentHierarchyConnections';

interface AgentHierarchyProps {
  agents: SpecialistAgent[];
  selectedAgent?: SpecialistAgent | null;
  onSelectAgent: (agent: SpecialistAgent) => void;
}

export type FlowMode = 'all' | 'command' | 'pipeline';
export type GridViewMode = 'panoramic' | 'matrix';

export interface CardAnchor {
  x: number;
  topY: number;
  bottomY: number;
  leftX: number;
  rightX: number;
  width: number;
  height: number;
  row: number;
}

export const AgentHierarchy: React.FC<AgentHierarchyProps> = ({
  agents,
  selectedAgent,
  onSelectAgent,
}) => {
  const [telemetryAgent, setTelemetryAgent] = useState<SpecialistAgent | null>(null);
  const flowMode: FlowMode = 'command';
  const gridViewMode: GridViewMode = 'panoramic';

  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const innerContainerRef = useRef<HTMLDivElement>(null);
  const cardRefs = useRef<(HTMLDivElement | null)[]>([]);

  // Inter-agent sequential pipeline links:
  // 0 (malware) -> 1 (ioc), 1 (ioc) -> 2 (net), 1 (ioc) -> 3 (threat),
  // 3 (threat) -> 4 (code), 4 (code) -> 5 (memory), 5 (memory) -> 6 (verify), 6 (verify) -> 7 (report)
  const pipelineLinks: PipelineLinkDefinition[] = useMemo(() => [
    { from: 0, to: 1, label: 'features' },
    { from: 1, to: 2, label: 'net-iocs' },
    { from: 1, to: 3, label: 'threat-feeds' },
    { from: 3, to: 4, label: 'payloads' },
    { from: 4, to: 5, label: 'artifacts' },
    { from: 5, to: 6, label: 'prior-incidents' },
    { from: 6, to: 7, label: 'verified-proof' },
  ], []);

  // Hook dynamically recalculating SVG path coordinates based on getBoundingClientRect and snapping to nearest edges
  const {
    containerDimensions,
    rowBuses,
    stemX,
    masterBusY,
    commandConnections,
    pipelineConnections,
  } = useAgentHierarchyConnections(
    innerContainerRef,
    cardRefs,
    agents,
    {
      gridViewMode,
      flowMode,
      selectedAgentId: selectedAgent?.id,
      pipelineLinks,
    }
  );

  return (
    <div id="agent-hierarchy-section" className="space-y-2.5 w-full">
      {/* Section Header with Tier Diagnostics & Command Bus Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-0.5">
        <div>
          <h3 className="text-xs sm:text-sm font-cyber font-bold uppercase tracking-widest text-white flex items-center gap-2">
            <span>AGENT ORCHESTRATION HIERARCHY</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-950/80 text-purple-300 border border-purple-500/40">
              8 SPECIALISTS
            </span>
          </h3>
          <p className="text-[10.5px] font-mono text-purple-300/80 mt-0.5">
            CEO ARCHON Master Orchestrator directing 3-tier multi-threaded operational pipelines
          </p>
        </div>

        {/* Controls: Command Bus Indicator & Live Patrol Status */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Command Bus Indicator */}
          <div className="flex items-center rounded-lg bg-[#0d051d] p-0.5 border border-purple-500/30 text-[10px] font-mono">
            <span
              className="px-2.5 py-0.5 rounded bg-purple-600 text-white font-bold shadow-[0_0_8px_rgba(168,85,247,0.5)]"
              title="Direct Archon CEO delegation bus lines to specialist pods"
            >
              Command Bus
            </span>
          </div>

          {/* Active Patrol Legend */}
          <div className="flex items-center gap-1.5 text-[10px] font-mono bg-[#0c051a] px-2.5 py-1 rounded-lg border border-purple-500/30 text-emerald-300 font-semibold shrink-0">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span>Active Patrol</span>
          </div>
        </div>
      </div>

      {/* Operational Hierarchy Tier Headers (Positioned cleanly above the SVG Bus Corridor) */}
      <div className="w-full grid grid-cols-1 lg:grid-cols-8 gap-1.5 text-[9px] font-mono select-none">
        {/* Tier 1: Intake & Triage */}
        <div className="lg:col-span-2 flex items-center justify-between gap-1 px-2.5 py-1 rounded-md bg-emerald-950/40 border border-emerald-500/30 text-emerald-300/90 min-w-0">
          <span className="font-bold tracking-wider truncate">TIER 1: INTAKE &amp; TRIAGE</span>
          <span className="text-[7.5px] text-emerald-400/75 uppercase shrink-0">Sensors &amp; Extraction</span>
        </div>
        {/* Tier 2: Correlation & Audit */}
        <div className="lg:col-span-3 flex items-center justify-between gap-1 px-2.5 py-1 rounded-md bg-sky-950/40 border border-sky-500/30 text-sky-300/90 min-w-0">
          <span className="font-bold tracking-wider truncate">TIER 2: CORRELATION &amp; AUDIT</span>
          <span className="text-[7.5px] text-sky-400/75 uppercase shrink-0">PCAP · Feeds · Code</span>
        </div>
        {/* Tier 3: Governance & Delivery */}
        <div className="lg:col-span-3 flex items-center justify-between gap-1 px-2.5 py-1 rounded-md bg-purple-950/40 border border-purple-500/30 text-purple-300/90 min-w-0">
          <span className="font-bold tracking-wider truncate">TIER 3: GOVERNANCE &amp; SYNTHESIS</span>
          <span className="text-[7.5px] text-purple-400/75 uppercase shrink-0">Vector · Audit · Brief</span>
        </div>
      </div>

      {/* Unified Synchronized Canvas Container for SVG Command Bus Overlay and Agent Card Nodes */}
      <div 
        ref={scrollContainerRef}
        className="w-full"
      >
        <div 
          ref={innerContainerRef} 
          className="w-full flex flex-col relative"
        >
          {/* Dynamic Absolute SVG Overlay covering the bus corridor and cards */}
          <svg 
            width={containerDimensions.width}
            height={containerDimensions.height}
            viewBox={`0 0 ${containerDimensions.width} ${containerDimensions.height}`}
            className="absolute inset-0 pointer-events-none select-none overflow-visible z-10"
            style={{ width: '100%', height: '100%' }}
          >
            <defs>
              <linearGradient id="activeBusGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#34d399" stopOpacity="0.8" />
                <stop offset="50%" stopColor="#38bdf8" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#c084fc" stopOpacity="0.8" />
              </linearGradient>

              <linearGradient id="selectedBeamGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#c084fc" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity="1" />
              </linearGradient>

              <filter id="glowGreen" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="2.5" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>

              <filter id="glowSelected" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="3.5" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* ARCHON Central Ingress Stem & Beacon Hub */}
            {(flowMode === 'all' || flowMode === 'command') && (
              <g id="archon-central-stem">
                {/* Central Vertical Stem inside the Bus Corridor */}
                <line 
                  x1={stemX} 
                  y1={0} 
                  x2={stemX} 
                  y2={masterBusY} 
                  stroke="#a855f7" 
                  strokeWidth="2" 
                  strokeOpacity="0.9"
                />
                {/* High-speed animated packet streaming down stem */}
                <line 
                  x1={stemX} 
                  y1={0} 
                  x2={stemX} 
                  y2={masterBusY} 
                  stroke="#38bdf8" 
                  strokeWidth="2" 
                  strokeDasharray="4 4"
                  className="animate-data-flow"
                />
                {/* Central Archon Hub Beacon */}
                <circle cx={stemX} cy={masterBusY} r="4.5" fill="#a855f7" className="animate-pulse" />
                <circle cx={stemX} cy={masterBusY} r="7.5" fill="none" stroke="#c084fc" strokeWidth="1" strokeOpacity="0.7" />
                <circle cx={stemX} cy={masterBusY} r="2" fill="#ffffff" />
                {/* Centered Archon Directive Port Label in corridor gap */}
                <rect
                  x={stemX - 42}
                  y={masterBusY + 6}
                  width={84}
                  height={11}
                  rx={3}
                  fill="#090316"
                  fillOpacity="0.9"
                  stroke="#a855f7"
                  strokeOpacity="0.35"
                  strokeWidth="0.75"
                />
                <text 
                  x={stemX} 
                  y={masterBusY + 14} 
                  textAnchor="middle"
                  fill="#d8b4fe" 
                  fontSize="6.8" 
                  fontFamily="monospace" 
                  fontWeight="bold" 
                  letterSpacing="0.04em"
                >
                  ARCHON MASTER BUS
                </text>
              </g>
            )}

            {/* Dynamic Multi-Row Bus Bars and Drop Lines */}
            {rowBuses.map((rowBus, rIdx) => {
              const connectionsInRow = commandConnections.filter((c) => c.row === rowBus.row);
              if (connectionsInRow.length === 0) return null;

              return (
                <g key={`row-bus-group-${rIdx}`} id={`bus-row-${rIdx}`}>
                  {/* If Row > 0: Vertical Trunk connecting primary bus to secondary row bus */}
                  {(flowMode === 'all' || flowMode === 'command') && rIdx > 0 && (
                    <g id={`bus-trunk-row-${rIdx}`}>
                      <line 
                        x1={stemX} 
                        y1={masterBusY} 
                        x2={stemX} 
                        y2={rowBus.busY} 
                        stroke="#7e22ce" 
                        strokeWidth="1.5" 
                        strokeOpacity="0.75"
                        strokeDasharray="4 4"
                        className="animate-data-flow"
                      />
                      <circle cx={stemX} cy={rowBus.busY} r="4" fill="#a855f7" />
                      <circle cx={stemX} cy={rowBus.busY} r="2" fill="#ffffff" />
                    </g>
                  )}

                  {/* Horizontal Distribution Bus Bar for this row */}
                  {(flowMode === 'all' || flowMode === 'command') && (
                    <line 
                      x1={rowBus.firstX} 
                      y1={rowBus.busY} 
                      x2={rowBus.lastX} 
                      y2={rowBus.busY} 
                      stroke="#4c1d95" 
                      strokeWidth="1.5" 
                      strokeOpacity="0.65"
                    />
                  )}

                  {/* Drop Lines to Each Card Node in this Row Snapping to Nearest Edge */}
                  {connectionsInRow.map((conn) => {
                    return (
                      <g key={`agent-connector-${conn.agentId}`}>
                        {/* Active Bus Segment from Central Stem/Trunk to Agent Card */}
                        {(flowMode === 'all' || flowMode === 'command') && conn.isActive && (
                          <line
                            x1={stemX}
                            y1={conn.busY}
                            x2={conn.busPoint.x}
                            y2={conn.busY}
                            stroke={conn.tierColor}
                            strokeWidth="2"
                            strokeOpacity="0.9"
                            strokeDasharray="5 5"
                            className="animate-data-flow"
                            filter="url(#glowGreen)"
                          />
                        )}

                        {/* Selected Agent Super-Beam Highlight along Bus Bar */}
                        {conn.isSelected && (
                          <line
                            x1={stemX}
                            y1={conn.busY}
                            x2={conn.busPoint.x}
                            y2={conn.busY}
                            stroke="#c084fc"
                            strokeWidth="2.5"
                            strokeOpacity="1"
                            filter="url(#glowSelected)"
                          />
                        )}

                        {/* Drop Line Down to Card Nearest Edge Point */}
                        <line
                          x1={conn.busPoint.x}
                          y1={conn.busPoint.y}
                          x2={conn.cardSnapPoint.x}
                          y2={conn.cardSnapPoint.y}
                          stroke={
                            conn.isSelected 
                              ? '#c084fc' 
                              : conn.isActive 
                                ? conn.tierColor 
                                : '#581c87'
                          }
                          strokeWidth={conn.isSelected ? '2.5' : conn.isActive ? '1.8' : '1'}
                          strokeOpacity={conn.isSelected ? 1 : conn.isActive ? 0.95 : 0.45}
                          strokeDasharray={conn.isSelected ? undefined : conn.isActive ? '4 4' : '2 2'}
                          className={conn.isActive && !conn.isSelected ? 'animate-data-flow' : undefined}
                          filter={conn.isSelected ? 'url(#glowSelected)' : conn.isActive ? 'url(#glowGreen)' : undefined}
                        />

                        {/* Joint Node on Bus Bar */}
                        {(flowMode === 'all' || flowMode === 'command') && (
                          <circle 
                            cx={conn.busPoint.x} 
                            cy={conn.busPoint.y} 
                            r={conn.isSelected ? 3.5 : conn.isActive ? 2.8 : 1.8} 
                            fill={conn.isSelected ? '#ffffff' : conn.isActive ? conn.tierColor : '#9333ea'} 
                            stroke={conn.isActive ? '#06020e' : 'none'}
                            strokeWidth="0.8"
                            opacity={conn.isActive || conn.isSelected ? 1 : 0.7}
                          />
                        )}

                        {/* Directional Downward Ingress Arrowhead pointing into snapped card edge */}
                        <polygon 
                          points={conn.arrowPoints} 
                          fill={conn.isSelected ? '#ffffff' : conn.isActive ? conn.tierColor : '#7e22ce'} 
                          opacity={conn.isActive || conn.isSelected ? 1 : 0.6}
                        />

                        {/* Terminal Socket Node at Snapped Edge of Agent Card */}
                        <circle 
                          cx={conn.cardSnapPoint.x} 
                          cy={conn.cardSnapPoint.y} 
                          r={conn.isSelected ? 4.5 : conn.isActive ? 3.5 : 2.2} 
                          fill={conn.isSelected ? '#ffffff' : conn.isActive ? conn.tierColor : '#6b21a8'} 
                          stroke={conn.isActive ? '#0a0418' : '#38126b'}
                          strokeWidth="1.2"
                        />

                        {/* Pulse Ring for Active / Selected Pod at Card Nearest Edge */}
                        {(conn.isActive || conn.isSelected) && (
                          <circle 
                            cx={conn.cardSnapPoint.x} 
                            cy={conn.cardSnapPoint.y} 
                            r={conn.isSelected ? 7 : 5.5} 
                            fill="none" 
                            stroke={conn.isSelected ? '#c084fc' : conn.tierColor} 
                            strokeWidth="1" 
                            strokeOpacity="0.75" 
                            strokeDasharray="2 2"
                            className="animate-spin"
                          />
                        )}
                      </g>
                    );
                  })}
                </g>
              );
            })}

            {/* Inter-Agent Pipeline Cascade Streams (Conduits between Stages Snapped to Nearest Edges) */}
            {(flowMode === 'all' || flowMode === 'pipeline') && (
              <g id="pipeline-cascade-conduits">
                {pipelineConnections.map((pipe) => {
                  return (
                    <g key={pipe.id}>
                      <path 
                        d={pipe.path} 
                        fill="none" 
                        stroke={pipe.isActive ? '#38bdf8' : '#581c87'} 
                        strokeWidth={pipe.isActive ? '1.5' : '1'} 
                        strokeOpacity={pipe.isActive ? 0.85 : 0.35} 
                        strokeDasharray={pipe.isActive ? '4 4' : '2 2'}
                        className={pipe.isActive ? 'animate-data-flow' : undefined}
                      />
                      {pipe.isActive && (
                        <>
                          <polygon 
                            points={pipe.arrowPoints} 
                            fill="#38bdf8" 
                            opacity="0.9"
                          />
                          <circle cx={pipe.midPoint.x} cy={pipe.midPoint.y} r="2.5" fill="#38bdf8" className="animate-pulse" />
                        </>
                      )}
                    </g>
                  );
                })}
              </g>
            )}
          </svg>

          {/* Bus Corridor Spacing Zone: Provides exact vertical clearance for Archon master bus & labels */}
          <div className="w-full h-9 pointer-events-none" aria-hidden="true" />

          {/* 8 Agent Cards in Full-Width Responsive 8-Column Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-1.5 w-full">
            {agents.map((agent, index) => {
              const isActive = agent.status === 'ACTIVE';
              const isSelected = selectedAgent?.id === agent.id;
              const tierBadge = index < 2 ? 'T1' : index < 5 ? 'T2' : 'T3';
              const tierColorClass = index < 2 
                ? 'text-emerald-400 border-emerald-500/40 bg-emerald-950/60' 
                : index < 5 
                  ? 'text-sky-400 border-sky-500/40 bg-sky-950/60' 
                  : 'text-purple-300 border-purple-500/40 bg-purple-950/60';

              return (
                <div
                  key={agent.id}
                  id={`agent-node-${agent.id}`}
                  ref={(el) => { cardRefs.current[index] = el; }}
                  onClick={() => onSelectAgent(agent)}
                  className={`group cursor-pointer rounded-xl bg-gradient-to-b from-[#140b2e] via-[#0e0622] to-[#090418] border ${
                    isSelected
                      ? 'border-purple-300 glow-purple-lg ring-1 ring-purple-400'
                      : isActive 
                        ? 'border-purple-500/50 glow-purple' 
                        : 'border-purple-500/25'
                  } hover:border-purple-300 hover:glow-purple-lg p-1.5 sm:p-2 flex flex-col justify-between transition-all duration-200 hover:-translate-y-1 min-w-0 relative overflow-hidden`}
                >
                  {/* Top Center Mechanical Socket Tab: Where connector lines terminate */}
                  <div className="absolute top-0 left-1/2 -translate-x-1/2 w-4 h-1 rounded-b bg-[#1e0d3d] border-b border-x border-purple-400/50 flex items-center justify-center z-20">
                    <span className={`w-1 h-1 rounded-full ${isActive ? 'bg-emerald-400 animate-ping' : 'bg-purple-500'}`} />
                  </div>

                  {/* Top Accent Gradient Bar */}
                  <div 
                    className={`absolute top-0 left-0 right-0 h-[2px] ${
                      isSelected
                        ? 'bg-gradient-to-r from-purple-400 via-sky-300 to-emerald-400'
                        : isActive 
                          ? 'bg-gradient-to-r from-emerald-400 via-cyan-400 to-purple-500' 
                          : 'bg-purple-500/30'
                    }`}
                  />

                  {/* Card Top: Name & Role/Category with Tier Pill */}
                  <div className="text-center pb-1 border-b border-purple-500/15 w-full pt-0.5">
                    <div className="flex items-center justify-center gap-1 mb-0.5">
                      <span className={`text-[7px] font-mono px-1 py-0.2 rounded border font-bold ${tierColorClass}`}>
                        {tierBadge}
                      </span>
                    </div>
                    <div 
                      className="w-full font-mono font-bold text-white tracking-tight leading-tight group-hover:text-purple-200 min-h-[2.4em] flex flex-wrap items-center justify-center text-center px-0.5 text-[9px] sm:text-[9.5px] xl:text-[10px]"
                      title={agent.name}
                    >
                      <span className="w-full break-words leading-tight">{agent.name.toUpperCase()}</span>
                    </div>
                    <div className="text-[8px] font-mono text-purple-300/80 truncate mt-0.5" title={agent.category}>
                      {agent.category}
                    </div>
                  </div>

                  {/* Card Center: Icon with Patrol-Path Scanning */}
                  <div className="py-1.5 flex flex-col items-center justify-center space-y-1">
                    <div className="relative flex items-center justify-center">
                      {/* Fading Ring Patrol Radar Animations */}
                      {isActive ? (
                        <>
                          <span 
                            className="absolute inset-0 rounded-xl border border-emerald-400/50 animate-patrol-ring-1 pointer-events-none" 
                            aria-hidden="true" 
                          />
                          <span 
                            className="absolute inset-0 rounded-xl border border-emerald-500/40 animate-patrol-ring-2 pointer-events-none" 
                            aria-hidden="true" 
                          />
                        </>
                      ) : (
                        <span 
                          className="absolute -inset-0.5 rounded-xl border border-cyan-500/30 animate-patrol-idle pointer-events-none" 
                          aria-hidden="true" 
                        />
                      )}

                      {/* Icon Box */}
                      <div className={`relative w-8 h-8 sm:w-9 sm:h-9 rounded-xl bg-[#1d0f3c] border ${
                        isActive 
                          ? 'border-emerald-400/70 shadow-[0_0_12px_rgba(16,185,129,0.3)]' 
                          : 'border-purple-500/40 glow-purple-sm'
                      } flex items-center justify-center shadow-inner group-hover:border-purple-300 group-hover:scale-105 transition-all shrink-0 z-10`}>
                        <CustomAgentIcon type={agent.id} className="w-4 h-4 sm:w-4.5 sm:h-4.5" glow={true} />
                        
                        {/* Corner Radar Signal Dot */}
                        <span 
                          className={`absolute -top-1 -right-1 w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full flex items-center justify-center border text-[7px] ${
                            isActive 
                              ? 'bg-emerald-950 border-emerald-400 text-emerald-300 shadow-[0_0_6px_#10b981]' 
                              : 'bg-[#150a2d] border-cyan-500/50 text-cyan-300/80'
                          }`}
                        >
                          {isActive ? (
                            <Radio className="w-1.5 h-1.5 sm:w-2 sm:h-2 text-emerald-300 animate-pulse" />
                          ) : (
                            <Eye className="w-1.5 h-1.5 text-cyan-400/70" />
                          )}
                        </span>
                      </div>
                    </div>

                    {/* Status Indicator Chip */}
                    <div className="flex items-center gap-1 pt-0.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${isActive ? 'bg-emerald-400 animate-ping' : 'bg-purple-400'}`} />
                      <span className={`text-[8px] sm:text-[8.5px] font-mono font-bold ${isActive ? 'text-emerald-300' : 'text-purple-300/80'}`}>
                        {isActive ? 'ACTIVE' : 'STANDBY'}
                      </span>
                    </div>
                  </div>

                  {/* Model & Task Info */}
                  <div className="py-1 px-1.5 rounded-lg bg-[#0b0417]/80 border border-purple-500/15 space-y-0.5 text-[7.5px] sm:text-[8px] font-mono min-w-0">
                    <div className="flex items-center justify-between text-purple-300/80 min-w-0">
                      <span className="text-purple-400 shrink-0">Model:</span>
                      <span className="text-white font-medium truncate ml-1">{agent.model.replace('gemini-', 'Gemini ').replace('gpt-', 'GPT-')}</span>
                    </div>
                    <div className="flex items-center justify-between text-purple-300/80 min-w-0">
                      <span className="text-purple-400 shrink-0">Task:</span>
                      <span className="text-slate-200 truncate ml-1" title={agent.currentTask}>{agent.currentTask}</span>
                    </div>
                  </div>

                  {/* Card Bottom: Progress Bar, Sparkline & Telemetry Trigger */}
                  <div className="space-y-1.5 pt-1.5 border-t border-purple-500/15">
                    <div className="flex items-center justify-between text-[8px] font-mono text-purple-300/80">
                      <span>Cycle</span>
                      <span className="font-bold text-white">{agent.progress}%</span>
                    </div>
                    
                    <div className="w-full h-1 rounded-full bg-[#1b0d38] border border-purple-500/30 overflow-hidden">
                      <div 
                        className={`h-full transition-all duration-500 ${
                          isActive 
                            ? 'bg-gradient-to-r from-emerald-400 to-teal-300 shadow-[0_0_6px_#34d399]' 
                            : 'bg-gradient-to-r from-purple-500 to-indigo-400'
                        }`}
                        style={{ width: `${agent.progress}%` }}
                      />
                    </div>

                    {/* Mini Real-Time Sparkline (unclipped full height) */}
                    <div className="w-full">
                      <AgentSparkline agentId={agent.id} isActive={isActive} type="cpu" />
                    </div>

                    {/* On-Demand Telemetry Popover Button */}
                    <button
                      type="button"
                      id={`view-logs-btn-${agent.id}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        setTelemetryAgent(agent);
                      }}
                      className="w-full py-0.5 px-1 rounded-lg bg-[#180c33] hover:bg-purple-900/50 border border-purple-500/30 hover:border-purple-400/60 text-[8px] font-mono text-purple-200 hover:text-white flex items-center justify-center gap-1 transition-all group/btn cursor-pointer"
                      title="View live terminal logs and system diagnostics"
                    >
                      <Terminal className="w-2.5 h-2.5 text-purple-400 group-hover/btn:text-cyan-300 shrink-0" />
                      <span className="truncate">Logs</span>
                      <ChevronRight className="w-2 h-2 text-purple-400 group-hover/btn:translate-x-0.5 transition-transform shrink-0" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Telemetry Logs Modal */}
      {telemetryAgent && (
        <AgentTelemetryModal
          agent={telemetryAgent}
          isOpen={!!telemetryAgent}
          onClose={() => setTelemetryAgent(null)}
        />
      )}
    </div>
  );
};
