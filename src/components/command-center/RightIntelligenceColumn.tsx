import React, { useState } from 'react';
import { ActivityItem, IOCItem } from '../../types';
import { 
  ShieldAlert, 
  Cpu, 
  Database, 
  HardDrive, 
  Users, 
  ArrowUpRight, 
  Copy, 
  Check, 
  Filter, 
  Radio, 
  Sparkles,
  Zap
} from 'lucide-react';
import { CustomAgentIcon } from '../common/CustomAgentIcon';

interface RightIntelligenceColumnProps {
  threatScore?: number;
  threatLevel?: string;
  activities?: ActivityItem[];
  iocs?: IOCItem[];
  cpu?: number;
  memoryUsed?: number;
  memoryTotal?: number;
  disk?: number;
  activeAgents?: number;
  totalAgents?: number;
  onSelectIOC: (ioc: IOCItem) => void;
  onOpenCase: () => void;
  onOpenCEOChat: () => void;
}

export const RightIntelligenceColumn: React.FC<RightIntelligenceColumnProps> = ({
  threatScore = 7.8,
  threatLevel = 'HIGH',
  activities = [],
  iocs = [],
  cpu = 23,
  memoryUsed = 7.3,
  memoryTotal = 16,
  disk = 62,
  activeAgents = 7,
  totalAgents = 8,
  onSelectIOC,
  onOpenCase,
  onOpenCEOChat
}) => {
  // Feed Tab Switcher: 'feed' | 'iocs'
  const [activeTab, setActiveTab] = useState<'feed' | 'iocs'>('feed');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (e: React.MouseEvent, text: string, id: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div id="right-intelligence-column" className="space-y-3.5">
      
      {/* 1. UNIFIED DEFENSE & SYSTEM TELEMETRY CARD */}
      <div 
        id="defcon-telemetry-module"
        className="rounded-2xl bg-gradient-to-b from-[#12082b] to-[#0c051a] border border-purple-500/30 p-3.5 shadow-lg space-y-3"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-purple-500/20 pb-2">
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-cyber font-bold text-white tracking-wider">
              DEFCON TELEMETRY
            </span>
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
          </div>
          <button
            onClick={onOpenCase}
            className="text-[10px] font-mono text-purple-400 hover:text-purple-300 flex items-center gap-0.5"
          >
            <span>Overview</span>
            <ArrowUpRight className="w-3 h-3" />
          </button>
        </div>

        {/* Defense Gauge + Metrics Split */}
        <div className="grid grid-cols-12 gap-3 items-center">
          
          {/* Gauge Center */}
          <div className="col-span-5 flex flex-col items-center justify-center p-2 rounded-xl bg-[#190d38]/80 border border-purple-500/25">
            <div className="relative w-16 h-16 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full bg-rose-600/20 blur-md animate-pulse" />
              <div className="absolute inset-0 rounded-full border border-rose-500/40" />
              <div className="absolute inset-1 rounded-full border border-dashed border-rose-500/60 animate-spin [animation-duration:20s]" />
              <div className="relative flex flex-col items-center">
                <span className="text-xs font-cyber font-extrabold text-rose-400">
                  {threatLevel}
                </span>
                <span className="text-[9.5px] font-mono font-bold text-slate-200">
                  {threatScore}/10
                </span>
              </div>
            </div>
            <span className="text-[9px] font-mono text-rose-300 font-semibold mt-1">Elevated Risk</span>
          </div>

          {/* Compact Telemetry Chips */}
          <div className="col-span-7 space-y-1.5 font-mono text-xs">
            {/* CPU */}
            <div className="flex items-center justify-between p-1.5 rounded-lg bg-[#150a30] border border-purple-500/15">
              <div className="flex items-center gap-1.5 text-slate-400 text-[10px]">
                <Cpu className="w-3 h-3 text-purple-400" />
                <span>CPU Usage</span>
              </div>
              <span className="text-purple-200 font-bold text-[11px]">{cpu}%</span>
            </div>

            {/* RAM */}
            <div className="flex items-center justify-between p-1.5 rounded-lg bg-[#150a30] border border-purple-500/15">
              <div className="flex items-center gap-1.5 text-slate-400 text-[10px]">
                <Database className="w-3 h-3 text-cyan-400" />
                <span>RAM</span>
              </div>
              <span className="text-cyan-200 font-bold text-[11px]">{memoryUsed} / {memoryTotal} GB</span>
            </div>

            {/* Active Agents */}
            <div className="flex items-center justify-between p-1.5 rounded-lg bg-[#150a30] border border-purple-500/15">
              <div className="flex items-center gap-1.5 text-slate-400 text-[10px]">
                <Users className="w-3 h-3 text-emerald-400" />
                <span>Swarm</span>
              </div>
              <span className="text-emerald-300 font-bold text-[11px]">{activeAgents}/{totalAgents} Online</span>
            </div>
          </div>
        </div>
      </div>

      {/* 2. REAL-TIME INTELLIGENCE & INDICATORS HUB */}
      <div 
        id="real-time-intel-hub"
        className="rounded-2xl bg-gradient-to-b from-[#12082b] to-[#0c051a] border border-purple-500/30 p-3.5 shadow-lg space-y-3"
      >
        {/* Tab Header: Live Feed vs Top IOCs */}
        <div className="flex items-center justify-between border-b border-purple-500/20 pb-2">
          <div className="flex items-center gap-1.5 bg-[#0a0518] p-0.5 rounded-lg border border-purple-500/20 text-xs font-mono">
            <button
              onClick={() => setActiveTab('feed')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded transition-colors ${
                activeTab === 'feed' ? 'bg-purple-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Zap className="w-3 h-3" />
              <span>Live Activity</span>
            </button>
            <button
              onClick={() => setActiveTab('iocs')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded transition-colors ${
                activeTab === 'iocs' ? 'bg-purple-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldAlert className="w-3 h-3 text-rose-400" />
              <span>Top IOCs ({iocs.length})</span>
            </button>
          </div>

          <button
            onClick={onOpenCEOChat}
            className="text-[10px] font-mono text-purple-400 hover:text-purple-300 flex items-center gap-0.5"
          >
            <span>Expand</span>
            <ArrowUpRight className="w-3 h-3" />
          </button>
        </div>

        {/* TAB 1: Live Activity Feed */}
        {activeTab === 'feed' && (
          <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
            {activities.map((act) => (
              <div 
                key={act.id}
                className="flex items-start gap-2.5 p-2 rounded-xl bg-[#140b2e] hover:bg-[#1b0f3f] border border-purple-500/15 transition-colors group text-xs font-mono"
              >
                {/* Custom Agent Icon */}
                <div className="w-6 h-6 rounded-md bg-[#1f1142] border border-purple-500/30 flex items-center justify-center shrink-0 p-0.5 mt-0.5">
                  <CustomAgentIcon type={act.agentType || 'malware-analysis'} className="w-3.5 h-3.5" glow={false} />
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-purple-200 text-[11px] truncate">
                      {act.agentName}
                    </span>
                    <span className="text-[9.5px] text-purple-400/70 shrink-0">
                      {act.timestamp}
                    </span>
                  </div>
                  <p className="text-slate-300 text-[10.5px] font-sans leading-snug mt-0.5">
                    {act.action}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* TAB 2: Top IOCs Indicator List */}
        {activeTab === 'iocs' && (
          <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
            {iocs.map((ioc) => {
              const sev = (ioc.severity || 'Suspicious').toLowerCase();
              const isMalicious = sev === 'malicious';
              const isSuspicious = sev === 'suspicious';

              return (
                <div
                  key={ioc.id}
                  onClick={() => onSelectIOC(ioc)}
                  className="p-2.5 rounded-xl bg-[#140b2e] hover:bg-[#1b0f3f] border border-purple-500/15 hover:border-purple-400/40 cursor-pointer transition-all text-xs font-mono group"
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-1.5 truncate">
                      <span className={`w-2 h-2 rounded-full ${
                        isMalicious ? 'bg-rose-500' : isSuspicious ? 'bg-amber-400' : 'bg-slate-400'
                      }`} />
                      <span className="font-bold text-slate-100 text-[11px] truncate group-hover:text-purple-200">
                        {ioc.value}
                      </span>
                    </div>

                    <button
                      onClick={(e) => handleCopy(e, ioc.value, ioc.id)}
                      className="p-1 rounded hover:bg-purple-900/60 text-slate-400 hover:text-purple-200 shrink-0 transition-colors"
                      title="Copy indicator"
                    >
                      {copiedId === ioc.id ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-400">
                    <span>Type: <strong className="text-purple-300">{ioc.type}</strong></span>
                    <span className="text-purple-300 font-bold">{ioc.confidence}% Conf.</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

      </div>
    </div>
  );
};
