import React, { useState, useMemo, useRef, useEffect } from 'react';
import { StreamEvent, SpecialistAgent, CaseItem } from '../../types';
import { 
  Radio, 
  ShieldAlert, 
  GitFork, 
  Layers, 
  Download, 
  FileText, 
  FileSpreadsheet, 
  ChevronDown, 
  Sliders, 
  Check 
} from 'lucide-react';
import { LogExportModal } from '../modals/LogExportModal';
import { exportLogsToFile } from '../../utils/logExporter';

interface EventStreamProps {
  events?: StreamEvent[];
  agents?: SpecialistAgent[];
  cases?: CaseItem[];
  threatScore?: number;
}

export type EventFilterType = 'All' | 'Threats' | 'Delegations';

export const EventStream: React.FC<EventStreamProps> = ({ 
  events = [], 
  agents = [], 
  cases = [], 
  threatScore = 84 
}) => {
  const [autoScroll, setAutoScroll] = useState(true);
  const [activeFilter, setActiveFilter] = useState<EventFilterType>('All');
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [isExportMenuOpen, setIsExportMenuOpen] = useState(false);
  const [lastExportedFormat, setLastExportedFormat] = useState<string | null>(null);
  
  const menuRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (evt: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(evt.target as Node)) {
        setIsExportMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Categorization helpers
  const isThreatEvent = (evt: StreamEvent): boolean => {
    if (evt.category === 'threat' || evt.type === 'threat' || evt.type === 'alert' || evt.type === 'warning') return true;
    const msg = (evt.message || '').toLowerCase();
    return (
      msg.includes('threat') || 
      msg.includes('malware') || 
      msg.includes('c2') || 
      msg.includes('beacon') || 
      msg.includes('cve') || 
      msg.includes('exploit') || 
      msg.includes('trojan') || 
      msg.includes('critical') ||
      msg.includes('anomaly')
    );
  };

  const isDelegationEvent = (evt: StreamEvent): boolean => {
    if (evt.category === 'delegation' || evt.type === 'delegate' || evt.type === 'delegation') return true;
    const msg = (evt.message || '').toLowerCase();
    return (
      msg.includes('delegat') || 
      msg.includes('assigned') || 
      msg.includes('dispatched') || 
      msg.includes('archon ->') ||
      msg.includes('task')
    );
  };

  // Filtered dataset
  const filteredEvents = useMemo(() => {
    if (activeFilter === 'Threats') {
      return events.filter(isThreatEvent);
    }
    if (activeFilter === 'Delegations') {
      return events.filter(isDelegationEvent);
    }
    return events;
  }, [events, activeFilter]);

  // Counts for filter badges
  const counts = useMemo(() => {
    return {
      all: events.length,
      threats: events.filter(isThreatEvent).length,
      delegations: events.filter(isDelegationEvent).length,
    };
  }, [events]);

  const filterOptions: { id: EventFilterType; label: string; icon: React.ElementType; count: number; activeClass: string }[] = [
    {
      id: 'All',
      label: 'All',
      icon: Layers,
      count: counts.all,
      activeClass: 'bg-purple-900/60 text-purple-200 border-purple-400/60 shadow-[0_0_8px_rgba(168,85,247,0.35)]',
    },
    {
      id: 'Threats',
      label: 'Threats',
      icon: ShieldAlert,
      count: counts.threats,
      activeClass: 'bg-rose-950/80 text-rose-200 border-rose-500/60 shadow-[0_0_8px_rgba(244,63,94,0.4)]',
    },
    {
      id: 'Delegations',
      label: 'Delegations',
      icon: GitFork,
      count: counts.delegations,
      activeClass: 'bg-cyan-950/80 text-cyan-200 border-cyan-500/60 shadow-[0_0_8px_rgba(6,182,212,0.4)]',
    },
  ];

  // Quick Direct Exporters
  const handleQuickExport = (format: 'json' | 'csv') => {
    setIsExportMenuOpen(false);
    exportLogsToFile(
      filteredEvents,
      {
        format,
        scope: activeFilter === 'All' ? 'all' : 'current',
        filterName: activeFilter,
        includeAuditHash: true,
        includeDiagnostics: true,
        threatScore
      },
      {
        agents,
        cases,
        threatScore
      }
    );
    setLastExportedFormat(format.toUpperCase());
    setTimeout(() => setLastExportedFormat(null), 3000);
  };

  return (
    <>
      <div 
        id="live-event-stream-bar"
        className="h-10 border-t px-2.5 lg:px-4 flex items-center justify-between text-xs font-mono select-none shrink-0 z-20 transition-colors duration-300 gap-2 relative"
        style={{
          backgroundColor: 'var(--color-bg-sidebar)',
          borderColor: 'var(--color-panel-border)'
        }}
      >
        {/* Title & Live Pulse */}
        <div className="flex items-center gap-2 pr-2.5 lg:pr-3.5 border-r shrink-0" style={{ borderColor: 'var(--color-panel-border)' }}>
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <span 
            className="text-[10px] lg:text-[11px] font-cyber font-bold tracking-wider hidden sm:inline"
            style={{ color: 'var(--color-primary-light)' }}
          >
            LIVE EVENT STREAM
          </span>
        </div>

        {/* Filter Button Group */}
        <div 
          id="event-stream-filter-group"
          className="flex items-center gap-1 bg-[#060212]/90 p-0.5 rounded-lg border shrink-0"
          style={{ borderColor: 'var(--color-panel-border)' }}
        >
          {filterOptions.map((opt) => {
            const Icon = opt.icon;
            const isActive = activeFilter === opt.id;
            return (
              <button
                key={opt.id}
                id={`filter-btn-${opt.id.toLowerCase()}`}
                type="button"
                onClick={() => setActiveFilter(opt.id)}
                className={`flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] lg:text-[11px] font-mono transition-all border ${
                  isActive 
                    ? opt.activeClass 
                    : 'text-slate-400 hover:text-slate-200 border-transparent hover:bg-white/5'
                }`}
              >
                <Icon className="w-2.5 h-2.5 lg:w-3 lg:h-3" />
                <span>{opt.label}</span>
                <span 
                  className={`text-[8.5px] px-1 py-0.2 rounded-full font-semibold ${
                    isActive ? 'bg-white/20 text-white' : 'bg-white/5 text-slate-400'
                  }`}
                >
                  {opt.count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Stream Items Ticker */}
        <div className="flex-1 overflow-x-auto whitespace-nowrap px-2 flex items-center gap-4 lg:gap-6 no-scrollbar text-xs">
          {filteredEvents.length > 0 ? (
            filteredEvents.map((evt) => {
              const isThreat = isThreatEvent(evt);
              const isDelegation = isDelegationEvent(evt);

              return (
                <div key={evt.id} className="inline-flex items-center gap-1.5 shrink-0 group">
                  <span className="text-purple-400 font-mono text-[10px] font-semibold" style={{ color: 'var(--color-primary-light)' }}>
                    {evt.timestamp}
                  </span>

                  {isThreat && (
                    <span className="px-1 py-0.2 rounded text-[8px] font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-500/40">
                      THREAT
                    </span>
                  )}
                  {isDelegation && (
                    <span className="px-1 py-0.2 rounded text-[8px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/40">
                      DELEGATE
                    </span>
                  )}

                  <span className="text-slate-200 font-sans text-xs">
                    {evt.message}
                  </span>
                </div>
              );
            })
          ) : (
            <div className="text-slate-500 text-[11px] font-mono italic">
              No events found under the "{activeFilter}" filter
            </div>
          )}
        </div>

        {/* Action Controls Group: Download Logs + Auto Scroll */}
        <div className="flex items-center gap-1.5 pl-2 lg:pl-3 border-l shrink-0" style={{ borderColor: 'var(--color-panel-border)' }}>
          
          {/* Download Logs Dropdown / Action */}
          <div className="relative" ref={menuRef}>
            <div className="flex items-center rounded bg-[#060212]/90 border border-cyan-500/30 hover:border-cyan-400 transition-colors">
              <button
                type="button"
                id="event-stream-download-btn"
                onClick={() => setIsExportModalOpen(true)}
                className="flex items-center gap-1.5 px-2 py-0.5 text-[10px] lg:text-[11px] font-mono text-cyan-300 hover:text-white font-semibold transition-colors"
                title="Export diagnostic and threat event stream logs to JSON or CSV"
              >
                {lastExportedFormat ? (
                  <>
                    <Check className="w-2.5 h-2.5 lg:w-3 lg:h-3 text-emerald-400" />
                    <span className="text-emerald-300">Exported {lastExportedFormat}</span>
                  </>
                ) : (
                  <>
                    <Download className="w-2.5 h-2.5 lg:w-3 lg:h-3 text-cyan-400" />
                    <span>Download Logs</span>
                  </>
                )}
              </button>

              <button
                type="button"
                id="event-stream-download-dropdown-btn"
                onClick={() => setIsExportMenuOpen(prev => !prev)}
                className="px-1 py-1 text-cyan-400 hover:text-cyan-200 border-l border-cyan-500/30 hover:bg-cyan-500/20 transition-colors"
                title="Choose export format"
              >
                <ChevronDown className="w-2.5 h-2.5" />
              </button>
            </div>

            {/* Quick Export Popover Menu */}
            {isExportMenuOpen && (
              <div 
                className="absolute bottom-full right-0 mb-1.5 w-52 bg-[#090514] border border-cyan-500/40 rounded-lg shadow-[0_0_25px_rgba(6,182,212,0.3)] p-1.5 z-50 text-[11px] font-mono animate-fadeIn"
                style={{ backgroundColor: 'var(--color-bg-sidebar)' }}
              >
                <div className="px-2 py-1 text-[10px] text-slate-400 uppercase tracking-wider font-cyber border-b border-slate-800 mb-1">
                  Export Forensics
                </div>
                
                <button
                  type="button"
                  onClick={() => handleQuickExport('json')}
                  className="w-full flex items-center justify-between px-2 py-1.5 rounded hover:bg-cyan-950/60 hover:text-cyan-200 text-slate-300 text-left transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <FileText className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Export as JSON</span>
                  </div>
                  <span className="text-[9px] px-1 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30">SIEM</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleQuickExport('csv')}
                  className="w-full flex items-center justify-between px-2 py-1.5 rounded hover:bg-purple-950/60 hover:text-purple-200 text-slate-300 text-left transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <FileSpreadsheet className="w-3.5 h-3.5 text-purple-400" />
                    <span>Export as CSV</span>
                  </div>
                  <span className="text-[9px] px-1 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-500/30">TABLE</span>
                </button>

                <div className="border-t border-slate-800 my-1" />

                <button
                  type="button"
                  onClick={() => {
                    setIsExportMenuOpen(false);
                    setIsExportModalOpen(true);
                  }}
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded hover:bg-white/10 text-cyan-300 text-left transition-colors font-semibold"
                >
                  <Sliders className="w-3.5 h-3.5" />
                  <span>Advanced Export Options...</span>
                </button>
              </div>
            )}
          </div>

          {/* Auto Scroll Toggle */}
          <button
            id="event-stream-autoscroll-btn"
            type="button"
            onClick={() => setAutoScroll(prev => !prev)}
            className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] lg:text-[11px] font-mono transition-colors ${
              autoScroll 
                ? 'text-purple-200 bg-purple-950/60 border border-purple-500/40 glow-theme-sm font-semibold' 
                : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            <Radio className="w-2.5 h-2.5 lg:w-3 lg:h-3 text-purple-400" style={{ color: 'var(--color-primary-light)' }} />
            <span className="hidden sm:inline">Auto Scroll</span>
          </button>
        </div>
      </div>

      {/* Forensic Log Export Modal */}
      <LogExportModal 
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        events={events}
        activeFilter={activeFilter}
        filteredEvents={filteredEvents}
        agents={agents}
        cases={cases}
        threatScore={threatScore}
      />
    </>
  );
};


