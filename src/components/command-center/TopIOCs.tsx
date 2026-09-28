import React from 'react';
import { IOCItem } from '../../types';
import { ArrowUpRight, ShieldAlert } from 'lucide-react';
import { GothicCornerFiligree } from '../common/GothicCornerFiligree';

interface TopIOCsProps {
  iocs?: IOCItem[];
  onSelectIOC?: (ioc: IOCItem) => void;
  onViewAll?: () => void;
}

export const TopIOCs: React.FC<TopIOCsProps> = ({ iocs = [], onSelectIOC, onViewAll }) => {
  return (
    <div 
      id="top-iocs-widget"
      className="rounded-xl bg-[#090317]/95 border border-purple-500/30 p-3.5 shadow-[0_0_15px_rgba(168,85,247,0.2)] space-y-2.5 relative overflow-hidden"
    >
      <GothicCornerFiligree size="sm" opacity="text-purple-400/50" />
      {/* Header */}
      <div className="flex items-center justify-between border-b border-purple-500/20 pb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-cyber font-bold text-white tracking-wider">
            TOP IOCS
          </span>
          <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse glow-red" />
        </div>
        {onViewAll && (
          <button 
            onClick={onViewAll}
            className="text-[10.5px] font-mono text-purple-400 hover:text-purple-300 flex items-center gap-1"
          >
            <span>View All</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* List */}
      <div className="space-y-1.5">
        {(iocs || []).slice(0, 5).map((ioc) => {
          const sev = (ioc.severity || 'Suspicious').toLowerCase();
          const isMalicious = sev === 'malicious';
          const isSuspicious = sev === 'suspicious';

          return (
            <div 
              key={ioc.id}
              onClick={() => onSelectIOC && onSelectIOC(ioc)}
              className="flex items-center justify-between p-2 px-2.5 rounded-lg bg-[#140b2e] hover:bg-[#1a0f3d] border border-purple-500/20 cursor-pointer text-xs font-mono transition-all group"
            >
              <div className="min-w-0 pr-2">
                <div className="text-[11.5px] font-medium text-slate-200 truncate group-hover:text-purple-200">
                  {ioc.value}
                </div>
                <div className="text-[10px] text-purple-300/70 mt-0.5">
                  {ioc.type}
                </div>
              </div>

              <div className="flex items-center gap-1.5 shrink-0">
                <span className={`text-[10.5px] font-bold ${
                  isMalicious ? 'text-rose-400' : isSuspicious ? 'text-amber-400' : 'text-slate-400'
                }`}>
                  • {ioc.severity || 'Suspicious'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
