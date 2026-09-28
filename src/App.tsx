import React, { useState, useEffect, useRef } from 'react';
import { 
  INITIAL_CEO, 
  INITIAL_AGENTS, 
  INITIAL_MISSION, 
  INITIAL_ACTIVITIES, 
  INITIAL_IOCS, 
  INITIAL_CASES, 
  INITIAL_PROVIDERS, 
  INITIAL_STREAM_EVENTS,
  INITIAL_ARTIFACTS
} from './data/mockData';
import { SpecialistAgent, CaseItem, IOCItem, CEONode, MissionData, ThemeMode, EvidenceArtifact, AIProvider, StreamEvent, AgentFinding, ActivityEvent, AgentProgressStage } from './types';
import { SearchItemType } from './utils/searchIndex';
import { stripApiKeys } from './utils/security';
import { initializeSession, secureFetchWithRecovery } from './utils/apiClient';
import { buildPipelineOrder, initializeAgentFindings, generateFinding, fetchThreatIntelFinding, computeAggregateVerdict, computeInvestigationMetrics } from './utils/multiAgentAnalysis';
import { refreshCustomRules } from './utils/customRules';
import { RULE_CAPABLE_AGENT_IDS } from './types';
import { signInWithGooglePopup, signOutFirebase, syncInvestigationToFirestore } from './firebase';

// Layout Components
import { Sidebar } from './components/layout/Sidebar';
import { TopBar } from './components/layout/TopBar';
import { EmergencyBanner } from './components/layout/EmergencyBanner';

// Dashboard Layout Customization & Widgets
import { useDashboardLayout } from './hooks/useDashboardLayout';
import { WidgetRenderer } from './components/dashboard/WidgetRenderer';
import { CustomizeModeBanner } from './components/dashboard/CustomizeModeBanner';
import { DashboardLayoutModal } from './components/dashboard/DashboardLayoutModal';
import { EventStream } from './components/command-center/EventStream';

// Interactive Modals & Drawers
import { AgentDetailModal } from './components/modals/AgentDetailModal';
import { CEOChatDrawer } from './components/modals/CEOChatDrawer';
import { CaseDetailModal } from './components/modals/CaseDetailModal';
import { IOCDetailModal } from './components/modals/IOCDetailModal';
import { CommandPalette } from './components/modals/CommandPalette';
import { EvidenceUploadModal } from './components/modals/EvidenceUploadModal';
import { AIProvidersModal } from './components/modals/AIProvidersModal';
import { NewCaseModal } from './components/modals/NewCaseModal';
import { VoiceCommandHUD } from './components/voice/VoiceCommandHUD';
import { TacticalShortcutsModal } from './components/modals/TacticalShortcutsModal';
import { AgentsFleetModal } from './components/modals/AgentsFleetModal';
import { useVoiceRecognition } from './hooks/useVoiceRecognition';
import { exportLogsToFile } from './utils/logExporter';
import {
  PlaygroundPage, BattleModePage, PromptLibraryPage, MemoryCenterPage,
} from './components/pages/AIPages';
import { CasesPage, ReportsPage, TimelinePage, InvestigationPage } from './components/pages/InvestigationPages';
import { ThreatIntelPage, IOCExplorerPage, MitreBrowserPage, KnowledgeGraphPage } from './components/pages/IntelPages';
import { MalwareIntelligencePage, MalwareLearningPage } from './components/pages/MalwareIntelPages';
import { WorkflowsPage, AnalyticsPage, SystemMonitorPage, SettingsPage } from './components/pages/OperationsPages';
import { ToolsPage } from './components/pages/ToolsPages';
import {
  BillingPage, UpgradePage, DowngradePage, CancelSubscriptionPage,
  PaymentSuccessPage, PaymentFailedPage, PaymentPendingPage,
} from './components/pages/AccountPages';
import { HelpCenterPageEmbedded, SupportPageEmbedded } from './components/pages/SupportPages';
import { UXStatesShowcasePage } from './components/pages/UXStatesShowcasePage';

export default function App() {
  // Theme State with persistence
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem('nexsus_clean_theme');
    if (saved === 'deep-emerald' || saved === 'crimson-alert' || saved === 'cyber-purple') {
      return saved;
    }
    return 'cyber-purple';
  });

  // Threat & Emergency Override State with LocalStorage persistence
  const [threatScore, setThreatScore] = useState<number>(() => {
    const saved = localStorage.getItem('nexsus_clean_threat_score');
    return saved ? Number(saved) : 0;
  });
  const [threatThreshold, setThreatThreshold] = useState<number>(() => {
    const saved = localStorage.getItem('nexsus_clean_threat_threshold');
    return saved ? Number(saved) : 80;
  });
  const [isManualOverride, setIsManualOverride] = useState<boolean>(false);

  // Compute if Emergency Mode is Active
  const isEmergencyActive = isManualOverride || threatScore >= threatThreshold;
  const threatLevelLabel = threatScore >= 90 ? 'CRITICAL' : threatScore >= 75 ? 'HIGH' : threatScore >= 50 ? 'ELEVATED' : 'NOMINAL';

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.body.setAttribute('data-theme', theme);
    localStorage.setItem('nexsus_clean_theme', theme);
  }, [theme]);

  useEffect(() => {
    // Load analyst-added custom rules once for every pattern-based agent so
    // the pipeline tick loop (which must stay synchronous) has them cached
    // and ready via applyCustomRules() before any artifact finishes a step.
    refreshCustomRules(RULE_CAPABLE_AGENT_IDS.filter((id) => id !== 'malware-analysis'));
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute('data-emergency', isEmergencyActive ? 'true' : 'false');
    document.body.setAttribute('data-emergency', isEmergencyActive ? 'true' : 'false');
  }, [isEmergencyActive]);

  useEffect(() => {
    localStorage.setItem('nexsus_clean_threat_score', String(threatScore));
  }, [threatScore]);

  useEffect(() => {
    localStorage.setItem('nexsus_clean_threat_threshold', String(threatThreshold));
  }, [threatThreshold]);

  // Navigation & Modal State
  const [activeNav, setActiveNav] = useState('dashboard');
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [searchInitialFilter, setSearchInitialFilter] = useState<SearchItemType | 'all'>('all');
  const [isCEOChatOpen, setIsCEOChatOpen] = useState(false);
  const [ceoChatPrompt, setCeoChatPrompt] = useState<string | undefined>(undefined);
  const [isEvidenceModalOpen, setIsEvidenceModalOpen] = useState(false);
  const [evidenceModalCaseId, setEvidenceModalCaseId] = useState<string>('');

  const openEvidenceModal = (caseId?: string) => {
    setEvidenceModalCaseId(caseId || '');
    setIsEvidenceModalOpen(true);
  };
  const [isProvidersModalOpen, setIsProvidersModalOpen] = useState(false);
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState(false);
  const [isVoiceHUDOpen, setIsVoiceHUDOpen] = useState(false);
  const [isShortcutsModalOpen, setIsShortcutsModalOpen] = useState(false);
  const [isAgentsFleetModalOpen, setIsAgentsFleetModalOpen] = useState(false);

  const handleOpenSearchWithFilter = (filter: SearchItemType | 'all' = 'all') => {
    setSearchInitialFilter(filter);
    setIsSearchOpen(true);
  };

  // Dashboard Layout Management with Drag-and-Drop & LocalStorage persistence
  const {
    widgets,
    mainWidgets,
    sidebarWidgets,
    isCustomizeMode,
    isLayoutModalOpen,
    draggedWidgetId,
    dragOverWidgetId,
    toggleCustomizeMode,
    setIsCustomizeMode,
    openLayoutModal,
    closeLayoutModal,
    toggleWidgetVisibility,
    updateWidgetWidth,
    switchWidgetSection,
    moveWidget,
    handleDragStart,
    handleDragOver,
    handleDragLeave,
    handleDragEnd,
    handleDrop,
    resetLayout,
    applyPreset,
    setWidgets
  } = useDashboardLayout();
  
  // Selected items for modal inspection
  const [selectedAgent, setSelectedAgent] = useState<SpecialistAgent | null>(null);
  const [selectedCase, setSelectedCase] = useState<CaseItem | null>(null);
  const [selectedIOC, setSelectedIOC] = useState<IOCItem | null>(null);

  // Core Dynamic Data with LocalStorage Persistence
  const [ceo, setCeo] = useState<CEONode>(() => {
    try {
      const saved = localStorage.getItem('nexsus_clean_ceo_state');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === 'object') {
          return { ...INITIAL_CEO, ...parsed };
        }
      }
    } catch (e) {
      console.warn('Failed to parse saved CEO state', e);
    }
    return INITIAL_CEO;
  });
  // Per-agent model assignments persist across reloads (which provider +
  // model each specialist agent is set to run on — same idea as the CEO's
  // "Set as Primary AI Engine", just scoped to one fleet member).
  const [agents, setAgents] = useState<SpecialistAgent[]>(() => {
    try {
      const saved = localStorage.getItem('nexsus_clean_agent_models');
      if (saved) {
        const overrides = JSON.parse(saved) as Record<string, { providerName: string; model: string }>;
        if (overrides && typeof overrides === 'object') {
          return INITIAL_AGENTS.map((a) => (overrides[a.id] ? { ...a, model: overrides[a.id].model } : a));
        }
      }
    } catch (e) {
      console.warn('Failed to parse saved agent model assignments', e);
    }
    return INITIAL_AGENTS;
  });

  const isProdMode = Boolean(import.meta.env.PROD);
  const [apiUnavailableError, setApiUnavailableError] = useState<string | null>(null);
  const [operatorUser, setOperatorUser] = useState<{
    id: string;
    name: string;
    email: string;
    role: 'Admin' | 'Analyst' | 'Viewer';
    badge: string;
  }>({
    id: 'analyst-1',
    name: 'Lead SOC Operator',
    email: 'operator@agency.gov',
    role: 'Admin',
    badge: 'SOC-771',
  });
  const [rbacNotice, setRbacNotice] = useState<string | null>(null);

  const [mission, setMission] = useState<MissionData>(INITIAL_MISSION);
  const [activities, setActivities] = useState<ActivityEvent[]>(() => (isProdMode ? [] : INITIAL_ACTIVITIES));
  const [iocs, setIocs] = useState<IOCItem[]>(() => (isProdMode ? [] : INITIAL_IOCS));
  const [cases, setCases] = useState<CaseItem[]>(() => (isProdMode ? [] : INITIAL_CASES));
  
  // AI Providers with LocalStorage persistence (Secrets strictly stripped)
  const [providers, setProviders] = useState<AIProvider[]>(() => {
    try {
      const saved = localStorage.getItem('nexsus_clean_ai_providers');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const sanitized = stripApiKeys(parsed);
          localStorage.setItem('nexsus_clean_ai_providers', JSON.stringify(sanitized));
          return sanitized;
        }
      }
    } catch (e) {
      console.warn('Failed to parse saved AI providers', e);
    }
    return stripApiKeys(INITIAL_PROVIDERS);
  });

  const [streamEvents, setStreamEvents] = useState<StreamEvent[]>(() => (isProdMode ? [] : INITIAL_STREAM_EVENTS));
  const [artifacts, setArtifacts] = useState<EvidenceArtifact[]>(() => (isProdMode ? [] : INITIAL_ARTIFACTS));

  useEffect(() => {
    const mappedActivities: ActivityEvent[] = streamEvents.slice(0, 60).map((event, index) => ({
      id: event.id || `activity-${index}`,
      timestamp: event.timestamp || event.time || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      agentName: event.source || 'SYSTEM',
      agentType: event.category === 'threat' ? 'threat-intel' : event.category === 'delegation' ? 'archon' : 'malware-analysis',
      action: event.message,
      type: event.type || 'info',
    }));
    setActivities(mappedActivities);
  }, [streamEvents]);

  // Update CEO state and persist
  const handleUpdateCeo = (updates: Partial<CEONode>) => {
    setCeo(prev => {
      const updated = { ...prev, ...updates };
      try {
        localStorage.setItem('nexsus_clean_ceo_state', JSON.stringify(updated));
      } catch (e) {
        console.warn('Failed to persist CEO state', e);
      }
      return updated;
    });

    if (updates.model) {
      const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      setStreamEvents(prev => [
        {
          id: `st-${Date.now()}`,
          timestamp: timeStr,
          message: `Commander ARCHON primary neural engine shifted to ${updates.model} [Context: ${updates.contextWindow || '200K'}]`,
          type: 'info',
          category: 'system',
          source: 'CEO ARCHON'
        },
        ...prev
      ]);
    }
  };

  // Update AI Providers and persist without sensitive keys
  const handleUpdateProviders = (updated: AIProvider[]) => {
    const sanitized = stripApiKeys(updated);
    setProviders(sanitized);
    try {
      localStorage.setItem('nexsus_clean_ai_providers', JSON.stringify(sanitized));
    } catch (e) {
      console.error('Failed to persist AI providers', e);
    }
  };

  const handleSelectPrimaryModel = (providerName: string, modelName: string) => {
    setCeo(prev => ({
      ...prev,
      model: `${providerName} (${modelName})`
    }));

    // Add stream event notification
    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setStreamEvents(prev => [
      {
        id: `st-${Date.now()}`,
        timestamp: timeStr,
        message: `Commander ARCHON primary AI engine shifted to ${providerName} [${modelName}]`,
        type: 'info',
        category: 'system',
        source: 'CEO ARCHON'
      },
      ...prev
    ]);
  };

  // Assign a specific provider + model to one specialist agent (mirrors
  // handleSelectPrimaryModel for the CEO, scoped to a single fleet member).
  const handleUpdateAgentModel = (agentId: string, providerName: string, modelName: string) => {
    setAgents(prev => {
      const updated = prev.map(a => (a.id === agentId ? { ...a, model: modelName } : a));
      try {
        const saved = localStorage.getItem('nexsus_clean_agent_models');
        const overrides = saved ? JSON.parse(saved) : {};
        overrides[agentId] = { providerName, model: modelName };
        localStorage.setItem('nexsus_clean_agent_models', JSON.stringify(overrides));
      } catch (e) {
        console.warn('Failed to persist agent model assignment', e);
      }
      return updated;
    });

    const agentName = agents.find(a => a.id === agentId)?.name || agentId;
    const timeStr2 = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setStreamEvents(prev => [
      {
        id: `st-${Date.now()}`,
        timestamp: timeStr2,
        message: `${agentName} reassigned to ${providerName} [${modelName}]`,
        type: 'info',
        category: 'system',
        source: 'CEO ARCHON'
      },
      ...prev
    ]);
  };

  const handleSwitchOperatorRole = async (newRole: 'Admin' | 'Analyst' | 'Viewer') => {
    try {
      const res = await secureFetchWithRecovery('/api/auth/role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: newRole, email: operatorUser.email, name: operatorUser.name, uid: operatorUser.id }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.user) {
          setOperatorUser(data.user);
          setRbacNotice(`Active RBAC role switched to ${data.user.role} (${data.user.badge})`);
          setTimeout(() => setRbacNotice(null), 4000);
        }
      }
    } catch (err: any) {
      setApiUnavailableError(`Failed to switch role: ${err?.message || 'API unavailable'}`);
    }
  };

  const handleGoogleSignIn = async () => {
    try {
      const fbUser = await signInWithGooglePopup();
      const res = await secureFetchWithRecovery('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          uid: fbUser.uid,
          email: fbUser.email,
          name: fbUser.name,
          role: fbUser.role,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.user) setOperatorUser(data.user);
      }
      setRbacNotice(`Authenticated via Firebase Google Sign-In as ${fbUser.email} [${fbUser.role}]`);
      setTimeout(() => setRbacNotice(null), 5000);
    } catch (err: any) {
      setRbacNotice(`Google Sign-In notice: ${err?.message || 'Popup closed'}`);
      setTimeout(() => setRbacNotice(null), 5000);
    }
  };

  // Bootstrap operator session on mount
  useEffect(() => {
    initializeSession().then(async () => {
      try {
        const meRes = await fetch('/api/auth/me', { credentials: 'include' });
        if (meRes.ok) {
          const meData = await meRes.json();
          if (meData.user) setOperatorUser(meData.user);
        }
      } catch {
        // Handled by syncBackendInvestigationState
      }
    });
  }, []);

  // Sync real backend investigation cases, IOCs, and live activity stream (Item 2: No silent fallback to mockData when API fails)
  const syncBackendInvestigationState = async () => {
    try {
      const [liveRes, casesRes, iocsRes] = await Promise.all([
        secureFetchWithRecovery('/api/investigations/live-activity'),
        secureFetchWithRecovery('/api/investigations'),
        secureFetchWithRecovery('/api/malware-intel/knowledge/iocs'),
      ]);

      if (!casesRes.ok || !liveRes.ok) {
        setApiUnavailableError(
          `Backend API / Database returned HTTP ${casesRes.status || liveRes.status}. Production mode strictly refuses to display mock fallback data.`,
        );
        if (isProdMode) {
          setCases([]);
          setActivities([]);
          setIocs([]);
        }
        return;
      }

      setApiUnavailableError(null);

      if (iocsRes.ok) {
        const iocsData = await iocsRes.json();
        if (Array.isArray(iocsData.iocs) && iocsData.iocs.length > 0) {
          const mappedIocs: IOCItem[] = iocsData.iocs.map((raw: any, idx: number) => {
            const conf = raw.threatScore || Math.round((raw.confidence || 0.9) * 100);
            const severity: 'Malicious' | 'Suspicious' | 'Benign' =
              raw.severity === 'Malicious' || raw.severity === 'Suspicious' || raw.severity === 'Benign'
                ? raw.severity
                : conf >= 80
                  ? 'Malicious'
                  : conf >= 50
                    ? 'Suspicious'
                    : 'Benign';
            return {
              id: raw.id || `ioc-db-${idx}`,
              value: raw.value || raw.ioc || 'unknown',
              type: raw.type === 'ip' ? 'IP' : raw.type === 'domain' ? 'Domain' : raw.type === 'url' ? 'URL' : 'File Hash',
              severity,
              confidence: conf,
              source: raw.source || 'Malware Analysis',
              firstSeen: raw.firstSeen || '2026-03-15',
              lastSeen: 'Active',
              tags: [raw.extractionMethod || 'extracted', raw.location || 'offset 0x0000'],
              associatedActor: 'Catalogued Indicator',
              threatActor: raw.threatActor || 'Catalogued Indicator',
              description: raw.description || `${raw.extractionMethod || 'static'} @ ${raw.location || 'offset 0x0000'}`,
              status: 'Active',
            };
          });
          setIocs((prev) => (isProdMode ? mappedIocs : [...mappedIocs, ...prev.filter((p) => !mappedIocs.some((m) => m.value === p.value))]));
        }
      }

      const liveData = await liveRes.json();
      if (Array.isArray(liveData.activities) && liveData.activities.length > 0) {
        setActivities(liveData.activities);
      }

      const casesData = await casesRes.json();
      if (Array.isArray(casesData.investigations) && casesData.investigations.length > 0) {
        const mappedCases = casesData.investigations.map((inv: any) => ({
          id: inv.id,
          caseNumber: inv.caseNumber,
          title: inv.title,
          severity: inv.severity || 'HIGH',
          status: inv.status || 'COMPLETED',
          assignedAgent: inv.assignedAgent || 'ARCHON',
          confidence: inv.confidence || 90,
          time: new Date(inv.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          lead: inv.assignedAgent || 'ARCHON',
          indicatorsCount:
            (inv.evidencePackage?.available_artifacts?.ips?.length || 0) +
              (inv.evidencePackage?.available_artifacts?.domains?.length || 0) +
              (inv.evidencePackage?.available_artifacts?.urls?.length || 0) || 6,
          progress: inv.status === 'COMPLETED' ? 100 : 75,
          reportSummary: inv.reportSummary,
          agentFindings: inv.agentFindings,
          correlatedFindings: inv.correlatedFindings,
          verificationMatrix: inv.verificationMatrix,
          mitreAttackTechniques: inv.mitreAttackTechniques,
        }));

        setCases((prev) => {
          if (isProdMode) return mappedCases;
          const result = [...mappedCases];
          prev.forEach((existing) => {
            if (!result.some((r) => r.id === existing.id || r.caseNumber === existing.caseNumber)) {
              result.push(existing);
            }
          });
          return result;
        });
      }
    } catch (err: any) {
      setApiUnavailableError(
        `API / Database Connection Unavailable (${err?.message || 'Network failure'}). Refusing to silently display mock data.`,
      );
      if (isProdMode) {
        setCases([]);
        setActivities([]);
        setIocs([]);
      }
    }
  };

  useEffect(() => {
    void syncBackendInvestigationState();
    const interval = setInterval(syncBackendInvestigationState, 15000);
    return () => clearInterval(interval);
  }, []);

  // --- Live investigation heartbeat -----------------------------------
  // Keeps ref mirrors of `agents` / `artifacts` so the interval below always
  // reads the latest state without needing to be re-created on every update.
  const agentsRef = useRef<SpecialistAgent[]>(agents);
  useEffect(() => {
    agentsRef.current = agents;
  }, [agents]);

  const artifactsRef = useRef<EvidenceArtifact[]>(artifacts);
  useEffect(() => {
    artifactsRef.current = artifacts;
  }, [artifacts]);

  const artifactIds = artifacts.map((artifact) => artifact.id).join(',');
  useEffect(() => {
    if (!artifactIds) return;
    let cancelled = false;
    const loadPersistedEvents = async () => {
      const responses = await Promise.all(
        artifactIds.split(',').map(async (artifactId) => {
          const response = await secureFetchWithRecovery(`/api/investigations/${encodeURIComponent(artifactId)}/events`);
          if (!response.ok) return [] as StreamEvent[];
          const body = await response.json().catch(() => null);
          return (body?.events || []) as StreamEvent[];
        }),
      );
      if (cancelled) return;
      const persisted = responses.flat();
      if (persisted.length) setStreamEvents((current) => {
        const known = new Set(current.map((event) => event.id));
        return [...persisted.filter((event) => !known.has(event.id)), ...current].slice(0, 200);
      });
    };
    void loadPersistedEvents().catch(() => undefined);
    return () => { cancelled = true; };
  }, [artifactIds]);

  // Rotating "what's happening right now" step messages per specialist,
  // used for agents that are busy on a case (not an artifact pipeline —
  // those get their own generated findings from generateFinding()).
  useEffect(() => {
    const AGENT_STEP_MESSAGES: Record<string, string[]> = {
      'malware-analysis': [
        'Preparing static artifact analysis...',
        'Reviewing file structure and embedded strings...',
        'Checking for suspicious imports and persistence indicators...',
        'Assessing entropy and obfuscation markers...',
        'Documenting applicable static findings and limitations...'
      ],
      'ioc-extraction': [
        'Parsing artifact content for indicators...',
        'Normalizing de-fanged and repeated IOCs...',
        'Validating extracted values against syntax rules...',
        'Grouping indicators by type and confidence...',
        'Preparing indicator summary for downstream correlation...'
      ],
      'threat-intel': [
        'Checking configured threat-intel providers...',
        'Correlating indicators with supported external feeds...',
        'Reviewing available reputation data for known infrastructure...',
        'Recording provider status and coverage gaps...',
        'Summarizing external evidence if a connector is available...'
      ],
      'network-analysis': [
        'Reviewing embedded URLs, domains, and sockets...',
        'Checking whether network primitives are linked to execution or downloads...',
        'Assessing static network indicators and context...',
        'Documenting what was observed versus what remains unverified...',
        'Recording any network-related evidence gaps...'
      ],
      'code-review': [
        'Reviewing script and code patterns...',
        'Checking for execution, persistence, and download logic...',
        'Scanning for encoded payloads and suspicious API usage...',
        'Validating whether the artifact is executable or descriptive text...',
        'Documenting code-level evidence and limitations...'
      ],
      'report-generator': [
        'Synthesizing specialist findings...',
        'Drafting executive summary and evidence trail...',
        'Mapping findings to relevant contexts and gaps...',
        'Compiling recommendations and confidence notes...',
        'Formatting the investigative report...'
      ],
      'memory-agent': [
        'Searching historical case and IOC relationships...',
        'Comparing structure, strings, and indicators...',
        'Reviewing related samples and family associations...',
        'Recording similarity and confidence limits...'
      ],
      'verification-agent': [
        'Cross-checking reported claims against available evidence...',
        'Checking whether findings are supported, weak, or unverified...',
        'Auditing coverage and contradiction risk...',
        'Preparing a verified evidence summary...'
      ]
    };

    const threatIntelResults = new Map<string, ReturnType<typeof generateFinding>>();
    const threatIntelStarted = new Set<string>();
    let tickRunning = false;
    const interval = setInterval(() => {
      if (tickRunning) return;
      tickRunning = true;
      void (async () => {
       try {
      const currentAgents = agentsRef.current;
      const currentArtifacts = artifactsRef.current;
      const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

      type PipelineUpdate = { id: string; name: string; currentTask: string; progress: number; completedTask: boolean };
      const pipelineAgentUpdates = new Map<string, PipelineUpdate>();
      const pipelineStreamEvents: StreamEvent[] = [];
      let artifactsChanged = false;

      // Agents already mid-step on some artifact right now — reserved so a
      // second artifact can't also claim them in the same tick.
      const busyAgentIds = new Set<string>();
      currentArtifacts.forEach(art => {
        const active = art.agentFindings?.find(f => f.status === 'analyzing');
        if (active) busyAgentIds.add(active.agentId);
      });

      await Promise.all(currentArtifacts.map(async (art) => {
        const active = art.agentFindings?.find(f => f.status === 'analyzing');
        if (!active || active.agentId !== 'threat-intel' || threatIntelStarted.has(art.id)) return;
        threatIntelStarted.add(art.id);
        threatIntelResults.set(art.id, await fetchThreatIntelFinding(art));
      }));

      const nextArtifacts = currentArtifacts.map(art => {
        if (art.status !== 'Analyzing' || !art.agentFindings || art.agentFindings.length === 0) {
          return art;
        }

        const findings = [...art.agentFindings];
        const activeIdx = findings.findIndex(f => f.status === 'analyzing');

        if (activeIdx === -1) {
          // No step currently running — try to start the next queued one.
          const nextIdx = findings.findIndex(f => f.status === 'pending');
          if (nextIdx === -1) {
            // Every specialist has finished — finalize the overall verdict.
            const { maliciousScore, verdict } = computeAggregateVerdict(findings);
            const investigationMetrics = computeInvestigationMetrics(findings);
            artifactsChanged = true;
            pipelineStreamEvents.push({
              id: `st-${Date.now()}-${art.id}-final`,
              artifactId: art.id,
              timestamp: timeStr,
              message: verdict === 'Unknown'
                ? `REPORT_GENERATED: "${art.name}" — full specialist pipeline finished, but no specialist produced a scored, evidence-backed verdict for this artifact type. Marked UNASSESSED rather than Safe.`
                : `REPORT_GENERATED: "${art.name}" — full specialist pipeline finished. Verdict: ${verdict.toUpperCase()} (${maliciousScore}% malicious score).`,
              type: verdict === 'Malicious' ? 'alert' : verdict === 'Suspicious' ? 'warning' : verdict === 'Unknown' ? 'info' : 'success',
              category: 'forensics',
              source: 'REPORT_GENERATED'
            });
            return {
              ...art,
              status: (verdict === 'Safe' ? 'Clean' : verdict === 'Unknown' ? 'Parsed' : 'Flagged') as EvidenceArtifact['status'],
              verdict,
              maliciousScore,
              ...investigationMetrics
            };
          }

          const candidate = findings[nextIdx];
          if (busyAgentIds.has(candidate.agentId)) {
            return art; // that specialist is busy on another artifact — retry next tick
          }
          busyAgentIds.add(candidate.agentId);
          const startProgress = 10;
          findings[nextIdx] = { ...candidate, status: 'analyzing', stepProgress: startProgress };
          artifactsChanged = true;

          const startEventType =
            candidate.agentId === 'malware-analysis' ? 'MALWARE_ANALYSIS_STARTED'
            : candidate.agentId === 'threat-intel' ? 'TOOL_QUERY_STARTED'
            : candidate.agentId === 'verification-agent' ? 'VERIFICATION_STARTED'
            : 'STATIC_ANALYSIS_STARTED';

          pipelineAgentUpdates.set(candidate.agentId, {
            id: candidate.agentId,
            name: candidate.agentName,
            currentTask: `Analyzing evidence: ${art.name}`,
            progress: startProgress,
            completedTask: false
          });
          pipelineStreamEvents.push({
            id: `st-${Date.now()}-${art.id}-${candidate.agentId}-start`,
            artifactId: art.id,
            timestamp: timeStr,
            message: `${startEventType}: ${candidate.agentName} started inspecting "${art.name}".`,
            type: 'info',
            category: 'forensics',
            source: startEventType
          });
          return { ...art, agentFindings: findings };
        }

        // A step is actively running — advance it through real progress stages (Fix 12)
        const active = findings[activeIdx];
        const bump = 35;
        const newStepProgress = Math.min(100, active.stepProgress + bump);
        artifactsChanged = true;

        const stageName: AgentProgressStage =
          newStepProgress >= 100 ? 'Completed'
          : newStepProgress >= 85 ? 'Verifying'
          : newStepProgress >= 70 ? 'Correlating'
          : newStepProgress >= 50 ? 'Enriching'
          : newStepProgress >= 30 ? 'Analyzing'
          : 'Extracting features';

        if (newStepProgress >= 100) {
          const content = active.agentId === 'threat-intel'
            ? (threatIntelResults.get(art.id) || generateFinding(active.agentId, art))
            : generateFinding(active.agentId, art);
          findings[activeIdx] = {
            ...active,
            status: 'complete',
            stage: 'Completed',
            stepProgress: 100,
            verdict: content.verdict,
            canonicalVerdict: content.canonicalVerdict,
            maliciousScore: content.maliciousScore,
            summary: content.summary,
            findings: content.findings,
            structuredEvidence: content.structuredEvidence,
            evidenceGaps: content.evidenceGaps,
            evidenceCoverage: content.evidenceCoverage,
            evidenceQuality: content.evidenceQuality,
            completedAt: timeStr
          };
          pipelineAgentUpdates.set(active.agentId, {
            id: active.agentId,
            name: active.agentName,
            currentTask: 'Idle',
            progress: 100,
            completedTask: true
          });
          const completionEventType =
            active.agentId === 'ioc-extraction' ? 'IOC_DISCOVERED'
            : active.agentId === 'threat-intel' ? 'TOOL_QUERY_COMPLETED'
            : active.agentId === 'verification-agent' ? 'VERIFICATION_COMPLETED'
            : active.agentId === 'report-generator' ? 'REPORT_GENERATED'
            : 'AGENT_COMPLETED';
          pipelineStreamEvents.push({
            id: `st-${Date.now()}-${art.id}-${active.agentId}-done`,
            artifactId: art.id,
            timestamp: timeStr,
            message: `${completionEventType}: ${active.agentName} on "${art.name}" — ${content.summary}${content.findings?.length ? ` Evidence items: ${content.findings.length}.` : ''}`,
            type: content.verdict === 'Malicious' ? 'alert'
              : content.verdict === 'Suspicious' ? 'warning'
              : content.verdict === 'Insufficient Evidence' || content.verdict === 'Not Applicable' ? 'info'
              : 'success',
            category: 'forensics',
            source: completionEventType
          });
          return { ...art, agentFindings: findings };
        }

        findings[activeIdx] = { ...active, stage: stageName, stepProgress: newStepProgress };
        pipelineAgentUpdates.set(active.agentId, {
          id: active.agentId,
          name: active.agentName,
          currentTask: `[${stageName}] ${art.name} (${newStepProgress}%)`,
          progress: newStepProgress,
          completedTask: false
        });
        return { ...art, agentFindings: findings };
      });

      if (artifactsChanged) {
        setArtifacts(() => nextArtifacts);
      }

      if (pipelineAgentUpdates.size > 0) {
        setAgents(prev => prev.map(a => {
          const pu = pipelineAgentUpdates.get(a.id);
          if (pu) {
            if (pu.completedTask) {
              return {
                ...a,
                progress: 100,
                status: 'IDLE' as const,
                currentTask: 'Idle',
                tasksCompleted: a.tasksCompleted + 1,
                lastActive: timeStr,
                lastLog: { timestamp: timeStr, action: 'Analysis complete.' },
                systemLogs: [
                  { id: `log-${Date.now()}-${a.id}`, timestamp: timeStr, level: 'EXEC' as const, message: 'Task completed — findings compiled.' },
                  ...(a.systemLogs || [])
                ].slice(0, 20)
              };
            }
            return {
              ...a,
              status: 'ANALYZING' as const,
              currentTask: pu.currentTask,
              progress: pu.progress,
              lastActive: timeStr,
              lastLog: { timestamp: timeStr, action: pu.currentTask },
              systemLogs: [
                { id: `log-${Date.now()}-${a.id}`, timestamp: timeStr, level: 'INFO' as const, message: pu.currentTask },
                ...(a.systemLogs || [])
              ].slice(0, 20)
            };
          }
          return a;
        }));
      }

      const allNewEvents = [...pipelineStreamEvents];
      if (allNewEvents.length > 0) {
        setStreamEvents(prev => [...allNewEvents, ...prev].slice(0, 200));
        const eventsByArtifact = new Map<string, StreamEvent[]>();
        pipelineStreamEvents.forEach((event) => {
          if (!event.artifactId) return;
          const existing = eventsByArtifact.get(event.artifactId) || [];
          existing.push(event);
          eventsByArtifact.set(event.artifactId, existing);
        });
        eventsByArtifact.forEach((events, artifactId) => {
          void secureFetchWithRecovery(`/api/investigations/${encodeURIComponent(artifactId)}/events`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(events.map((ev) => ({
              event_id: ev.id,
              investigation_id: artifactId,
              agent_id: ev.source,
              agent_name: ev.source,
              type: ev.source,
              status: 'ANALYZING',
              message: ev.message,
              timestamp: new Date().toISOString(),
            }))),
          }).catch(() => undefined);
        });
      }
       } finally {
         tickRunning = false;
       }
      })();
    }, 5000);

    return () => clearInterval(interval);
  }, []);


  // Global Keyboard Shortcuts (⌘K, Shift+V, Shift+C, Shift+N, Shift+L, Shift+E, Shift+P, Shift+D, Shift+X, ?, Esc)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore shortcut triggers if the user is typing inside an input or textarea
      const target = e.target as HTMLElement;
      const isInput = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable);

      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsSearchOpen(prev => !prev);
        return;
      }

      // If user presses Escape, dismiss any open modals
      if (e.key === 'Escape') {
        setIsSearchOpen(false);
        setIsCEOChatOpen(false);
        setIsEvidenceModalOpen(false);
        setIsProvidersModalOpen(false);
        setIsNewCaseModalOpen(false);
        setIsVoiceHUDOpen(false);
        setIsShortcutsModalOpen(false);
        setIsAgentsFleetModalOpen(false);
        setSelectedAgent(null);
        setSelectedCase(null);
        setSelectedIOC(null);
        return;
      }

      if (isInput) return;

      // Question mark (?) for Tactical Shortcuts Help
      if (e.key === '?' || (e.shiftKey && e.key === '/')) {
        e.preventDefault();
        setIsShortcutsModalOpen(prev => !prev);
        return;
      }

      // Shift key shortcuts
      if (e.shiftKey) {
        if (e.key === 'V' || e.key === 'v') {
          e.preventDefault();
          setIsVoiceHUDOpen(prev => !prev);
        } else if (e.key === 'C' || e.key === 'c') {
          e.preventDefault();
          setIsCEOChatOpen(prev => !prev);
        } else if (e.key === 'N' || e.key === 'n') {
          e.preventDefault();
          setIsNewCaseModalOpen(prev => !prev);
        } else if (e.key === 'L' || e.key === 'l') {
          e.preventDefault();
          toggleCustomizeMode();
        } else if (e.key === 'E' || e.key === 'e') {
          e.preventDefault();
          setIsEvidenceModalOpen(prev => !prev);
        } else if (e.key === 'P' || e.key === 'p') {
          e.preventDefault();
          setIsProvidersModalOpen(prev => !prev);
        } else if (e.key === 'D' || e.key === 'd') {
          e.preventDefault();
          handleToggleEmergencyOverride();
        } else if (e.key === 'X' || e.key === 'x') {
          e.preventDefault();
          handleExportLogs('json');
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [toggleCustomizeMode, isEmergencyActive]);

  const handleToggleEmergencyOverride = () => {
    if (isEmergencyActive) {
      setIsManualOverride(false);
      setThreatScore(prev => Math.min(prev, 65));
      const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      setStreamEvents(prev => [
        {
          id: `st-${Date.now()}`,
          timestamp: timeStr,
          message: `OPERATOR ACTION: Emergency Override manually DISENGAGED. Threat telemetry returned to baseline.`,
          type: 'info',
          category: 'system',
          source: 'OPERATOR'
        },
        ...prev
      ]);
    } else {
      setIsManualOverride(true);
      setThreatScore(prev => Math.max(prev, 96));
      const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      setStreamEvents(prev => [
        {
          id: `st-${Date.now()}`,
          timestamp: timeStr,
          message: `🚨 DEFCON 1 EMERGENCY OVERRIDE TRIGGERED: Full spectrum lockdown initialized across all SOC nodes.`,
          type: 'alert',
          category: 'threat',
          source: 'DEFCON-1'
        },
        ...prev
      ]);
    }
  };

  const handleDeployCountermeasures = () => {
    setIsManualOverride(false);
    setThreatScore(38);
    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setStreamEvents(prev => [
      {
        id: `st-${Date.now()}`,
        timestamp: timeStr,
        message: `🛡️ AUTOMATED COUNTERMEASURES EXECUTED: 8 Specialist Agents deployed synchronized containment routines. Threat suppressed (96% -> 38%).`,
        type: 'action',
        category: 'forensics',
        source: 'ARCHON & AGENTS'
      },
      ...prev
    ]);
  };

  const handleLockdownPorts = () => {
    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setStreamEvents(prev => [
      {
        id: `st-${Date.now()}`,
        timestamp: timeStr,
        message: `🔒 NETWORK BLACKOUT ENGAGED: Ingress/egress ports 443, 8080, 22, 3389 isolated. All C2 beacons blocked.`,
        type: 'alert',
        category: 'network',
        source: 'CIPHER-NET'
      },
      ...prev
    ]);
  };

  const handleRunAgentTask = (agentId: string, task: string) => {
    setAgents(prev => prev.map(a => {
      if (a.id === agentId) {
        return {
          ...a,
          currentTask: task,
          progress: Math.min(100, a.progress + 15),
          tasksCompleted: a.tasksCompleted + 1
        };
      }
      return a;
    }));
  };

  const handleOpenCaseById = (caseId: string) => {
    const found = cases.find(c => c.caseNumber === caseId) || cases[0];
    setSelectedCase(found);
  };

  const handleCreateCase = (newCase: CaseItem, assignedAgent: SpecialistAgent) => {
    if (operatorUser.role === 'Viewer') {
      setRbacNotice('RBAC Permission Denied: Role "Viewer" cannot create cases. Switch to Analyst or Admin.');
      setTimeout(() => setRbacNotice(null), 5000);
      return;
    }
    setCases(prev => [newCase, ...prev]);
    void syncInvestigationToFirestore({
      id: newCase.id,
      caseNumber: newCase.caseNumber,
      title: newCase.title,
      status: 'ANALYZING',
      severity: newCase.severity === 'CRITICAL' ? 'Critical' : newCase.severity === 'HIGH' ? 'High' : 'Medium',
      assignedAgent: assignedAgent.name,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }).catch(() => undefined);

    // Update assigned specialist agent task and execution log
    setAgents(prev => prev.map(a => {
      if (a.id === assignedAgent.id) {
        const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        return {
          ...a,
          currentTask: `Investigating ${newCase.caseNumber}: ${newCase.title.slice(0, 32)}...`,
          progress: 15,
          status: 'ANALYZING' as const,
          tasksCompleted: a.tasksCompleted + 1,
          lastActive: nowStr,
          lastLog: {
            timestamp: nowStr,
            action: `Dispatched to ${newCase.caseNumber} - ${newCase.title}`
          },
          systemLogs: [
            {
              id: `log-${Date.now()}`,
              timestamp: nowStr,
              level: 'EXEC' as const,
              message: `Auto-Assigned incident ${newCase.caseNumber} [${newCase.severity}] (${newCase.iocCount} IOCs)`
            },
            ...(a.systemLogs || [])
          ]
        };
      }
      return a;
    }));

    // Stream real-time dispatch event
    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setStreamEvents(prev => [
      {
        id: `st-${Date.now()}`,
        timestamp: timeStr,
        message: `🎯 AUTO-ASSIGN DISPATCH: ${newCase.caseNumber} ("${newCase.title}") allocated to ${assignedAgent.name} [Confidence: ${newCase.confidence}%]`,
        type: 'action',
        category: 'forensics',
        source: 'AI WORKLOAD ROUTER'
      },
      ...prev
    ]);
  };

  const handleReassignCaseAgent = (caseId: string, agentName: string) => {
    setCases(prev => prev.map(c => {
      if (c.caseNumber === caseId || c.id === caseId) {
        return { ...c, assignedAgent: agentName };
      }
      return c;
    }));

    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setStreamEvents(prev => [
      {
        id: `st-${Date.now()}`,
        timestamp: timeStr,
        message: `🔄 CASE REASSIGNED: ${caseId} transferred to specialist ${agentName}`,
        type: 'info',
        category: 'system',
        source: 'WORKLOAD ENGINE'
      },
      ...prev
    ]);
  };

  const handleUpdateCaseStatus = (caseId: string, newStatus: string) => {
    setCases(prev => prev.map(c => {
      if (c.caseNumber === caseId || c.id === caseId) {
        return { ...c, status: newStatus };
      }
      return c;
    }));
  };

  const handleAddArtifact = (newArtifact: EvidenceArtifact) => {
    // Build the full specialist roster this artifact will travel through —
    // starting with whichever agent it was assigned/auto-matched to, then
    // the rest of the fixed pipeline order — so every specialist works this
    // one file sequentially instead of just the single assigned agent.
    const pipeline = buildPipelineOrder(agents, newArtifact.assignedAgent);
    const agentFindings = initializeAgentFindings(pipeline);
    const firstAgent = pipeline[0];

    const enrichedArtifact: EvidenceArtifact = {
      ...newArtifact,
      status: 'Analyzing',
      verdict: 'Unknown',
      agentFindings,
    };
    setArtifacts(prev => [enrichedArtifact, ...prev]);

    // Reflect the upload as live agent activity immediately, so the
    // Investigation view shows real-time "who's working on what" the
    // moment evidence lands, without waiting for the next heartbeat tick.
    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    if (firstAgent) {
      setAgents(prev => prev.map(a => {
        if (a.id !== firstAgent.id) return a;
        return {
          ...a,
          status: 'ANALYZING' as const,
          currentTask: `Analyzing evidence: ${newArtifact.name}`,
          progress: Math.max(a.progress >= 100 ? 0 : a.progress, 8),
          lastActive: timeStr,
          lastLog: { timestamp: timeStr, action: `Started analysis on uploaded artifact "${newArtifact.name}"` },
          systemLogs: [
            {
              id: `log-${Date.now()}`,
              timestamp: timeStr,
              level: 'EXEC' as const,
              message: `Ingested evidence "${newArtifact.name}" (${newArtifact.type.toUpperCase()}) — beginning analysis.`
            },
            ...(a.systemLogs || [])
          ].slice(0, 20)
        };
      }));
    }

    const intakeEvents: StreamEvent[] = [
      {
        id: `st-${Date.now()}-3`,
        artifactId: newArtifact.id,
        timestamp: timeStr,
        message: `STATIC_ANALYSIS_COMPLETED: "${newArtifact.name}" (${newArtifact.type.toUpperCase()}) static triage dispatched across ${pipeline.length} specialist agents, starting with ${firstAgent?.name || 'ARCHON'}.`,
        type: 'action',
        category: 'forensics',
        source: 'STATIC_ANALYSIS_COMPLETED'
      },
      {
        id: `st-${Date.now()}-2`,
        artifactId: newArtifact.id,
        timestamp: timeStr,
        message: `HASH_COMPLETED: Computed cryptographic fingerprint SHA256=${newArtifact.sha256 || 'n/a'} for "${newArtifact.name}".`,
        type: 'info',
        category: 'forensics',
        source: 'HASH_COMPLETED'
      },
      {
        id: `st-${Date.now()}-1`,
        artifactId: newArtifact.id,
        timestamp: timeStr,
        message: `UPLOAD_STARTED: Received evidence artifact "${newArtifact.name}" (${newArtifact.size}).`,
        type: 'info',
        category: 'forensics',
        source: 'UPLOAD_STARTED'
      },
    ];

    setStreamEvents(prev => [...intakeEvents, ...prev]);

    void secureFetchWithRecovery(`/api/investigations/${encodeURIComponent(newArtifact.id)}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(intakeEvents.map((ev) => ({
        event_id: ev.id,
        investigation_id: newArtifact.id,
        agent_id: ev.source,
        agent_name: ev.source,
        type: ev.source,
        status: 'RECEIVED',
        message: ev.message,
        timestamp: new Date().toISOString(),
      }))),
    }).catch(() => undefined);
  };

  const handleDeleteArtifact = (artifactId: string) => {
    setArtifacts(prev => prev.filter(a => a.id !== artifactId));
  };

  const handleExportLogs = (format: 'json' | 'csv' = 'json') => {
    exportLogsToFile(
      streamEvents,
      {
        format,
        scope: 'all',
        filterName: 'All',
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
  };

  const handleSelectAgentByName = (rawName: string): boolean => {
    const clean = (rawName || '').toLowerCase().replace(/agent/g, '').trim();
    const found = agents.find(a => {
      const name = (a.name || '').toLowerCase();
      const role = (a.role || '').toLowerCase();
      const id = (a.id || '').toLowerCase();
      return (
        name.includes(clean) || 
        role.includes(clean) ||
        id.includes(clean) ||
        (clean.includes('malware') && role.includes('malware')) ||
        (clean.includes('ioc') && role.includes('ioc')) ||
        (clean.includes('threat') && role.includes('threat')) ||
        (clean.includes('network') && role.includes('network')) ||
        (clean.includes('code') && role.includes('code')) ||
        (clean.includes('report') && role.includes('report')) ||
        (clean.includes('memory') && role.includes('memory')) ||
        (clean.includes('verification') && role.includes('verification'))
      );
    });
    if (found) {
      setSelectedAgent(found);
      return true;
    }
    return false;
  };

  const handleSelectCaseByNumber = (caseNum: string): boolean => {
    const clean = (caseNum || '').toLowerCase().replace(/case|incident|#/g, '').trim();
    const found = cases.find(c => (c.caseNumber || '').toLowerCase().includes(clean) || (c.id || '').toLowerCase().includes(clean));
    if (found) {
      setSelectedCase(found);
      return true;
    }
    return false;
  };

  const handleAddStreamLog = (message: string, type: 'info' | 'alert' | 'action' | 'threat' = 'info') => {
    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setStreamEvents(prev => [
      {
        id: `st-${Date.now()}`,
        timestamp: timeStr,
        message,
        type,
        category: type === 'alert' ? 'threat' : type === 'action' ? 'forensics' : 'system',
        source: 'VOICE COMMAND'
      },
      ...prev
    ]);
  };

  // Web Speech API Voice Recognition Hook
  const voice = useVoiceRecognition({
    toggleEmergencyOverride: handleToggleEmergencyOverride,
    isEmergencyOverride: isEmergencyActive,
    deployCountermeasures: handleDeployCountermeasures,
    lockdownPorts: handleLockdownPorts,
    openNewCase: () => setIsNewCaseModalOpen(true),
    openCEOChat: (prompt) => {
      if (prompt) setCeoChatPrompt(prompt);
      setIsCEOChatOpen(true);
    },
    openEvidenceModal: () => openEvidenceModal(),
    openProvidersModal: () => setIsProvidersModalOpen(true),
    openSearch: (_initialQuery) => {
      setIsSearchOpen(true);
    },
    exportLogs: (format) => handleExportLogs(format || 'json'),
    toggleCustomizeMode: toggleCustomizeMode,
    resetLayout: resetLayout,
    selectAgentByName: handleSelectAgentByName,
    selectCaseByNumber: handleSelectCaseByNumber,
    setThreatThreshold: (val) => setThreatThreshold(val),
    addStreamLog: handleAddStreamLog
  });

  return (
    <div 
      id="app-root"
      data-theme={theme}
      className="relative flex h-screen w-screen overflow-hidden text-slate-100 font-sans transition-colors duration-500"
      style={{ backgroundColor: 'var(--color-bg-base)' }}
    >
      {/* Background Visual Layer */}
      <div className="absolute inset-0 cyber-grid opacity-75 pointer-events-none z-0" />
      
      {/* Emergency Mode Red Strobe Vignette */}
      {isEmergencyActive && (
        <div 
          id="emergency-vignette-layer"
          className="fixed inset-0 pointer-events-none z-20 emergency-vignette opacity-80 mix-blend-screen"
        />
      )}

      <div 
        className="absolute -top-32 -left-32 w-96 h-96 rounded-full blur-3xl pointer-events-none z-0 transition-all duration-700" 
        style={{
          backgroundColor: isEmergencyActive
            ? 'rgba(244, 63, 94, 0.25)'
            : theme === 'deep-emerald' 
            ? 'rgba(16, 185, 129, 0.12)' 
            : theme === 'crimson-alert' 
            ? 'rgba(244, 63, 94, 0.14)' 
            : 'rgba(147, 51, 234, 0.18)'
        }}
      />
      {/* Central Gothic Purple Atmospheric Ambient Pulse */}
      <div 
        className="absolute top-1/4 left-1/3 -translate-x-1/2 w-[600px] h-[600px] rounded-full blur-[140px] pointer-events-none z-0 transition-all duration-1000"
        style={{
          backgroundColor: isEmergencyActive
            ? 'rgba(225, 29, 72, 0.15)'
            : 'rgba(126, 34, 206, 0.12)'
        }}
      />
      <div 
        className="absolute -bottom-32 -right-32 w-96 h-96 rounded-full blur-3xl pointer-events-none z-0 transition-all duration-700" 
        style={{
          backgroundColor: isEmergencyActive
            ? 'rgba(225, 29, 72, 0.25)'
            : theme === 'deep-emerald' 
            ? 'rgba(6, 182, 212, 0.12)' 
            : theme === 'crimson-alert' 
            ? 'rgba(245, 158, 11, 0.12)' 
            : 'rgba(109, 40, 217, 0.16)'
        }}
      />

      {/* Global CRT Animated Scanline Overlay */}
      <div 
        id="global-crt-scanline-overlay"
        aria-hidden="true"
        className="fixed inset-0 pointer-events-none z-[1] scanline-overlay opacity-60 mix-blend-overlay"
      />

      {/* 1. Left Sidebar with Theme Switcher & Provider Hub Trigger */}
      <Sidebar 
        activeNav={activeNav}
        onSelectNav={(navId) => {
          if (navId === 'evidence') {
            openEvidenceModal();
          } else if (navId === 'provider-hub' || navId === 'model-routing') {
            setIsProvidersModalOpen(true);
          } else {
            setActiveNav(navId);
          }
        }}
        onOpenCEOChat={() => setIsCEOChatOpen(true)}
        onOpenVoiceCommand={() => setIsVoiceHUDOpen(true)}
        onOpenEvidenceModal={() => openEvidenceModal()}
        onOpenProvidersModal={() => setIsProvidersModalOpen(true)}
        onOpenAgentsFleet={() => setIsAgentsFleetModalOpen(true)}
        onOpenIOCExplorer={() => handleOpenSearchWithFilter('ioc')}
        evidenceCount={artifacts.length}
        currentTheme={theme}
        onSelectTheme={setTheme}
      />

      {/* 2. Main Application Frame */}
      <div className="relative z-10 flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Top Header Bar */}
        <TopBar 
          onOpenSearch={() => handleOpenSearchWithFilter('all')}
          onOpenCEOChat={() => setIsCEOChatOpen(true)}
          onOpenEvidenceUpload={() => openEvidenceModal()}
          onOpenProvidersModal={() => setIsProvidersModalOpen(true)}
          onOpenShortcutsModal={() => setIsShortcutsModalOpen(true)}
          onOpenNewCase={() => setIsNewCaseModalOpen(true)}
          onOpenVoiceCommand={() => setIsVoiceHUDOpen(true)}
          onOpenAgentsFleet={() => setIsAgentsFleetModalOpen(true)}
          onOpenSystemStatus={() => setIsAgentsFleetModalOpen(true)}
          isVoiceListening={voice.isListening}
          onToggleEmergencyOverride={handleToggleEmergencyOverride}
          onToggleCustomizeMode={toggleCustomizeMode}
          onOpenLayoutModal={openLayoutModal}
          isEmergencyOverride={isEmergencyActive}
          isCustomizeMode={isCustomizeMode}
          artifactsCount={artifacts.length}
          activeAgentsCount={agents.filter((a) => a.status !== 'OFFLINE' && a.status !== 'IDLE').length}
          totalAgentsCount={agents.length}
          threatLevel={threatLevelLabel}
          threatScore={threatScore}
          activeProvidersCount={providers.filter(p => p.enabled !== false).length}
        />

        {/* Production API / Database Error State Banner (Item 2: Never silently fall back to mock data) */}
        {apiUnavailableError && (
          <div
            role="alert"
            className="px-4 py-2.5 bg-rose-950/95 border-b border-rose-500/70 text-rose-200 flex items-center justify-between gap-3 text-xs font-mono z-20"
          >
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-rose-600 text-white font-bold uppercase">API / DB Unavailable</span>
              <span>{apiUnavailableError}</span>
            </div>
            <button
              type="button"
              onClick={() => void syncBackendInvestigationState()}
              className="px-3 py-1 rounded bg-rose-700 hover:bg-rose-600 text-white font-semibold border border-rose-400/40 cursor-pointer shrink-0"
            >
              Retry Connection
            </button>
          </div>
        )}

        {/* RBAC & Authenticated Operator Bar (Item 3: Server-Side & UI Role Enforcement) */}
        <div className="px-4 py-1.5 bg-slate-950/90 border-b border-purple-500/25 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono z-20">
          <div className="flex items-center gap-2 text-slate-300">
            <span className="text-purple-400 font-semibold">AUTH & RBAC ENFORCEMENT:</span>
            <span className="px-2 py-0.5 rounded bg-purple-950/80 border border-purple-500/40 text-cyan-300">
              {operatorUser.name} ({operatorUser.email})
            </span>
            <span className="px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-300 font-bold">
              ROLE: {operatorUser.role.toUpperCase()}
            </span>
            {rbacNotice && <span className="text-amber-300 ml-2">{rbacNotice}</span>}
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 mr-1">Switch Role:</span>
            {(['Admin', 'Analyst', 'Viewer'] as const).map((r) => (
              <button
                key={r}
                type="button"
                onClick={() => void handleSwitchOperatorRole(r)}
                className={`px-2 py-0.5 rounded border transition-all cursor-pointer ${
                  operatorUser.role === r
                    ? 'bg-purple-600 text-white border-purple-400 font-bold'
                    : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-slate-200'
                }`}
              >
                {r}
              </button>
            ))}
            <button
              type="button"
              onClick={() => void handleGoogleSignIn()}
              className="ml-2 px-2.5 py-0.5 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-200 cursor-pointer"
            >
              Google Sign-In
            </button>
          </div>
        </div>

        {/* Global Emergency Override DEFCON-1 Banner */}
        {isEmergencyActive && (
          <EmergencyBanner 
            threatScore={threatScore}
            threatThreshold={threatThreshold}
            onDeployCountermeasures={handleDeployCountermeasures}
            onLockdownPorts={handleLockdownPorts}
            onDisengageOverride={handleToggleEmergencyOverride}
          />
        )}

        {/* Dashboard Layout Customizer Active Sticky Banner */}
        {isCustomizeMode && (
          <CustomizeModeBanner 
            widgets={widgets}
            onOpenManagerModal={openLayoutModal}
            onResetLayout={resetLayout}
            onExitCustomize={() => setIsCustomizeMode(false)}
          />
        )}

        {/* Center + Right Intelligence Content Area */}
        <main className="flex-1 overflow-y-auto p-3 lg:p-4 space-y-dynamic">
          {activeNav === 'playground' ? (
            <PlaygroundPage providers={providers} ceo={ceo} onOpenProvidersModal={() => setIsProvidersModalOpen(true)} />
          ) : activeNav === 'battle-mode' ? (
            <BattleModePage providers={providers} />
          ) : activeNav === 'prompt-library' ? (
            <PromptLibraryPage />
          ) : activeNav === 'memory-center' ? (
            <MemoryCenterPage agents={agents} ceo={ceo} />
          ) : activeNav === 'tools-integrations' ? (
            <ToolsPage agents={agents} />
          ) : activeNav === 'investigation' ? (
            <InvestigationPage
              cases={cases}
              agents={agents}
              artifacts={artifacts}
              streamEvents={streamEvents}
              onOpenEvidenceModal={openEvidenceModal}
              onSelectCase={setSelectedCase}
              onSelectAgent={(a) => setSelectedAgent(a)}
              onNewCase={() => setIsNewCaseModalOpen(true)}
              onDeleteArtifact={handleDeleteArtifact}
            />
          ) : activeNav === 'cases' ? (
            <CasesPage cases={cases} onSelectCase={setSelectedCase} onNewCase={() => setIsNewCaseModalOpen(true)} />
          ) : activeNav === 'reports' ? (
            <ReportsPage cases={cases} onSelectCase={setSelectedCase} onExportLogs={() => handleExportLogs('json')} />
          ) : activeNav === 'timeline' ? (
            <TimelinePage activities={activities} streamEvents={streamEvents} />
          ) : activeNav === 'threat-intel' ? (
            <ThreatIntelPage iocs={iocs} activities={activities} />
          ) : activeNav === 'ioc-explorer' ? (
            <IOCExplorerPage iocs={iocs} onSelectIOC={setSelectedIOC} />
          ) : activeNav === 'mitre-browser' ? (
            <MitreBrowserPage />
          ) : activeNav === 'knowledge-graph' ? (
            <KnowledgeGraphPage cases={cases} iocs={iocs} />
          ) : activeNav === 'malware-intel' ? (
            <MalwareIntelligencePage />
          ) : activeNav === 'malware-learning' ? (
            <MalwareLearningPage />
          ) : activeNav === 'workflows' ? (
            <WorkflowsPage cases={cases} agents={agents} onOpenNewCase={() => setIsNewCaseModalOpen(true)} onSelectCase={setSelectedCase} />
          ) : activeNav === 'analytics' ? (
            <AnalyticsPage agents={agents} cases={cases} iocs={iocs} providers={providers} />
          ) : activeNav === 'system-monitor' ? (
            <SystemMonitorPage agents={agents} providers={providers} streamEvents={streamEvents} threatScore={threatScore} threatLevelLabel={threatLevelLabel} isEmergencyActive={isEmergencyActive} />
          ) : activeNav === 'settings' ? (
            <SettingsPage theme={theme} onSelectTheme={setTheme} threatThreshold={threatThreshold} onSetThreatThreshold={setThreatThreshold} isEmergencyActive={isEmergencyActive} onToggleEmergencyOverride={handleToggleEmergencyOverride} onResetLayout={resetLayout} onExportLogs={handleExportLogs} onOpenProvidersModal={() => setIsProvidersModalOpen(true)} onOpenAgentsFleet={() => setIsAgentsFleetModalOpen(true)} />
          ) : activeNav === 'billing' ? (
            <BillingPage onNavigate={setActiveNav} />
          ) : activeNav === 'billing-upgrade' ? (
            <UpgradePage onNavigate={setActiveNav} />
          ) : activeNav === 'billing-downgrade' ? (
            <DowngradePage onNavigate={setActiveNav} />
          ) : activeNav === 'billing-cancel' ? (
            <CancelSubscriptionPage onNavigate={setActiveNav} />
          ) : activeNav === 'payment-success' ? (
            <PaymentSuccessPage onNavigate={setActiveNav} />
          ) : activeNav === 'payment-failed' ? (
            <PaymentFailedPage onNavigate={setActiveNav} />
          ) : activeNav === 'payment-pending' ? (
            <PaymentPendingPage onNavigate={setActiveNav} />
          ) : activeNav === 'help-center' ? (
            <HelpCenterPageEmbedded />
          ) : activeNav === 'support' ? (
            <SupportPageEmbedded />
          ) : activeNav === 'ux-states' ? (
            <UXStatesShowcasePage />
          ) : (
          <div className="grid grid-cols-1 xl:grid-cols-12 grid-gap-dynamic items-start">
            {/* Center Main Operational Column */}
            {mainWidgets.length > 0 && (
              <div className={`${sidebarWidgets.length > 0 ? 'xl:col-span-9' : 'xl:col-span-12'} space-y-3`}>
                <div className="grid grid-cols-1 md:grid-cols-6 lg:grid-cols-12 gap-3 items-start">
                  {mainWidgets.map((config) => (
                    <WidgetRenderer 
                      key={config.id}
                      config={config}
                      isCustomizeMode={isCustomizeMode}
                      isDragging={draggedWidgetId === config.id}
                      isDragOver={dragOverWidgetId === config.id}
                      onDragStart={handleDragStart}
                      onDragEnd={handleDragEnd}
                      onDragOver={handleDragOver}
                      onDragLeave={handleDragLeave}
                      onDrop={handleDrop}
                      onToggleVisibility={toggleWidgetVisibility}
                      onMoveUp={(id) => moveWidget(id, 'up')}
                      onMoveDown={(id) => moveWidget(id, 'down')}
                      onSwitchSection={switchWidgetSection}
                      onChangeWidth={updateWidgetWidth}
                      ceo={ceo}
                      agents={agents}
                      mission={mission}
                      cases={cases}
                      iocs={iocs}
                      activities={activities}
                      providers={providers}
                      threatScore={threatScore}
                      threatLevelLabel={threatLevelLabel}
                      threatThreshold={threatThreshold}
                      isEmergencyActive={isEmergencyActive}
                      onOpenCEOChat={(prompt) => {
                        setCeoChatPrompt(prompt);
                        setIsCEOChatOpen(true);
                      }}
                      onSelectAgent={(a) => setSelectedAgent(a)}
                      onSelectCase={(c) => setSelectedCase(c)}
                      onSelectIOC={(i) => setSelectedIOC(i)}
                      onOpenCaseById={handleOpenCaseById}
                      onUpdateCaseStatus={handleUpdateCaseStatus}
                      onOpenEvidenceModal={() => openEvidenceModal()}
                      onOpenProvidersModal={() => setIsProvidersModalOpen(true)}
                      onToggleEmergencyOverride={handleToggleEmergencyOverride}
                      onSetThreatScore={(s) => setThreatScore(s)}
                      onSetThreatThreshold={(t) => setThreatThreshold(t)}
                      onDeployCountermeasures={handleDeployCountermeasures}
                      onOpenSearch={() => handleOpenSearchWithFilter('all')}
                      onOpenIOCExplorer={() => handleOpenSearchWithFilter('ioc')}
                      onOpenNewCase={() => setIsNewCaseModalOpen(true)}
                      onUpdateCeo={handleUpdateCeo}
                    />
                  ))}
                </div>
              </div>
            )}

            {/* Right-Side Persistent Intelligence Column */}
            {sidebarWidgets.length > 0 && (
              <div className={`${mainWidgets.length > 0 ? 'xl:col-span-3' : 'xl:col-span-12'} space-y-3`}>
                {sidebarWidgets.map((config) => (
                  <WidgetRenderer 
                    key={config.id}
                    config={config}
                    isCustomizeMode={isCustomizeMode}
                    isDragging={draggedWidgetId === config.id}
                    isDragOver={dragOverWidgetId === config.id}
                    onDragStart={handleDragStart}
                    onDragEnd={handleDragEnd}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                    onToggleVisibility={toggleWidgetVisibility}
                    onMoveUp={(id) => moveWidget(id, 'up')}
                    onMoveDown={(id) => moveWidget(id, 'down')}
                    onSwitchSection={switchWidgetSection}
                    onChangeWidth={updateWidgetWidth}
                    ceo={ceo}
                    agents={agents}
                    mission={mission}
                    cases={cases}
                    iocs={iocs}
                    activities={activities}
                    providers={providers}
                    threatScore={threatScore}
                    threatLevelLabel={threatLevelLabel}
                    threatThreshold={threatThreshold}
                    isEmergencyActive={isEmergencyActive}
                    onOpenCEOChat={(prompt) => {
                      setCeoChatPrompt(prompt);
                      setIsCEOChatOpen(true);
                    }}
                    onSelectAgent={(a) => setSelectedAgent(a)}
                    onSelectCase={(c) => setSelectedCase(c)}
                    onSelectIOC={(i) => setSelectedIOC(i)}
                    onOpenCaseById={handleOpenCaseById}
                    onUpdateCaseStatus={handleUpdateCaseStatus}
                    onOpenEvidenceModal={() => openEvidenceModal()}
                    onOpenProvidersModal={() => setIsProvidersModalOpen(true)}
                    onToggleEmergencyOverride={handleToggleEmergencyOverride}
                    onSetThreatScore={(s) => setThreatScore(s)}
                    onSetThreatThreshold={(t) => setThreatThreshold(t)}
                    onDeployCountermeasures={handleDeployCountermeasures}
                    onOpenSearch={() => handleOpenSearchWithFilter('all')}
                    onOpenIOCExplorer={() => handleOpenSearchWithFilter('ioc')}
                    onOpenNewCase={() => setIsNewCaseModalOpen(true)}
                    onUpdateCeo={handleUpdateCeo}
                  />
                ))}
              </div>
            )}
          </div>
          )}
        </main>

        {/* 3. Bottom Live Event Stream */}
        <EventStream 
          events={streamEvents} 
          agents={agents}
          cases={cases}
          threatScore={threatScore}
        />
      </div>

      {/* 4. Interactive Drawers & Dialog Modals */}
      <CEOChatDrawer 
        isOpen={isCEOChatOpen}
        onClose={() => {
          setIsCEOChatOpen(false);
          setCeoChatPrompt(undefined);
        }}
        ceo={ceo}
        initialPrompt={ceoChatPrompt}
        onOpenEvidenceModal={() => openEvidenceModal()}
        onAddArtifact={handleAddArtifact}
        agents={agents}
        onCreateCase={handleCreateCase}
      />

      <AgentDetailModal 
        agent={selectedAgent}
        onClose={() => setSelectedAgent(null)}
        onRunTask={handleRunAgentTask}
        providers={providers}
        onUpdateAgentModel={handleUpdateAgentModel}
      />

      <CaseDetailModal 
        caseData={selectedCase}
        onClose={() => setSelectedCase(null)}
        agents={agents}
        existingCases={cases}
        onReassignAgent={handleReassignCaseAgent}
        onUpdateStatus={handleUpdateCaseStatus}
      />

      <IOCDetailModal 
        ioc={selectedIOC}
        onClose={() => setSelectedIOC(null)}
      />

      <CommandPalette 
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        initialFilter={searchInitialFilter}
        agents={agents}
        cases={cases}
        iocs={iocs}
        artifacts={artifacts}
        ceo={ceo}
        providers={providers}
        onSelectAgent={(a) => setSelectedAgent(a)}
        onSelectCase={(c) => setSelectedCase(c)}
        onSelectIOC={(i) => setSelectedIOC(i)}
        onOpenCEOChat={(prompt) => {
          setCeoChatPrompt(prompt);
          setIsCEOChatOpen(true);
        }}
        onOpenNewCase={() => setIsNewCaseModalOpen(true)}
        onExportLogs={handleExportLogs}
        onOpenVoiceCommand={() => setIsVoiceHUDOpen(true)}
        onOpenEvidenceModal={() => openEvidenceModal()}
        onOpenProvidersModal={() => setIsProvidersModalOpen(true)}
        onToggleEmergencyOverride={handleToggleEmergencyOverride}
        onToggleCustomizeLayout={toggleCustomizeMode}
        onOpenLayoutModal={openLayoutModal}
      />

      {/* Voice Command Natural Language Operator HUD */}
      <VoiceCommandHUD
        voice={voice}
        isOpen={isVoiceHUDOpen}
        onClose={() => setIsVoiceHUDOpen(false)}
      />

      {/* Incident Intake & Auto-Assign Specialist Modal */}
      <NewCaseModal
        isOpen={isNewCaseModalOpen}
        onClose={() => setIsNewCaseModalOpen(false)}
        agents={agents}
        existingCases={cases}
        onCreateCase={handleCreateCase}
      />

      {/* Evidence & Forensic Artifact Upload Modal */}
      <EvidenceUploadModal
        isOpen={isEvidenceModalOpen}
        onClose={() => {
          setIsEvidenceModalOpen(false);
          setEvidenceModalCaseId('');
        }}
        artifacts={artifacts}
        agents={agents}
        currentCaseId={evidenceModalCaseId}
        onAddArtifact={handleAddArtifact}
        onDeleteArtifact={handleDeleteArtifact}
        onCreateCase={handleCreateCase}
      />

      {/* AI Provider & API Key Integration Hub Modal */}
      <AIProvidersModal
        isOpen={isProvidersModalOpen}
        onClose={() => setIsProvidersModalOpen(false)}
        providers={providers}
        onUpdateProviders={handleUpdateProviders}
        onSelectPrimaryModel={handleSelectPrimaryModel}
      />

      {/* Dashboard Layout & Widget Manager Modal */}
      <DashboardLayoutModal
        isOpen={isLayoutModalOpen}
        onClose={closeLayoutModal}
        widgets={widgets}
        onUpdateWidgets={setWidgets}
        onResetLayout={resetLayout}
        onApplyPreset={applyPreset}
      />

      {/* Tactical Operator Playbook & Keyboard Shortcuts Guide Modal */}
      <TacticalShortcutsModal
        isOpen={isShortcutsModalOpen}
        onClose={() => setIsShortcutsModalOpen(false)}
        onOpenVoiceCommand={() => setIsVoiceHUDOpen(true)}
        onOpenCEOChat={() => setIsCEOChatOpen(true)}
        onOpenNewCase={() => setIsNewCaseModalOpen(true)}
        onOpenEvidence={() => openEvidenceModal()}
        onOpenProviders={() => setIsProvidersModalOpen(true)}
        onToggleCustomize={toggleCustomizeMode}
        onToggleEmergency={handleToggleEmergencyOverride}
        onOpenSearch={() => setIsSearchOpen(true)}
        onExportLogs={() => handleExportLogs('json')}
      />

      {/* Autonomous Specialist Fleet & Live Health Matrix Modal */}
      <AgentsFleetModal
        isOpen={isAgentsFleetModalOpen}
        onClose={() => setIsAgentsFleetModalOpen(false)}
        agents={agents}
        onSelectAgent={(agent) => setSelectedAgent(agent)}
        onRunAgentTask={handleRunAgentTask}
        providers={providers}
        onUpdateAgentModel={handleUpdateAgentModel}
      />
    </div>
  );
}
