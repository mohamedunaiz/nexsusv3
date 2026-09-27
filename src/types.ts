export type ArtifactType = 'file' | 'image' | 'link' | 'pcap' | 'code' | 'log';

export type CanonicalVerdict =
  | 'malicious'
  | 'benign'
  | 'suspicious'
  | 'unknown'
  | 'analysis_unavailable';

export type EvidenceNature = 'OBSERVED' | 'INFERRED' | 'CONFIRMED' | 'UNAVAILABLE' | 'DIRECT' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNVERIFIED';

export type AgentProgressStage =
  | 'Queued'
  | 'Initializing'
  | 'Extracting features'
  | 'Analyzing'
  | 'Enriching'
  | 'Correlating'
  | 'Verifying'
  | 'Completed'
  | 'Failed';

/**
 * A single evidence-backed sub-finding: never a bare verdict. Every claim
 * an agent makes is traceable to its source, location, context, and confidence.
 */
export interface EvidenceFinding {
  claim: string;
  finding?: string;
  evidence: string;
  source: string;
  confidence: number; // 0-1
  artifact?: string;
  location?: string; // e.g. "offset 0x18A2 (line 14)"
  analysis_method?: string;
  timestamp?: string;
  limitation?: string;
  limitations?: string;
  evidenceType?: EvidenceNature;
  context?: string; // surrounding text snippet
  relatedArtifact?: string;
  externalEnrichment?: {
    tool: string;
    verdict: string;
    confidence: number;
    detail: string;
    latencyMs?: number;
    status: 'SUCCESS' | 'UNAVAILABLE' | 'FAILED' | 'NOT_CONFIGURED' | 'QUERY_FAILED' | 'NO_MALICIOUS_DETECTIONS';
  };
}

export interface AgentFinding {
  agentId: string;
  agentName: string;
  status: 'pending' | 'analyzing' | 'complete' | 'failed';
  stage?: AgentProgressStage;
  stepProgress: number;
  verdict?: 'Malicious' | 'Suspicious' | 'Safe' | 'Informational' | 'Insufficient Evidence' | 'Not Applicable' | 'Unavailable' | CanonicalVerdict;
  canonicalVerdict?: CanonicalVerdict;
  maliciousScore?: number;
  summary?: string;
  completedAt?: string;
  /** Evidence trail this verdict was derived from — claim + supporting evidence + provenance + confidence per item. */
  findings?: EvidenceFinding[];
  /** What's missing that would raise confidence, or what would change the verdict. */
  evidenceGaps?: string[];
  /** Fraction of expected evidence categories that were available to this agent. */
  evidenceCoverage?: number;
  /** Separate from maliciousScore: quality of the evidence supporting the finding. */
  evidenceQuality?: 'LOW' | 'MEDIUM' | 'HIGH';
  /** Explicit reason and evidence audit when an investigation domain is not applicable or unavailable */
  notApplicableReason?: {
    reason: string;
    evidenceAvailable: Record<string, string | number>;
  };
  familyCandidates?: MalwareFamilyCandidate[];
  recommendations?: string[];
  limitations?: string[];
  techniques?: string[];
  extractedIOCs?: ExtractedIOC[];
  structuredEvidence?: Record<string, any>;
}

export interface EvidenceArtifact {
  id: string;
  name: string;
  type: ArtifactType;
  size?: string;
  url?: string;
  thumbnailUrl?: string;
  mimeType?: string;
  sha256?: string;
  uploadedAt: string;
  uploadedBy: string;
  caseId?: string;
  assignedAgent?: string;
  status: 'Ingested' | 'Analyzing' | 'Parsed' | 'Flagged' | 'Clean';
  tags: string[];
  description?: string;
  extractedIOCsCount?: number;
  previewContent?: string;
  analysisContent?: string;
  /** Aggregate threat score across all specialists that scored this artifact (0-100). */
  maliciousScore?: number;
  /** Overall verdict once the full specialist pipeline has finished. */
  verdict?: 'Malicious' | 'Suspicious' | 'Safe' | 'Unknown';
  /** Per-specialist pipeline: every agent that has worked, is working, or will work this artifact. */
  agentFindings?: AgentFinding[];
  /**
   * Real result from the Malware Intelligence Engine (/api/malware-intel),
   * set when this artifact was a file/code upload that was actually run
   * through static feature extraction + rules + similarity + the trained
   * classifier. When present, the "malware-analysis" specialist's finding
   * is generated FROM this instead of the simulated random verdict — see
   * multiAgentAnalysis.ts. Absent for link/photo/paste-code artifacts, or
   * if the malware-intel service couldn't be reached at upload time.
   */
  malwareIntelSample?: MalwareSample | null;
  pcapAnalysis?: PcapAnalysis | null;
  /** Interactive multi-agent investigation evidence graph */
  evidenceGraph?: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  evidenceProvenance?: {
    totalSignals: number;
    activeSignals: string[];
    fusionWeights: Record<string, number>;
  };
}

export type AgentStatus = 'ACTIVE' | 'IDLE' | 'BUSY' | 'OFFLINE' | 'ANALYZING';

export interface AgentSystemLog {
  id: string;
  timestamp: string;
  level: 'INFO' | 'DEBUG' | 'WARN' | 'EXEC';
  message: string;
}

export interface SpecialistAgent {
  id: string;
  name: string;
  category: string;
  role: string;
  model: string;
  currentTask: string;
  progress: number;
  status: AgentStatus;
  iconName: string;
  tasksCompleted: number;
  successRate: number;
  avgTime: string;
  lastActive: string;
  lastLog?: {
    timestamp: string;
    action: string;
  };
  systemLogs?: AgentSystemLog[];
  systemPrompt?: string;
  specialization: string[];
}

export interface CEONode {
  name: string;
  callsign?: string;
  status?: AgentStatus;
  title?: string;
  tagline?: string;
  description?: string;
  mandate?: string;
  mandateQuote?: string;
  model: string;
  contextWindow: string;
  temperature: number;
  memory?: string;
  memoryMode?: string;
  avatarUrl?: string;
  activeDelegations?: number;
}

export interface MissionPhase {
  id: string;
  name: string;
  status: 'Completed' | 'In Progress' | 'Pending' | 'Failed';
  assignedAgent?: string;
  details?: string;
}

export interface MissionData {
  id: string;
  title: string;
  caseId: string;
  status?: 'Orchestrating' | 'In Progress' | 'Resolved' | 'Completed' | string;
  caseStatus?: 'Investigating' | 'In Progress' | 'Resolved' | 'Closed' | string;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  progress: number;
  startedAt: string;
  estimatedCompletion: string;
  delegatedBy: string;
  description: string;
  phases?: MissionPhase[];
  stages?: { id?: string; name: string; status: string; assignedAgent?: string; details?: string }[];
}

export interface ActivityEvent {
  id: string;
  timestamp: string;
  agent?: string;
  agentName?: string;
  agentType?: string;
  agentId?: string;
  action: string;
  type?: 'delegation' | 'ioc' | 'intel' | 'network' | 'report' | 'malware' | 'alert' | string;
  status?: string;
  target?: string;
  iconName?: string;
}

export type ActivityItem = ActivityEvent;

export interface IOCItem {
  id: string;
  value: string;
  type: 'IP' | 'Domain' | 'File Hash' | 'URL' | 'CVE' | string;
  severity: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown' | string;
  threatLevel?: string;
  confidence: number;
  firstSeen: string;
  source?: string;
  context?: string;
  threatActor?: string;
  asn?: string;
  country?: string;
  description?: string;
}

export interface CaseItem {
  id: string;
  caseNumber: string;
  title: string;
  status: 'In Progress' | 'Completed' | 'High' | 'Low' | 'Investigating' | string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  priority?: string;
  category?: string;
  timestamp?: string;
  createdAt?: string;
  assignedAgent: string;
  iocCount?: number;
  iocsCount?: number;
  confidence?: number;
  summary?: string;
  affectedSystems?: number;
  tags?: string[];
}

export interface AIProvider {
  id: string;
  name: string;
  company?: string;
  model?: string;
  availableModels?: string[];
  status?: 'Online' | 'Degraded' | 'Offline' | 'Connected' | 'Ready' | string;
  uptime?: string;
  latency?: string;
  successRate?: number;
  health?: number;
  apiKey?: string;
  isCustomKey?: boolean;
  baseUrl?: string;
  description?: string;
  category?: 'Commercial LLM' | 'Open Weights' | 'Specialized Reasoning' | 'Local / Self-Hosted' | 'Gateway / Router' | string;
  iconColor?: string;
  docsUrl?: string;
  rateLimit?: string;
  contextWindow?: string;
  enabled?: boolean;
  testedAt?: string;
  testStatus?: 'idle' | 'testing' | 'success' | 'failed';
  testMessage?: string;
}

export type ProviderNode = AIProvider;

export interface GraphNode {
  id: string;
  label: string;
  type: 'case' | 'malware' | 'ip' | 'domain' | 'actor' | 'cve' | 'campaign' | string;
  x?: number;
  y?: number;
  radius?: number;
  color?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  label?: string;
}

export interface ThreatMapPoint {
  id: string;
  lat: number;
  lng: number;
  city: string;
  country: string;
  threatType: string;
  intensity: number;
  targetCity: string;
  targetLat: number;
  targetLng: number;
}

export interface StreamEvent {
  id: string;
  artifactId?: string;
  time?: string;
  timestamp?: string;
  message: string;
  type?: 'info' | 'success' | 'warning' | 'alert' | 'delegate' | 'threat' | string;
  category?: 'threat' | 'delegation' | 'system' | 'general' | string;
  source?: string;
}

// ---------------------------------------------------------------------------
// Tool Integration (Tools & Integrations page)
// ---------------------------------------------------------------------------

export interface ToolCapability {
  id: string;
  label: string;
  description: string;
}

export interface ToolHealth {
  status: 'HEALTHY' | 'DEGRADED' | 'DISCONNECTED' | 'UNKNOWN';
  latencyMs: number | null;
  lastCheckedAt: string | null;
  lastError: string | null;
}

export interface ToolPlanLimit {
  requestsPerMinute: number;
  note: string;
}

export interface ToolDefinition {
  id: string;
  name: string;
  vendor: string;
  category: string;
  description: string;
  docsUrl: string;
  defaultBaseUrl: string;
  authType: string;
  capabilities: ToolCapability[];
  connected: boolean;
  enabled: boolean;
  baseUrl: string | null;
  planTier: 'free' | 'premium';
  planLimits: Record<'free' | 'premium', ToolPlanLimit>;
  enabledCapabilities: string[];
  allowedAgents: string[];
  health: ToolHealth;
  connectedBy: string | null;
  connectedAt: string | null;
}

export interface ToolExecutionLog {
  id: string;
  toolId: string;
  action: string;
  requestedBy: string;
  requestedByUserId: string | null;
  caseId: string | null;
  status: 'SUCCESS' | 'FAILED' | 'DENIED';
  latencyMs: number;
  verdict: string | null;
  error: string | null;
  createdAt: string;
}

export interface ToolExecutionResult {
  tool: string;
  action: string;
  success: boolean;
  indicator: { type: string; value: string };
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  confidence: number;
  findings: { source: string; label: string; detail?: string }[];
  references: string[];
  timestamp: string;
}

export type ThemeMode = 
  | 'cyber-purple' 
  | 'deep-emerald' 
  | 'crimson-alert' 
  | 'electric-cyan' 
  | 'amber-overdrive' 
  | 'tokyo-neon' 
  | 'stealth-monochrome';

// ---------------------------------------------------------------------------
// Malware Intelligence Engine — mirrors python-server/app/malware_intel/types.py
// ---------------------------------------------------------------------------

export type MalwareVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

export interface MalwarePeSection {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
}

export interface MalwareFamilyCandidate {
  family: string;
  confidence: number;
  supportingEvidence: string[];
}

export interface MalwareStaticFeatures {
  sha256: string;
  sha1: string;
  md5: string;
  sizeBytes: number;
  entropyOverall: number;
  fileFormat: 'pe' | 'elf' | 'unknown';
  peSections?: MalwarePeSection[] | null;
  peNumSections?: number | null;
  elfType?: string | null;
  elfMachine?: string | null;
  suspiciousStrings: string[];
  networkIndicatorStrings: string[];
  persistenceIndicatorStrings: string[];
  uniqueByteRatio: number;
  printableStringRatio: number;
  vector: number[];
  /** Real PE Import Address Table, walked from IMAGE_IMPORT_DESCRIPTOR — dll name -> imported function names. null if not a PE or the table couldn't be parsed. */
  peImportedDlls?: Record<string, string[]> | null;
  /** Subset of peImportedDlls actually on the suspicious-API watchlist — confirmed-import evidence, stronger than a string-scan hit. */
  peSuspiciousImportedApis?: string[];
  // Expanded PE/ELF Structural Features
  architecture?: string | null;
  subsystem?: string | null;
  entryPointRva?: number | null;
  imageBase?: number | null;
  rwxSections?: string[];
  sectionPermissions?: Record<string, { read: boolean; write: boolean; execute: boolean }>;
  sectionSizeAnomalies?: string[];
  virtualRawRatio?: number;
  importCount?: number;
  dllCount?: number;
  suspiciousApiCount?: number;
  ordinalImportCount?: number;
  exportCount?: number;
  tlsCallbacks?: boolean;
  debugDirectory?: boolean;
  resourceCount?: number;
  versionInfo?: Record<string, string>;
  digitalSignature?: { present: boolean; valid?: boolean; subject?: string; issuer?: string };
  overlaySize?: number;
  richHeader?: boolean;
  packerIndicators?: string[];
  timestampAnomalies?: string[];
  entropyAnalysis?: {
    overall: number;
    highEntropy: boolean;
    assessment: string;
  };
}

export interface MalwareRuleMatch {
  ruleId: string;
  ruleName: string;
  kind: 'hash' | 'string' | 'import_hit';
  family?: string | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
}

export interface MalwareSimilarityMatch {
  sampleId: string;
  name: string;
  family?: string | null;
  label?: 'malicious' | 'benign' | null;
  score: number;
  overallSimilarity?: number;
  contentSimilarity?: number;
  iocSimilarity?: number;
  networkSimilarity?: number;
  behaviorSimilarity?: number;
  structureSimilarity?: number;
  importSimilarity?: number;
  stringSimilarity?: number;
  sectionSimilarity?: number;
}

export interface MalwareVerdictResult {
  verdict: MalwareVerdict;
  confidence: number;
  staticConfidence: number;
  ruleConfidence: number;
  similarityConfidence: number;
  modelConfidence?: number | null;
  modelVersion?: string | null;
  observedCharacteristics: string[];
  suspiciousImports?: string[];
  ruleMatches: MalwareRuleMatch[];
  similarSamples: MalwareSimilarityMatch[];
  likelyFamily?: string | null;
  familyCandidates?: MalwareFamilyCandidate[];
  fusionWeights?: Record<string, number>;
  entropyAssessment?: string;
}

export interface MalwareSample {
  id: string;
  name: string;
  sha256: string;
  sha1: string;
  md5: string;
  sizeBytes: number;
  fileFormat: 'pe' | 'elf' | 'unknown';
  label?: 'malicious' | 'benign' | null;
  family?: string | null;
  verdict?: MalwareVerdict | null;
  confidence?: number | null;
  verdictDetail?: MalwareVerdictResult | null;
  features: MalwareStaticFeatures;
  uploadedBy: string;
  caseId?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface PcapAnalysis {
  format: 'pcap';
  linkType: number;
  packetCount: number;
  truncatedCount: number;
  protocols: Record<string, number>;
  endpoints: Record<string, number>;
  ports: Record<string, number>;
  dnsQueries: Record<string, number>;
  httpHosts: Record<string, number>;
  tlsSni: Record<string, number>;
  limitReached: boolean;
}

export interface MalwareRule {
  id: string;
  name: string;
  kind: 'hash' | 'string' | 'import_hit';
  pattern: string;
  family?: string | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source?: string | null;
  createdBy?: string | null;
  agentId: string;
  createdAt: string;
}

/** Agent ids that support user-added detection/matching rules. */
export const RULE_CAPABLE_AGENT_IDS = [
  'malware-analysis',
  'ioc-extraction',
  'code-review',
  'network-analysis',
  'threat-intel',
] as const;
export type RuleCapableAgentId = typeof RULE_CAPABLE_AGENT_IDS[number];

export interface MalwareReport {
  id: string;
  name: string;
  contentExcerpt: string;
  extractedIOCs: Record<string, string[]>;
  extractedFamilies: string[];
  uploadedBy: string;
  createdAt: string;
}

export interface MalwareIOC {
  id: string;
  type: string;
  value: string;
  family?: string | null;
  sourceReportId?: string | null;
  sourceSampleId?: string | null;
  createdAt: string;
}

export interface MalwareFamilySummary {
  family: string;
  sampleCount: number;
  iocCount: number;
}

export interface MalwareDataset {
  id: string;
  name: string;
  contentHash: string;
  datasetType: 'malware_training' | 'ioc_list' | 'threat_intel' | 'network' | 'other';
  numRows: number;
  numMalicious: number;
  numBenign: number;
  numReference: number;
  uploadedBy: string;
  createdAt: string;
}

export interface MalwareModelVersion {
  id: string;
  version: number;
  bias?: number;
  trainAccuracy: number;
  numSamples: number;
  numMalicious: number;
  numBenign: number;
  trainedBy: string;
  createdAt: string;
  // Multi-metric evaluation and dataset partitioning
  precision?: number;
  recall?: number;
  f1Score?: number;
  specificity?: number;
  falsePositiveRate?: number;
  falseNegativeRate?: number;
  rocAuc?: number;
  prAuc?: number;
  confusionMatrix?: { tp: number; fp: number; tn: number; fn: number };
  splits?: { train: number; validation: number; test: number };
  modelId?: string;
  featureSchemaVersion?: string;
  ruleSetVersion?: string;
  knowledgeBaseVersion?: string;
}

export interface MalwareIntelStats {
  samples: number;
  malicious: number;
  benign: number;
  families: number;
  datasets: number;
  datasetRows: number;
  reportsIngested: number;
  iocs: number;
  rules: number;
  modelVersion: number | null;
  modelTrainAccuracy: number | null;
  modelTrainingSamples: number;
  // Live metric tracking
  precision?: number | null;
  recall?: number | null;
  f1Score?: number | null;
  rocAuc?: number | null;
}

// ---------------------------------------------------------------------------
// Production Investigation Pipeline & Evidence Contracts
// ---------------------------------------------------------------------------

export type InvestigationStageStatus =
  | 'RECEIVED'
  | 'VALIDATING'
  | 'QUEUED'
  | 'ANALYZING'
  | 'CORRELATING'
  | 'VERIFYING'
  | 'COMPLETED'
  | 'FAILED';

export interface EvidencePackage {
  investigation_id: string;
  evidence_id: string;
  file: {
    name: string;
    sha256: string;
    mime_type: string;
    size: number;
  };
  available_artifacts: {
    strings: string[];
    pe_headers?: Record<string, any>;
    network_connections: string[];
    urls: string[];
    domains: string[];
    ips: string[];
    hashes: string[];
    registry: string[];
    processes: string[];
    files: string[];
  };
}

export interface StructuredFinding {
  finding: string;
  evidence: string;
  source: string;
  confidence: number;
  reasoning?: string;
  agent: string;
  timestamp: string;
  status: 'Needs verification' | 'Verified' | 'Contradicted' | 'Unverified';
  location?: string;
  context?: string;
  category?: string;
}

export interface CorrelatedFinding {
  id: string;
  indicatorOrClaim: string;
  type: string;
  confidence: number;
  evidenceChecklist: {
    label: string;
    checked: boolean;
    source: string;
  }[];
  status: 'HIGH' | 'MEDIUM' | 'LOW';
  contributingAgents: string[];
  timestamp: string;
}

export interface VerificationItem {
  claim: string;
  evidenceCheck: string;
  sourceCheck: string;
  agentAgreement: string;
  contradictionCheck: string;
  confidence: number;
  status: 'SUPPORTED' | 'CONTRADICTED' | 'INSUFFICIENT EVIDENCE' | 'UNAVAILABLE' | 'VERIFIED' | 'UNVERIFIED';
  evaluatedAt: string;
}

export interface InvestigationAuditLog {
  event_id: string;
  investigation_id: string;
  agent_id?: string;
  type: string;
  timestamp: string;
  status: 'success' | 'warning' | 'error' | 'info';
  message: string;
  metadata?: Record<string, any>;
}

export interface InvestigationReport {
  investigation_id: string;
  title: string;
  caseNumber: string;
  createdAt: string;
  completedAt?: string;
  executiveSummary: string;
  verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
  canonicalVerdict?: CanonicalVerdict;
  confidence: number;
  evidencePackage: EvidencePackage;
  categorizedIOCs: {
    hashes: ExtractedIOC[];
    network: ExtractedIOC[];
    files: ExtractedIOC[];
    malwareArtifacts: ExtractedIOC[];
  };
  specialistFindings: Record<string, any>;
  correlatedFindings: CorrelatedFinding[];
  verificationMatrix: VerificationItem[];
  mitreAttackTechniques: string[];
  evidenceGaps: string[];
  recommendations: string[];
  timeline: InvestigationAuditLog[];
  familyAttribution?: {
    family?: string;
    status: 'CONFIRMED' | 'SUSPECTED' | 'UNCONFIRMED' | 'UNKNOWN';
    rationale: string;
  };
  toolAttributions?: Array<{
    tool: string;
    action: string;
    verdict: string;
    latencyMs?: number;
    status: 'SUCCESS' | 'UNAVAILABLE' | 'FAILED';
  }>;
}
// --- Real IOC extraction (src/utils/iocExtraction.ts) ----------------------
// Every value here is pattern-matched out of actual artifact text (names,
// preview content, malware-intel string findings) — never randomly
// generated. See iocExtraction.ts for the detectors.
export type ExtractedIOCType =
  | 'sha256' | 'sha1' | 'md5' | 'sha512' | 'ssdeep' | 'tlsh' | 'file_hash'
  | 'ipv4' | 'ipv6' | 'domain' | 'fqdn' | 'url' | 'email' | 'port' | 'protocol' | 'dns_record' | 'c2_indicator' | 'c2_address'
  | 'btc_address' | 'monero_address'
  | 'windows_path' | 'linux_path' | 'filename' | 'extension'
  | 'registry_path' | 'registry_key' | 'mutex' | 'named_pipe' | 'scheduled_task' | 'service_name'
  | 'cert_fingerprint' | 'cert_info' | 'ja3' | 'ja3s' | 'user_agent' | 'asn'
  | 'pdb_path' | 'embedded_url' | 'embedded_domain' | 'campaign_id' | 'config_indicator' | 'encryption_key_artifact'
  | 'cmdline_indicator' | 'powershell_cmd' | 'shell_cmd' | 'encoded_string'
  | 'cve' | 'attack_technique' | 'attack_software' | 'attack_group';

export interface ExtractedIOC {
  type: ExtractedIOCType;
  value: string;
  normalizedValue?: string;
  source: string;
  location?: string;
  offset?: string;
  lineNumber?: number;
  context?: string;
  category?: 'hash' | 'network' | 'file' | 'malware_artifact' | 'threat_intel' | 'crypto';
  agent?: string;
  /** 0-1. Regex-shape confidence, not a threat-intel reputation score. */
  confidence: number;
  /** Semantic role inferred from surrounding context */
  role?: 'c2' | 'exfiltration' | 'download_staging' | 'payload_drop' | 'phishing' | 'persistence' | 'execution' | 'reconnaissance' | 'legitimate_ref' | 'informational';
  roleEvidence?: string;
  firstSeen?: string;
  lastSeen?: string;
  occurrences?: number;
  locations?: string[];
  externalEnrichment?: {
    tool: string;
    verdict: string;
    confidence: number;
    detail: string;
    status: 'SUCCESS' | 'UNAVAILABLE' | 'FAILED';
  };
}
