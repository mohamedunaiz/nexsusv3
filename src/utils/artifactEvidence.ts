import { EvidenceArtifact, EvidenceContext, MalwareStaticFeatures } from '../types';
import { extractIOCs } from './iocExtraction';
import { computeSha256Hex } from './binaryAnalysis';

export interface ArtifactEvidenceProfile {
  text: string;
  lineCount: number;
  hasExecutableContext: boolean;
  hasNetworkPrimitive: boolean;
  hasExecutionPrimitive: boolean;
  hasDownloadPrimitive: boolean;
  hasEncodedContent: boolean;
  hasPersistencePrimitive: boolean;
  hasInjectionPrimitive: boolean;
  hasAntiAnalysisPrimitive: boolean;
  networkChain: boolean;
  executionChain: boolean;
  injectionChain: boolean;
  attackTechniques: string[];
  // Structural PE/ELF information
  isPE: boolean;
  isELF: boolean;
  architecture: string;
  subsystem: string;
  rwxSections: string[];
  suspiciousApis: { api: string; category: 'injection' | 'anti_analysis' | 'persistence' | 'network' | 'credential_access' }[];
  packerIndicators: string[];
  entropy: number;
  entropyAssessment: string;
  digitalSignatureFound: boolean;
}

const NETWORK_PRIMITIVE_RE = /(?:socket\s*\(|\.connect\s*\(|\b(?:InternetConnect|HttpSendRequest|URLDownloadToFile|WSA(?:Startup|Send|Recv)|DnsQuery|getaddrinfo)\b|https?:\/\/|\b(?:TCPClient|WebClient)\b)/i;
const EXECUTION_PRIMITIVE_RE = /(?:\b(?:powershell|pwsh|cmd(?:\.exe)?|bash|sh)\b|\b(?:exec|eval|os\.system|subprocess\.(?:run|Popen|call))\s*\(|\b(?:WinExec|ShellExecute|CreateProcess)\b)/i;
const DOWNLOAD_PRIMITIVE_RE = /(?:\b(?:curl|wget|Invoke-(?:WebRequest|RestMethod)|URLDownloadToFile|WebClient)\b|https?:\/\/)/i;
const ENCODED_CONTENT_RE = /(?:-enc(?:odedcommand)?\b|(?:FromBase64String|base64\.(?:b64decode|decode)|atob)\s*\(|(?:[A-Za-z0-9+/]{40,}={0,2}))/i;
const PERSISTENCE_PRIMITIVE_RE = /(?:CurrentVersion\\Run|schtasks|StartupApproved|CreateService|reg\s+add|New-ItemProperty|Winlogon\\Shell)/i;
const INJECTION_PRIMITIVE_RE = /\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|QueueUserAPC|NtQueueApcThread|SetThreadContext|ProcessHollowing)\b/i;
const ANTI_ANALYSIS_PRIMITIVE_RE = /\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString|NtQueryInformationProcess|GetTickCount|SleepEx|rdtsc)\b/i;
const CODE_LIKE_RE = /(?:[{};]|=>|\b(?:function|class|import|def|const|let|var|select|where)\b|[#$]\w+)/i;

const PACKER_SIGNATURE_RE = /\b(?:UPX[0-2]?|\.aspack|\.themida|\.vmp[0-2]?|\.petite|\.packed|Armadillo|Enigma)\b/i;

const SUSPICIOUS_API_CATALOG: { name: string; category: 'injection' | 'anti_analysis' | 'persistence' | 'network' | 'credential_access' }[] = [
  { name: 'VirtualAlloc', category: 'injection' },
  { name: 'VirtualProtect', category: 'injection' },
  { name: 'WriteProcessMemory', category: 'injection' },
  { name: 'CreateRemoteThread', category: 'injection' },
  { name: 'NtUnmapViewOfSection', category: 'injection' },
  { name: 'QueueUserAPC', category: 'injection' },
  { name: 'IsDebuggerPresent', category: 'anti_analysis' },
  { name: 'CheckRemoteDebuggerPresent', category: 'anti_analysis' },
  { name: 'OutputDebugString', category: 'anti_analysis' },
  { name: 'RegSetValueEx', category: 'persistence' },
  { name: 'CreateService', category: 'persistence' },
  { name: 'InternetConnect', category: 'network' },
  { name: 'HttpSendRequest', category: 'network' },
  { name: 'URLDownloadToFile', category: 'network' },
  { name: 'WSAStartup', category: 'network' },
  { name: 'MiniDumpWriteDump', category: 'credential_access' },
  { name: 'LsaRetrievePrivateData', category: 'credential_access' },
  { name: 'LsaEnumerateLogonSessions', category: 'credential_access' },
];

function calculateApproxEntropy(text: string): number {
  if (!text || text.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let ent = 0;
  const len = text.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    ent -= p * Math.log2(p);
  }
  return Number(Math.min(8.0, ent).toFixed(2));
}

export function buildArtifactEvidenceProfile(artifact: EvidenceArtifact): ArtifactEvidenceProfile {
  const text = [artifact.analysisContent || artifact.previewContent, artifact.description, artifact.name].filter(Boolean).join('\n');
  const hasNetworkPrimitive = NETWORK_PRIMITIVE_RE.test(text);
  const hasExecutionPrimitive = EXECUTION_PRIMITIVE_RE.test(text);
  const hasDownloadPrimitive = DOWNLOAD_PRIMITIVE_RE.test(text);
  const hasEncodedContent = ENCODED_CONTENT_RE.test(text);
  const hasPersistencePrimitive = PERSISTENCE_PRIMITIVE_RE.test(text);
  const hasInjectionPrimitive = INJECTION_PRIMITIVE_RE.test(text);
  const hasAntiAnalysisPrimitive = ANTI_ANALYSIS_PRIMITIVE_RE.test(text);
  const hasExecutableContext = artifact.type === 'code' || artifact.type === 'file' || CODE_LIKE_RE.test(text);

  const attackTechniques: string[] = [];
  if (/\b(?:powershell|pwsh)\b/i.test(text)) attackTechniques.push('T1059.001 PowerShell');
  if (/\b(?:cmd(?:\.exe)?|bash|sh)\b|\b(?:exec|os\.system|subprocess\.(?:run|Popen|call))\s*\(/i.test(text)) attackTechniques.push('T1059 Command and Scripting Interpreter');
  if (hasDownloadPrimitive) attackTechniques.push('T1105 Ingress Tool Transfer');
  if (hasPersistencePrimitive) attackTechniques.push('T1547.001 Registry Run Keys / Startup Folder');
  if (hasEncodedContent) attackTechniques.push('T1027 Obfuscated/Compressed Files and Information');
  if (hasInjectionPrimitive) attackTechniques.push('T1055 Process Injection');
  if (hasAntiAnalysisPrimitive) attackTechniques.push('T1497 Virtualization/Sandbox Evasion');

  // Check PE/ELF indicators
  const isPE = artifact.name.toLowerCase().endsWith('.exe') || artifact.name.toLowerCase().endsWith('.dll') || artifact.malwareIntelSample?.fileFormat === 'pe' || text.includes('PE32') || text.includes('MZ');
  const isELF = artifact.name.toLowerCase().endsWith('.elf') || artifact.malwareIntelSample?.fileFormat === 'elf' || text.includes('\x7fELF');

  // Suspicious APIs identified in text or features
  const suspiciousApis: { api: string; category: 'injection' | 'anti_analysis' | 'persistence' | 'network' | 'credential_access' }[] = [];
  for (const item of SUSPICIOUS_API_CATALOG) {
    if (new RegExp(`\\b${item.name}\\b`, 'i').test(text)) {
      suspiciousApis.push({ api: item.name, category: item.category });
    }
  }

  // Packer indicators
  const packerIndicators: string[] = [];
  const packerMatches = text.match(PACKER_SIGNATURE_RE);
  if (packerMatches) {
    packerIndicators.push(...new Set(packerMatches.map((m) => m.toUpperCase())));
  }

  // RWX Sections check
  const rwxSections: string[] = [];
  if (artifact.malwareIntelSample?.features?.rwxSections) {
    rwxSections.push(...artifact.malwareIntelSample.features.rwxSections);
  } else if (/section\s+.*(?:rwx|read\s*write\s*execute)/i.test(text)) {
    rwxSections.push('.text (RWX)');
  }

  // Entropy calculation and crucial calibration:
  // "High entropy != malware" - report accurately that high entropy is consistent with packing/compression
  const entropy = artifact.malwareIntelSample?.features?.entropyOverall ?? calculateApproxEntropy(text);
  const isHighEntropy = entropy >= 7.0;
  const entropyAssessment = isHighEntropy
    ? 'High entropy detected; this is consistent with packing or encryption, but is not independently sufficient to classify the sample as malicious.'
    : entropy >= 6.0
    ? 'Moderate entropy observed; consistent with structured code, compressed assets, or compiled binaries.'
    : 'Normal/low entropy observed; consistent with uncompressed plain-text or standard resource data.';

  return {
    text,
    lineCount: text ? text.split(/\r?\n/).length : 0,
    hasExecutableContext,
    hasNetworkPrimitive,
    hasExecutionPrimitive,
    hasDownloadPrimitive,
    hasEncodedContent,
    hasPersistencePrimitive,
    hasInjectionPrimitive,
    hasAntiAnalysisPrimitive,
    networkChain: hasNetworkPrimitive && (hasDownloadPrimitive || hasExecutionPrimitive),
    executionChain: hasExecutionPrimitive && (hasEncodedContent || hasDownloadPrimitive || hasPersistencePrimitive),
    injectionChain: hasInjectionPrimitive && (hasExecutionPrimitive || hasEncodedContent),
    attackTechniques: [...new Set(attackTechniques)],
    isPE,
    isELF,
    architecture: isPE ? (text.includes('PE32+') || text.includes('x64') ? 'PE32+ (x86-64)' : 'PE32 (x86-32)') : isELF ? 'ELF 64-bit' : 'Unknown / Script',
    subsystem: isPE ? (text.includes('GUI') ? 'Windows GUI' : 'Windows CUI / Console') : 'POSIX / Script',
    rwxSections,
    suspiciousApis,
    packerIndicators,
    entropy,
    entropyAssessment,
    digitalSignatureFound: /authenticode|digital signature|signed by/i.test(text),
  };
}

export function evidenceContext(profile: ArtifactEvidenceProfile): string {
  const relationships: string[] = [];
  if (profile.injectionChain) relationships.push('process injection APIs correlate with execution or encoded payload delivery');
  if (profile.networkChain) relationships.push('network primitive is associated with download or execution behavior');
  if (profile.executionChain) relationships.push('execution primitive is associated with encoding, download, or persistence behavior');
  if (profile.rwxSections.length > 0) relationships.push(`anomalous memory permissions detected (${profile.rwxSections.join(', ')})`);
  if (relationships.length) return relationships.join('; ');
  if (profile.hasNetworkPrimitive) return profile.hasExecutableContext ? 'network primitive present without a corroborating behavior chain' : 'network-related text without executable context';
  return 'no correlated network or execution behavior identified';
}

/**
 * Phase 1 — Step 1: Create one normalized EvidenceContext object that all agents consume.
 */
export function buildEvidenceContext(artifact: EvidenceArtifact): EvidenceContext {
  if (artifact.evidenceContext) {
    return artifact.evidenceContext;
  }

  const sample = artifact.malwareIntelSample;
  const features: any = sample?.features || {};
  const rawText = [
    artifact.analysisContent || artifact.previewContent || '',
    artifact.description || '',
  ]
    .filter(Boolean)
    .join('\n');

  const profile = buildArtifactEvidenceProfile(artifact);
  const iocs = extractIOCs({
    fileName: artifact.name,
    previewContent: rawText,
    staticStrings: sample?.features
      ? {
          suspicious: sample.features.suspiciousStrings,
          network: sample.features.networkIndicatorStrings,
          persistence: sample.features.persistenceIndicatorStrings,
        }
      : undefined,
  });

  const sha256 =
    artifact.sha256 ||
    sample?.sha256 ||
    iocs.find((i) => i.type === 'sha256')?.value ||
    computeSha256Hex(rawText || artifact.name);
  const md5 = sample?.md5 || iocs.find((i) => i.type === 'md5')?.value;
  const sha1 = sample?.sha1 || iocs.find((i) => i.type === 'sha1')?.value;

  const stringsList = Array.from(
    new Set([
      ...(features.suspiciousStrings || []),
      ...(features.networkIndicatorStrings || []),
      ...(features.persistenceIndicatorStrings || []),
      ...(rawText
        ? rawText
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter((l) => l.length >= 4)
            .slice(0, 100)
        : []),
    ]),
  );

  const urls = iocs.filter((i) => ['url', 'embedded_url'].includes(i.type)).map((i) => i.normalizedValue || i.value);
  const domains = iocs.filter((i) => ['domain', 'fqdn', 'embedded_domain'].includes(i.type)).map((i) => i.normalizedValue || i.value);
  const ips = iocs.filter((i) => ['ipv4', 'ipv6'].includes(i.type)).map((i) => i.normalizedValue || i.value);
  const filePaths = iocs
    .filter((i) => ['windows_path', 'linux_path', 'filename', 'pdb_path'].includes(i.type))
    .map((i) => i.normalizedValue || i.value);
  const registryKeys = iocs
    .filter((i) => ['registry_path', 'registry_key'].includes(i.type))
    .map((i) => i.normalizedValue || i.value);

  const imports = Array.from(
    new Set([
      ...(features.peSuspiciousImportedApis || []),
      ...(features.importedApis || []),
      ...profile.suspiciousApis.map((a) => a.api),
    ]),
  );

  const sections = (features.sections || features.peSections || []).map((s: any) => ({
    name: s.name || '.text',
    virtualSize: s.virtualSize ?? s.size ?? 0,
    virtualAddress: s.virtualAddress ?? 0,
    rawSize: s.rawSize ?? s.size ?? 0,
    rawAddress: s.rawAddress ?? 0,
    entropy: s.entropy ?? profile.entropy,
    rwx: Boolean(s.rwx || (features.rwxSections || []).includes(s.name)),
    characteristics: s.characteristics ?? 0,
  }));

  return {
    fileId: artifact.id,
    fileName: artifact.name,
    fileType: sample?.fileFormat || artifact.type,
    size: sample?.sizeBytes || (artifact.size ? parseInt(artifact.size, 10) || rawText.length : rawText.length),
    hashes: {
      md5,
      sha1,
      sha256,
    },
    strings: stringsList,
    urls,
    domains,
    ips,
    filePaths,
    registryKeys,
    pe: profile.isPE
      ? {
          isPE: true,
          machine: features.peHeaders?.machine || profile.architecture,
          subsystem: features.peHeaders?.subsystem || profile.subsystem,
          is64Bit: Boolean(features.peHeaders?.is64Bit ?? profile.architecture.includes('64')),
          entryPointRva: features.peHeaders?.entryPointRva ?? 0x1000,
          imageBase: features.peHeaders?.imageBase ?? '0x140000000',
          sectionCount: sections.length || 1,
          timeDateStamp: features.peHeaders?.timeDateStamp ?? 0,
          importedDlls: features.peImportedDlls || [],
          suspiciousApis: imports,
          rwxSections: profile.rwxSections,
        }
      : undefined,
    elf: profile.isELF
      ? {
          isELF: true,
          class: '64-bit',
          endianness: 'little',
          machine: features.elfHeaders?.machine || 'x86-64',
          type: features.elfHeaders?.type || 'EXEC',
        }
      : undefined,
    imports,
    exports: features.exports || (rawText.toLowerCase().includes('reflectiveloader') ? ['ReflectiveLoader'] : []),
    entropy: profile.entropy,
    sections,
    extractedArtifacts: iocs.map((ioc) => ({
      type: ioc.type,
      value: ioc.value,
      normalizedValue: ioc.normalizedValue,
      source: ioc.source,
      location: ioc.location || `offset ${ioc.offset || '0x0000'}`,
      occurrences: ioc.occurrences || 1,
      locations: ioc.locations || [ioc.location || ioc.source],
      context: ioc.context,
      confidence: ioc.confidence,
    })),
    sourceMetadata: {
      uploadedAt: artifact.uploadedAt,
      uploadedBy: artifact.uploadedBy,
      mimeType: artifact.mimeType || 'application/octet-stream',
      caseId: artifact.caseId,
      attackTechniques: profile.attackTechniques,
      packerIndicators: profile.packerIndicators,
      digitalSignatureFound: profile.digitalSignatureFound,
    },
  };
}

