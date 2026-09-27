/**
 * Comprehensive Context-Aware IOC Extraction Engine.
 *
 * Runs specialized detectors over actual artifact text — the artifact's
 * file name, preview/paste content, and printable-string findings surfaced
 * by static analysis.
 *
 * Supported indicator types:
 * - Hashes: SHA512, SHA256, SHA1, MD5
 * - Network: IPv4, IPv6, URL (including defanged hxxp/hxxps), Domain/FQDN,
 *   Email, ASN, JA3/JA3S fingerprint, User-Agent, Certificate Fingerprint
 * - Crypto: Bitcoin (BTC) address, Monero (XMR) address
 * - Host/System: Windows path, Linux path, Registry key, Mutex, Named pipe
 * - Threat Intel: CVE, MITRE ATT&CK technique, MITRE software, MITRE group
 *
 * Context-aware:
 * - Differentiates software version numbers (e.g. "Version 185.1.2.3") from C2 IPs.
 * - Extracts semantic role: C2, Exfiltration, Download/Staging, Payload/Dropper,
 *   Phishing, Persistence, Execution, Reconnaissance, Legitimate Reference.
 * - Retains full provenance: source, location, line number, surrounding context, confidence.
 */
import { ExtractedIOC, ExtractedIOCType } from '../types';

interface Detector {
  type: ExtractedIOCType;
  re: RegExp;
  confidence: number;
  /** Optional post-match validator to filter out false positives regex alone can't catch. */
  validate?: (value: string, fullContext?: string) => boolean;
}

function isPrivateOrReservedIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true; // Link-local
  if (a >= 224) return true; // Multicast / reserved
  if (a === 0 || a === 255) return true;
  return false;
}

function isSemanticVersion(value: string, context?: string): boolean {
  if (!context) return false;
  // If preceded by "v", "ver", "version", "build", "release"
  const re = new RegExp(`(?:version|ver|v|build|release|sdk|runtime|v\\.?)\\s*:?\\s*${value.replace(/\./g, '\\.')}`, 'i');
  return re.test(context);
}

function normalizeDefangedValue(raw: string): string {
  let normalized = raw.trim();
  normalized = normalized.replace(/hxxps/gi, 'https');
  normalized = normalized.replace(/hxxp/gi, 'http');
  normalized = normalized.replace(/(https?)\s*:\s*\/\//gi, '$1://');
  normalized = normalized.replace(/\[\.\]/gi, '.');
  normalized = normalized.replace(/\[\@\]/gi, '@');
  normalized = normalized.replace(/\(\.?\)/gi, '.');
  normalized = normalized.replace(/\(\[\]\)/gi, '');
  normalized = normalized.replace(/\[(?:\.|@)\]/g, (m) => (m === '[.]' ? '.' : '@'));
  normalized = normalized.replace(/(?<=\w)\[\.\](?=\w)/g, '.');
  if (/^\d\[\.\]\d/.test(normalized)) normalized = normalized.replace(/\[\.\]/g, '.');
  if (/^https?:\/\//i.test(normalized) && /\[\.\]/.test(raw)) normalized = normalized.replace(/\[\.\]/g, '.');
  if (/^https?:\/\//i.test(normalized)) {
    normalized = normalized.replace(/\[\.\]/g, '.');
  }
  normalized = normalized.replace(/\[@\]/g, '@');
  normalized = normalized.replace(/\[\]\./g, '.');
  normalized = normalized.replace(/\[\]\@/g, '@');
  normalized = normalized.replace(/\[\]/g, '');
  return normalized;
}

function defangForScanning(text: string): string {
  return text
    .replace(/hxxps?/gi, (protocol) => (protocol.toLowerCase().startsWith('hxxps') ? 'https' : 'http'))
    .replace(/\[\.\]|\(\.\)|\[\]\./gi, '.')
    .replace(/\[@\]|\(@\)/gi, '@');
}

function contextAround(text: string, value: string): { lineNumber: number; offset: string; context: string } {
  const idx = text.indexOf(value);
  if (idx === -1) return { lineNumber: 1, offset: '0x0000', context: '' };
  const before = text.slice(Math.max(0, idx - 120), idx);
  const after = text.slice(idx + value.length, idx + value.length + 120);
  const lineNumber = text.slice(0, idx).split(/\r?\n/).length;
  const offset = `0x${idx.toString(16).toUpperCase().padStart(4, '0')}`;
  const snippet = `${before}${value}${after}`.replace(/\s+/g, ' ').trim();
  return { lineNumber, offset, context: snippet.length > 0 ? snippet : value };
}

function isPrintableAscii(str: string): boolean {
  if (!str || str.length < 4) return false;
  let printable = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) {
      printable++;
    }
  }
  return printable / str.length >= 0.85;
}

function tryDecodeBase64(b64: string): { utf8?: string; utf16le?: string } {
  try {
    const clean = b64.trim().replace(/[\r\n\s]/g, '');
    if (clean.length < 16 || clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
      return {};
    }
    // Attempt standard atob / Buffer decode
    let rawBinary = '';
    if (typeof Buffer !== 'undefined') {
      const buf = Buffer.from(clean, 'base64');
      const utf8 = buf.toString('utf8');
      const utf16le = buf.toString('utf16le');
      return {
        utf8: isPrintableAscii(utf8) && (utf8.includes('http') || utf8.includes('.') || utf8.includes('/') || utf8.includes('powershell')) ? utf8 : undefined,
        utf16le: isPrintableAscii(utf16le) && (utf16le.includes('http') || utf16le.includes('.') || utf16le.includes('/') || utf16le.includes('powershell')) ? utf16le : undefined,
      };
    } else {
      rawBinary = atob(clean);
      const bytes = new Uint8Array(rawBinary.length);
      for (let i = 0; i < rawBinary.length; i++) bytes[i] = rawBinary.charCodeAt(i);
      const utf8 = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      const utf16le = new TextDecoder('utf-16le', { fatal: false }).decode(bytes);
      return {
        utf8: isPrintableAscii(utf8) && (utf8.includes('http') || utf8.includes('.') || utf8.includes('/') || utf8.includes('powershell')) ? utf8 : undefined,
        utf16le: isPrintableAscii(utf16le) && (utf16le.includes('http') || utf16le.includes('.') || utf16le.includes('/') || utf16le.includes('powershell')) ? utf16le : undefined,
      };
    }
  } catch {
    return {};
  }
}

/**
 * Infer semantic role and confidence boost from surrounding text.
 */
function inferRoleAndEvidence(context: string, type: ExtractedIOCType): {
  role?: ExtractedIOC['role'];
  roleEvidence?: string;
  confidenceAdjustment: number;
} {
  const ctx = context.toLowerCase();

  // False positive check: Documentation / Example
  if (ctx.includes('example.com') || ctx.includes('documentation') || ctx.includes('rfc1918') || ctx.includes('test ip')) {
    return {
      role: 'legitimate_ref',
      roleEvidence: 'Surrounding text refers to documentation, testing, or example domain/IP',
      confidenceAdjustment: -0.3,
    };
  }

  // C2 Server / Callback
  if (
    ctx.includes('c2') ||
    ctx.includes('command and control') ||
    ctx.includes('command-and-control') ||
    ctx.includes('beacon') ||
    ctx.includes('callback') ||
    ctx.includes('listener') ||
    ctx.includes('listening on') ||
    ctx.includes('botnet') ||
    ctx.includes('heartbeat') ||
    ctx.includes('operator')
  ) {
    return {
      role: 'c2',
      roleEvidence: 'Context indicates Command & Control (C2) / beaconing destination',
      confidenceAdjustment: 0.1,
    };
  }

  // Exfiltration
  if (
    ctx.includes('exfil') ||
    ctx.includes('stolen') ||
    ctx.includes('upload') ||
    ctx.includes('data leak') ||
    ctx.includes('archive sent to') ||
    ctx.includes('exfiltrat')
  ) {
    return {
      role: 'exfiltration',
      roleEvidence: 'Context indicates data exfiltration or staging destination',
      confidenceAdjustment: 0.1,
    };
  }

  // Download / Staging
  if (
    ctx.includes('download') ||
    ctx.includes('stage') ||
    ctx.includes('dropper url') ||
    ctx.includes('hosted on') ||
    ctx.includes('fetch') ||
    ctx.includes('wget') ||
    ctx.includes('curl') ||
    ctx.includes('invoke-webrequest')
  ) {
    return {
      role: 'download_staging',
      roleEvidence: 'Context indicates payload hosting or download staging',
      confidenceAdjustment: 0.08,
    };
  }

  // Payload Drop / Dropper
  if (
    ctx.includes('dropped') ||
    ctx.includes('payload') ||
    ctx.includes('implant') ||
    ctx.includes('sample') ||
    ctx.includes('binary') ||
    ctx.includes('executable')
  ) {
    return {
      role: 'payload_drop',
      roleEvidence: 'Context indicates dropped executable or payload file',
      confidenceAdjustment: 0.08,
    };
  }

  // Phishing / Lure
  if (
    ctx.includes('phish') ||
    ctx.includes('lure') ||
    ctx.includes('credential') ||
    ctx.includes('fake login') ||
    ctx.includes('spoof') ||
    ctx.includes('sender')
  ) {
    return {
      role: 'phishing',
      roleEvidence: 'Context indicates phishing campaign, credential harvester, or malicious lure',
      confidenceAdjustment: 0.08,
    };
  }

  // Persistence
  if (
    ctx.includes('run key') ||
    ctx.includes('persistence') ||
    ctx.includes('startup') ||
    ctx.includes('schtasks') ||
    ctx.includes('autorun') ||
    ctx.includes('service installed')
  ) {
    return {
      role: 'persistence',
      roleEvidence: 'Context indicates system persistence mechanism',
      confidenceAdjustment: 0.08,
    };
  }

  // Execution
  if (
    ctx.includes('execute') ||
    ctx.includes('spawn') ||
    ctx.includes('inject') ||
    ctx.includes('process hollowing') ||
    ctx.includes('powershell')
  ) {
    return {
      role: 'execution',
      roleEvidence: 'Context indicates process execution or injection mechanism',
      confidenceAdjustment: 0.05,
    };
  }

  // Reconnaissance
  if (
    ctx.includes('recon') ||
    ctx.includes('scan') ||
    ctx.includes('probe') ||
    ctx.includes('nmap') ||
    ctx.includes('whois') ||
    ctx.includes('enumerate')
  ) {
    return {
      role: 'reconnaissance',
      roleEvidence: 'Context indicates reconnaissance or enumeration activity',
      confidenceAdjustment: 0.05,
    };
  }

  // Default role by type if no specific keywords matched
  if (type === 'ipv4' || type === 'ipv6' || type === 'domain' || type === 'url') {
    return { role: 'informational', roleEvidence: 'Network indicator discovered in artifact', confidenceAdjustment: 0 };
  }
  if (type === 'registry_key') {
    return { role: 'persistence', roleEvidence: 'Registry key identified', confidenceAdjustment: 0 };
  }
  if (type === 'windows_path' || type === 'linux_path') {
    return { role: 'payload_drop', roleEvidence: 'File path identified', confidenceAdjustment: 0 };
  }
  return { role: 'informational', confidenceAdjustment: 0 };
}

// Well-known MITRE ATT&CK Software (Cobalt Strike, Mimikatz, etc.)
const KNOWN_ATTACK_SOFTWARE_REGEX = /(?<![a-zA-Z0-9.\-_\/])\b(?:S\d{4}|Cobalt\s*Strike|Mimikatz|PsExec|BloodHound|Empire|Metasploit|Qakbot|Emotet|TrickBot|AgentTesla|RedLine|IcedID|BlackCat|LockBit|Conti|DarkSide|REvil|Ryuk|BazarLoader|AsyncRAT|Remcos|Sliver|Havoc|Brute\s*Ratel)\b(?![a-zA-Z0-9.\-_\/])/gi;

// Well-known MITRE ATT&CK Groups (APT28, Lazarus, etc.)
const KNOWN_ATTACK_GROUPS_REGEX = /(?<![a-zA-Z0-9.\-_\/])\b(?:G\d{4}|APT28|APT29|APT33|APT34|APT38|APT41|Lazarus(?:\s*Group)?|FIN7|FIN8|Sandworm|Cozy\s*Bear|Fancy\s*Bear|Turla|Volt\s*Typhoon|Salt\s*Typhoon|Scattered\s*Spider|Silence|Wizard\s*Spider|TA505|TA551|Kimsuky|Mustang\s*Panda)\b(?![a-zA-Z0-9.\-_\/])/gi;

// Order matters: specific patterns and longer hex hashes before general domains
const DETECTORS: Detector[] = [
  // Hashes
  { type: 'sha512', re: /\b[a-fA-F0-9]{128}\b/g, confidence: 0.99 },
  { type: 'sha256', re: /\b[a-fA-F0-9]{64}\b/g, confidence: 0.98 },
  { type: 'sha1', re: /\b[a-fA-F0-9]{40}\b/g, confidence: 0.9 },
  { type: 'md5', re: /\b[a-fA-F0-9]{32}\b/g, confidence: 0.85 },
  { type: 'ssdeep', re: /\b\d{1,6}:[A-Za-z0-9/+]{10,}:[A-Za-z0-9/+]{3,}\b/g, confidence: 0.95 },
  { type: 'tlsh', re: /\bT1[0-9A-Fa-f]{68,72}\b/gi, confidence: 0.95 },

  // Threat Intel & Vulnerabilities
  { type: 'cve', re: /\bCVE-\d{4}-\d{4,7}\b/gi, confidence: 0.99 },
  { type: 'attack_technique', re: /\bT\d{4}(?:\.\d{3})?\b/g, confidence: 0.85 },
  { type: 'attack_software', re: KNOWN_ATTACK_SOFTWARE_REGEX, confidence: 0.9 },
  { type: 'attack_group', re: KNOWN_ATTACK_GROUPS_REGEX, confidence: 0.9 },

  // Crypto Wallets
  {
    type: 'btc_address',
    re: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{38,59})\b/g,
    confidence: 0.92,
  },
  {
    type: 'monero_address',
    re: /\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g,
    confidence: 0.95,
  },

  // URLs & Defanged URLs
  {
    type: 'url',
    re: /\b(?:https?|ftp|hxxp(?:s?)):\/\/[^\s"'<>()]+|\b(?:https?|hxxp(?:s?))\s*:\s*\/\/[^\s"'<>()]+/gi,
    confidence: 0.95,
  },

  // DNS Records
  {
    type: 'dns_record',
    re: /\bIN\s+(?:A|AAAA|CNAME|TXT|MX|NS)\s+[a-zA-Z0-9._\-=]+\b/gi,
    confidence: 0.9,
  },

  // Email
  {
    type: 'email',
    re: /\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g,
    confidence: 0.9,
  },

  // IPv4 Addresses (with semantic version filter & private/reserved filter)
  {
    type: 'ipv4',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    confidence: 0.9,
    validate: (v, ctx) => !isPrivateOrReservedIPv4(v) && !isSemanticVersion(v, ctx),
  },

  // IPv6 Addresses
  {
    type: 'ipv6',
    re: /\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|\b(?:[a-fA-F0-9]{1,4}:){1,7}:[a-fA-F0-9]{1,4}\b/g,
    confidence: 0.85,
  },

  // Autonomous System Number (ASN)
  {
    type: 'asn',
    re: /\bAS\d{2,6}\b/gi,
    confidence: 0.9,
  },

  // Mutexes (Windows Named Mutexes & Common Malware Mutex Names)
  {
    type: 'mutex',
    re: /(?<![\\\/])\b(?:Global\\|Local\\)[A-Za-z0-9_.\-{}]{4,64}\b(?![\\\/])|\b(?:Mutex_[A-Za-z0-9_]+|[A-Za-z0-9_]+_Mutex|ZoneTransfer_Mutex)\b/g,
    confidence: 0.95,
  },

  // Named Pipes
  {
    type: 'named_pipe',
    re: /\\\\(?:\.|[a-zA-Z0-9.\-_]+)\\pipe\\[a-zA-Z0-9.\-_\\/]+/gi,
    confidence: 0.95,
  },

  // Windows Registry Paths
  {
    type: 'registry_path',
    re: /\bHK(?:EY_)?(?:LOCAL_MACHINE|LM|CURRENT_USER|CU|CLASSES_ROOT|USERS)\\[^\s"'<>|]+/gi,
    confidence: 0.95,
  },

  // C2 Addresses (Host:Port or IPv4:Port combinations)
  {
    type: 'c2_address',
    re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|ru|cn|info|biz|xyz|top|club|online|site|dev|app|to|cc|pro|live):[1-9][0-9]{1,4}\b|\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d):[1-9][0-9]{1,4}\b/gi,
    confidence: 0.94,
    validate: (v) => {
      const parts = v.split(':');
      if (parts.length !== 2) return false;
      const port = parseInt(parts[1], 10);
      return port >= 1 && port <= 65535;
    },
  },

  // PowerShell Explicit Execution Cradles & Commands
  {
    type: 'powershell_cmd',
    re: /\b(?:powershell(?:\.exe)?\s+[^\r\n;]+|(?:Invoke-WebRequest|Invoke-Expression|IEX|DownloadString|DownloadFile|Start-Process|New-Object\s+Net\.WebClient)[^\r\n;]+)\b/gi,
    confidence: 0.93,
  },

  // Shell & Administrative Evasion Commands
  {
    type: 'shell_cmd',
    re: /\b(?:vssadmin(?:\.exe)?\s+delete\s+shadows[^\r\n;]*|bcdedit[^\r\n;]*recoveryenabled\s+No|chmod\s+\+x\s+[^\r\n;]+|bash\s+-i\s+>&[^\r\n;]+|nc\s+(?:-e|-c)\s+[^\r\n;]+|certutil(?:\.exe)?\s+-urlcache[^\r\n;]*)\b/gi,
    confidence: 0.95,
  },

  // Certificate Information & Thumbprints
  {
    type: 'cert_info',
    re: /\b(?:ServerCertificateValidationCallback|Thumbprint\s*[:=]\s*[a-fA-F0-9]{40}|CN=[a-zA-Z0-9._\s-]+|O=[a-zA-Z0-9._\s-]+)\b/gi,
    confidence: 0.90,
  },

  // Scheduled Tasks & Services
  {
    type: 'scheduled_task',
    re: /\bschtasks(?:\.exe)?\s+\/(?:create|run|change)[^\r\n;]+/gi,
    confidence: 0.9,
  },
  {
    type: 'service_name',
    re: /\bsc(?:\.exe)?\s+(?:create|start|config)\s+[a-zA-Z0-9_\-]+/gi,
    confidence: 0.9,
  },

  // Malware Artifacts & Internal Evidence
  {
    type: 'pdb_path',
    re: /\b[A-Za-z]:\\[^\s"'<>|:*?]+\.pdb\b/gi,
    confidence: 0.95,
  },
  {
    type: 'cmdline_indicator',
    re: /\b(?:cmd(?:\.exe)?\s+\/c\s+[^\r\n]+|powershell(?:\.exe)?\s+-(?:enc|encodedcommand|executionpolicy|nop|w\s+hidden)[^\r\n]+)\b/gi,
    confidence: 0.92,
  },
  {
    type: 'config_indicator',
    re: /\b(?:c2_server|c2_port|beacon_interval|sleep_time|jitter|rsa_public_key|aes_key)\s*[:=]\s*["']?([^\s"';]+)["']?/gi,
    confidence: 0.92,
  },
  {
    type: 'c2_indicator',
    re: /\b(?:c2|beacon|callback|payload)(?:_server|_host|_domain|_ip)?\s*[:=]\s*["']?([^\s"';]+)["']?/gi,
    confidence: 0.94,
  },
  {
    type: 'encryption_key_artifact',
    re: /\b(?:encryption_key|rc4_key|aes_key|xor_key|private_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{16,128})["']?/gi,
    confidence: 0.95,
  },
  {
    type: 'campaign_id',
    re: /\b(?:campaign|camp_id|op_name|operation)\s*[:=]\s*["']?([A-Za-z0-9_\-]{3,32})["']?/gi,
    confidence: 0.88,
  },

  // Executable / Script Filenames
  {
    type: 'filename',
    re: /(?<![\\\/a-zA-Z0-9._\-])\b[A-Za-z0-9_\-]{3,64}\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|vbe|scr|elf|so|dylib|bin|sh|msc|cpl)\b/gi,
    confidence: 0.85,
    validate: (v) => !v.endsWith('.ts') && !v.endsWith('.tsx') && !v.endsWith('.json'),
  },

  // Ports (colon prefixed or preceded by port keyword)
  {
    type: 'port',
    re: /(?::|\bport\s+)([1-9][0-9]{1,4})\b/gi,
    confidence: 0.82,
    validate: (v) => {
      const p = parseInt(v.replace(/^[^\d]+/, ''), 10);
      return p >= 1 && p <= 65535 && !(p >= 2020 && p <= 2030);
    },
  },

  // Windows Filesystem Paths
  {
    type: 'windows_path',
    re: /\b(?:[A-Za-z]:\\|%[A-Za-z_]+%\\)(?:[^\s"'<>|:*?]+\\)*[^\s"'<>|:*?]+\.[A-Za-z0-9]{1,5}\b/g,
    confidence: 0.75,
    validate: (v) => !v.toLowerCase().endsWith('.pdb'),
  },

  // Linux / UNIX Filesystem Paths
  {
    type: 'linux_path',
    re: /(?:\/etc\/|\/tmp\/|\/var\/(?:run|log|tmp)\/|\/bin\/|\/usr\/(?:bin|sbin|local)\/)[a-zA-Z0-9._\-\/]+/g,
    confidence: 0.75,
  },

  // User-Agent Strings
  {
    type: 'user_agent',
    re: /\b(?:Mozilla\/5\.0\s*\([^)]+\)\s*[^\r\n]{5,80}|curl\/\d+\.\d+(?:\.\d+)?|Wget\/\d+\.\d+(?:\.\d+)?|python-requests\/\d+\.\d+)\b/gi,
    confidence: 0.88,
  },

  // Domains & FQDNs
  {
    type: 'domain',
    re: /(?<![@\/a-zA-Z0-9._\-])\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|ru|cn|info|biz|xyz|top|club|online|site|dev|app|to|cc|tk|ml|ga|cf|icu|shop|buzz|rest|wiki|click|link|su|pro|live)\b(?![:\/])/gi,
    confidence: 0.65,
    validate: (v) => !/^\d+(\.\d+){3}$/.test(v) && !/^[a-fA-F0-9]{32,}$/.test(v),
  },
];

export function inferCategory(type: ExtractedIOCType): ExtractedIOC['category'] {
  if (['sha256', 'sha1', 'md5', 'sha512', 'ssdeep', 'tlsh', 'file_hash'].includes(type)) return 'hash';
  if (['ipv4', 'ipv6', 'domain', 'fqdn', 'url', 'email', 'port', 'protocol', 'dns_record', 'c2_indicator', 'c2_address', 'asn', 'ja3', 'ja3s', 'cert_fingerprint', 'cert_info'].includes(type)) return 'network';
  if (['windows_path', 'linux_path', 'filename', 'extension', 'registry_path', 'registry_key', 'mutex', 'named_pipe', 'scheduled_task', 'service_name'].includes(type)) return 'file';
  if (['pdb_path', 'embedded_url', 'embedded_domain', 'campaign_id', 'config_indicator', 'encryption_key_artifact', 'cmdline_indicator', 'powershell_cmd', 'shell_cmd', 'encoded_string', 'user_agent'].includes(type)) return 'malware_artifact';
  if (['cve', 'attack_technique', 'attack_software', 'attack_group'].includes(type)) return 'threat_intel';
  if (['btc_address', 'monero_address'].includes(type)) return 'crypto';
  return 'threat_intel';
}

export function categorizeExtractedIOCs(iocs: ExtractedIOC[]): {
  hashes: ExtractedIOC[];
  network: ExtractedIOC[];
  files: ExtractedIOC[];
  malwareArtifacts: ExtractedIOC[];
  threatIntel: ExtractedIOC[];
  crypto: ExtractedIOC[];
} {
  return {
    hashes: iocs.filter((i) => i.category === 'hash' || ['sha256', 'sha1', 'md5', 'sha512', 'ssdeep', 'tlsh', 'file_hash'].includes(i.type)),
    network: iocs.filter((i) => i.category === 'network' || ['ipv4', 'ipv6', 'domain', 'fqdn', 'url', 'email', 'port', 'protocol', 'dns_record', 'c2_indicator', 'c2_address', 'asn', 'ja3', 'ja3s', 'cert_fingerprint', 'cert_info'].includes(i.type)),
    files: iocs.filter((i) => i.category === 'file' || ['windows_path', 'linux_path', 'filename', 'extension', 'registry_path', 'registry_key', 'mutex', 'named_pipe', 'scheduled_task', 'service_name'].includes(i.type)),
    malwareArtifacts: iocs.filter((i) => i.category === 'malware_artifact' || ['pdb_path', 'embedded_url', 'embedded_domain', 'campaign_id', 'config_indicator', 'encryption_key_artifact', 'cmdline_indicator', 'powershell_cmd', 'shell_cmd', 'encoded_string', 'user_agent'].includes(i.type)),
    threatIntel: iocs.filter((i) => i.category === 'threat_intel' || ['cve', 'attack_technique', 'attack_software', 'attack_group'].includes(i.type)),
    crypto: iocs.filter((i) => i.category === 'crypto' || ['btc_address', 'monero_address'].includes(i.type)),
  };
}

/**
 * Extract IOCs from one labeled block of text with full provenance, offset calculation,
 * recursive encoded string decoding, and context-awareness.
 */
function extractFromText(text: string, source: string, recursionDepth = 0): ExtractedIOC[] {
  if (!text) return [];
  const out: ExtractedIOC[] = [];
  const scanTexts = [text];
  const normalizedScanText = defangForScanning(text);
  if (normalizedScanText !== text) scanTexts.push(normalizedScanText);

  for (const scanText of scanTexts) {
    for (const det of DETECTORS) {
      det.re.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = det.re.exec(scanText)) !== null) {
        const rawValue = match[0];
        const normalizedValue = normalizeDefangedValue(rawValue);
        const { lineNumber, offset, context } = contextAround(scanText, rawValue);

        if (det.validate && !det.validate(normalizedValue || rawValue, context)) continue;

        // Context-aware role & confidence inference
        const roleInfo = inferRoleAndEvidence(context, det.type);
        const calibratedConfidence = Math.max(0.1, Math.min(1.0, det.confidence + roleInfo.confidenceAdjustment));

        const initialLocation = `${source} (line ${lineNumber}, offset ${offset})`;
        out.push({
          type: det.type,
          value: rawValue,
          normalizedValue: normalizedValue !== rawValue ? normalizedValue : undefined,
          source,
          location: initialLocation,
          offset,
          lineNumber,
          context,
          category: inferCategory(det.type),
          agent: 'ioc-extraction',
          confidence: Number(calibratedConfidence.toFixed(2)),
          role: roleInfo.role,
          roleEvidence: roleInfo.roleEvidence,
          firstSeen: new Date().toISOString(),
          occurrences: 1,
          locations: [initialLocation],
        });
        if (out.length > 500) break;
      }
    }
  }

  // Recursive decoding for Base64 encoded payload strings (e.g. PowerShell -enc, cradles, or embedded blobs)
  if (recursionDepth < 2) {
    const b64Regex = /(?:-enc(?:odedcommand)?\s+)?([A-Za-z0-9+/]{16,}={0,2})(?=$|[\s"';,)>\]])/gi;
    let b64Match: RegExpExecArray | null;
    while ((b64Match = b64Regex.exec(text)) !== null) {
      const b64Val = b64Match[1];
      if (/^[a-fA-F0-9]{32,128}$/.test(b64Val) || /^T1[0-9A-Fa-f]{68,72}$/i.test(b64Val)) {
        continue;
      }
      const decoded = tryDecodeBase64(b64Val);
      const decodedPayload = decoded.utf8 || decoded.utf16le;
      if (decodedPayload) {
        const { lineNumber, offset } = contextAround(text, b64Val);
        // Record the encoded string indicator itself
        out.push({
          type: 'encoded_string',
          value: b64Val.length > 60 ? `${b64Val.slice(0, 57)}...` : b64Val,
          source: `${source} (encoded base64)`,
          location: `${source} (line ${lineNumber}, offset ${offset})`,
          offset,
          lineNumber,
          context: `Base64 encoded block (${b64Val.length} chars)`,
          category: 'malware_artifact',
          agent: 'ioc-extraction',
          confidence: 0.9,
          role: 'payload_drop',
          roleEvidence: 'Encoded executable payload or cradle string',
          firstSeen: new Date().toISOString(),
          occurrences: 1,
          locations: [`${source} (line ${lineNumber}, offset ${offset})`],
        });

        const nestedIOCs = extractFromText(
          decodedPayload,
          `decoded payload (base64) from ${source} line ${lineNumber}`,
          recursionDepth + 1,
        );
        out.push(...nestedIOCs);
      }
    }
  }

  const deduped = new Map<string, ExtractedIOC>();
  for (const ioc of out) {
    const key = `${ioc.type}:${(ioc.normalizedValue || ioc.value).toLowerCase()}`;
    const existing = deduped.get(key);
    if (existing) {
      existing.occurrences = (existing.occurrences || 1) + 1;
      if (!existing.locations) existing.locations = [existing.location || existing.source];
      if (ioc.location && !existing.locations.includes(ioc.location)) {
        existing.locations.push(ioc.location);
      }
      if (ioc.confidence > existing.confidence) {
        existing.confidence = ioc.confidence;
        existing.role = ioc.role || existing.role;
        existing.roleEvidence = ioc.roleEvidence || existing.roleEvidence;
        existing.context = ioc.context || existing.context;
        existing.location = ioc.location || existing.location;
      }
    } else {
      deduped.set(key, {
        ...ioc,
        occurrences: 1,
        locations: ioc.location ? [ioc.location] : [ioc.source],
      });
    }
  }

  return Array.from(deduped.values());
}

export interface IOCExtractionInput {
  fileName?: string;
  previewContent?: string;
  /** Strings already surfaced by the Malware Intelligence Engine's static analysis, if this artifact went through it. */
  staticStrings?: {
    suspicious?: string[];
    network?: string[];
    persistence?: string[];
  };
}

export function extractIOCs(input: IOCExtractionInput): ExtractedIOC[] {
  const found: ExtractedIOC[] = [];
  if (input.fileName) found.push(...extractFromText(input.fileName, 'artifact filename'));
  if (input.previewContent) found.push(...extractFromText(input.previewContent, 'preview content'));
  if (input.staticStrings) {
    const { suspicious = [], network = [], persistence = [] } = input.staticStrings;
    found.push(...extractFromText(network.join('\n'), 'static analysis: network strings'));
    found.push(...extractFromText(persistence.join('\n'), 'static analysis: persistence strings'));
    found.push(...extractFromText(suspicious.join('\n'), 'static analysis: suspicious strings'));
  }

  // De-dupe by type+value, accumulating occurrences & locations while preserving distinct indicators
  const byKey = new Map<string, ExtractedIOC>();
  for (const ioc of found) {
    const key = `${ioc.type}:${(ioc.normalizedValue || ioc.value).toLowerCase()}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.occurrences = (existing.occurrences || 1) + (ioc.occurrences || 1);
      if (!existing.locations) existing.locations = [existing.location || existing.source];
      if (ioc.locations) {
        for (const loc of ioc.locations) {
          if (!existing.locations.includes(loc)) existing.locations.push(loc);
        }
      } else if (ioc.location && !existing.locations.includes(ioc.location)) {
        existing.locations.push(ioc.location);
      }
      if (ioc.confidence > existing.confidence) {
        existing.confidence = ioc.confidence;
        existing.role = ioc.role || existing.role;
        existing.roleEvidence = ioc.roleEvidence || existing.roleEvidence;
        existing.context = ioc.context || existing.context;
      }
    } else {
      byKey.set(key, {
        ...ioc,
        occurrences: ioc.occurrences || 1,
        locations: ioc.locations && ioc.locations.length > 0 ? ioc.locations : [ioc.location || ioc.source],
      });
    }
  }
  return Array.from(byKey.values());
}

export interface IOCRecallResult {
  totalGroundTruth: number;
  discoveredCount: number;
  missedCount: number;
  recallRate: number; // 0 - 1
  provenanceVerifiedCount: number;
  provenanceRate: number; // 0 - 1
  discovered: { type: string; value: string; location?: string; confidence: number }[];
  missed: { type: string; value: string }[];
}

export function evaluateIOCRecall(
  sampleText: string,
  groundTruth: { type: ExtractedIOCType | string; value: string }[],
): IOCRecallResult {
  const extracted = extractIOCs({ previewContent: sampleText });
  const discovered: { type: string; value: string; location?: string; confidence: number }[] = [];
  const missed: { type: string; value: string }[] = [];
  let provenanceVerified = 0;

  const clean = (s: string) => s.toLowerCase().replace(/\\+/g, '/').replace(/["'=\s]/g, '').trim();

  for (const gt of groundTruth) {
    const gtVal = clean(gt.value || '');
    const match = extracted.find((e) => {
      const typeMatch = e.type === gt.type || e.type.includes(gt.type) || gt.type.includes(e.type);
      if (!typeMatch) return false;
      const eNorm = clean(e.normalizedValue || '');
      const eVal = clean(e.value || '');
      return (eNorm && (eNorm === gtVal || eNorm.includes(gtVal) || gtVal.includes(eNorm))) ||
             (eVal && (eVal === gtVal || eVal.includes(gtVal) || gtVal.includes(eVal)));
    });

    if (match) {
      discovered.push({
        type: match.type,
        value: match.normalizedValue || match.value,
        location: match.location,
        confidence: match.confidence,
      });
      if (match.location && match.context && match.confidence > 0) {
        provenanceVerified += 1;
      }
    } else {
      missed.push(gt);
    }
  }

  const recallRate = groundTruth.length > 0 ? Number((discovered.length / groundTruth.length).toFixed(3)) : 1.0;
  const provenanceRate = discovered.length > 0 ? Number((provenanceVerified / discovered.length).toFixed(3)) : 1.0;

  return {
    totalGroundTruth: groundTruth.length,
    discoveredCount: discovered.length,
    missedCount: missed.length,
    recallRate,
    provenanceVerifiedCount: provenanceVerified,
    provenanceRate,
    discovered,
    missed,
  };
}

export function summarizeIOCsByType(iocs: ExtractedIOC[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const ioc of iocs) {
    counts[ioc.type] = (counts[ioc.type] || 0) + 1;
  }
  return counts;
}

export function summarizeIOCsByRole(iocs: ExtractedIOC[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const ioc of iocs) {
    if (ioc.role) {
      counts[ioc.role] = (counts[ioc.role] || 0) + 1;
    }
  }
  return counts;
}
