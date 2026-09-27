import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'crypto';
import fs from 'fs';
import { AddressInfo } from 'net';
import { Server } from 'http';
import { app, getPersistedSamples, getPersistedAnalyses, getPersistedFindings, getPersistedEvidence } from '../server';
import { analyzeUploadedBytes } from '../src/utils/binaryAnalysis';
import { generateFinding } from '../src/utils/multiAgentAnalysis';
import { EvidenceArtifact } from '../src/types';

let server: Server;
let baseUrl = '';

beforeAll(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    if (server) server.close(() => resolve());
    else resolve();
  });
});

/**
 * Helper to construct a realistic synthetic PE32+ (64-bit) binary in memory
 * containing a valid MZ header, PE\0\0 signature, COFF header, Optional header,
 * section table (.text, .rdata), imported DLLs/APIs, and embedded C2/IOC strings.
 */
function buildSyntheticPEBuffer(): Buffer {
  const buf = Buffer.alloc(2048, 0);
  // MZ magic
  buf.write('MZ', 0, 'ascii');
  // e_lfanew at 0x3c -> 0x80
  buf.writeUInt32LE(0x80, 0x3c);
  // PE\0\0 signature at 0x80
  buf.write('PE\0\0', 0x80, 'ascii');
  // COFF File Header at 0x84
  buf.writeUInt16LE(0x8664, 0x84); // Machine: x86_64
  buf.writeUInt16LE(2, 0x86); // NumberOfSections: 2
  buf.writeUInt32LE(1711500000 + Math.floor(Math.random() * 10000), 0x88); // TimeDateStamp
  buf.writeUInt16LE(0xf0, 0x94); // SizeOfOptionalHeader (240 bytes for PE32+)
  buf.writeUInt16LE(0x0022, 0x96); // Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)

  // Optional Header at 0x98
  buf.writeUInt16LE(0x20b, 0x98); // Magic: PE32+ (64-bit)
  buf.writeUInt32LE(0x1000, 0x98 + 16); // AddressOfEntryPoint: 0x1000
  buf.writeUInt16LE(3, 0x98 + 68); // Subsystem: WINDOWS_CUI

  // Section 1 (.text) at 0x98 + 0xf0 = 0x188
  const sec1 = 0x188;
  buf.write('.text\0\0\0', sec1, 'ascii');
  buf.writeUInt32LE(0x400, sec1 + 8); // VirtualSize
  buf.writeUInt32LE(0x1000, sec1 + 12); // VirtualAddress
  buf.writeUInt32LE(0x400, sec1 + 16); // SizeOfRawData
  buf.writeUInt32LE(0x200, sec1 + 20); // PointerToRawData
  buf.writeUInt32LE(0x60000020, sec1 + 36); // Characteristics (MEM_EXECUTE | MEM_READ)

  // Section 2 (.rdata) at 0x188 + 40 = 0x1b0
  const sec2 = 0x1b0;
  buf.write('.rdata\0\0', sec2, 'ascii');
  buf.writeUInt32LE(0x400, sec2 + 8); // VirtualSize
  buf.writeUInt32LE(0x2000, sec2 + 12); // VirtualAddress
  buf.writeUInt32LE(0x400, sec2 + 16); // SizeOfRawData
  buf.writeUInt32LE(0x600, sec2 + 20); // PointerToRawData
  buf.writeUInt32LE(0x40000040, sec2 + 36); // Characteristics (MEM_READ)

  // Write imported DLLs, APIs, and IOC strings at offset 0x620 inside .rdata
  const payloadStrings = [
    'KERNEL32.dll',
    'WININET.dll',
    'VirtualAllocEx',
    'WriteProcessMemory',
    'CreateRemoteThread',
    'InternetOpenA',
    'http://c2.darkfleet-soc.io/stage2/beacon.bin',
    '185.220.101.44',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BeaconPersist',
    'Global\\CobaltStrike_Mutex_99',
  ].join('\0');

  buf.write(payloadStrings, 0x620, 'utf8');
  return buf;
}

describe('End-to-End Malware Investigation Pipeline Audit (Requirements 1-9)', () => {
  it('1 & 2. Analyzes actual uploaded PE bytes end-to-end and persists Sample -> Analysis -> Findings -> Evidence to disk', async () => {
    const peBuffer = buildSyntheticPEBuffer();
    const expectedSha256 = crypto.createHash('sha256').update(peBuffer).digest('hex');

    // Direct byte-level verification
    const byteAnalysis = analyzeUploadedBytes(peBuffer, 'cobalt_beacon_x64.exe');
    expect(byteAnalysis.sha256).toBe(expectedSha256);
    expect(byteAnalysis.detectedFormat).toBe('pe');
    expect(byteAnalysis.peHeaders?.isPE).toBe(true);
    expect(byteAnalysis.peHeaders?.machine).toBe('x86-64 (AMD64)');
    expect(byteAnalysis.sections.map((s) => s.name)).toEqual(['.text', '.rdata']);
    expect(byteAnalysis.suspiciousImportedApis).toEqual(
      expect.arrayContaining(['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'InternetOpenA'])
    );
    expect(byteAnalysis.entropy).toBeGreaterThan(0);

    // End-to-end HTTP upload via multipart/form-data
    const caseId = `case-e2e-${Date.now()}`;
    const formData = new FormData();
    formData.append('caseId', caseId);
    formData.append('file', new Blob([new Uint8Array(peBuffer)], { type: 'application/octet-stream' }), 'cobalt_beacon_x64.exe');

    const uploadRes = await fetch(`${baseUrl}/api/malware-intel/samples/upload`, {
      method: 'POST',
      body: formData,
    });
    expect(uploadRes.status).toBe(200);
    const uploadBody = await uploadRes.json();
    const sample = uploadBody.sample;
    expect(sample).toBeDefined();
    expect(sample.sha256).toBe(expectedSha256);
    expect(sample.fileFormat).toBe('pe');
    expect(sample.verdict).toBe('malicious');
    expect(fs.existsSync(sample.storagePath)).toBe(true);

    // Verify persistent records: Sample -> Analysis -> Findings -> Evidence
    const persistedSample = getPersistedSamples().find((s) => s.sha256 === expectedSha256);
    expect(persistedSample).toBeDefined();

    const persistedAnalysis = getPersistedAnalyses().find((a) => a.sha256 === expectedSha256);
    expect(persistedAnalysis).toBeDefined();
    expect(persistedAnalysis.detectedFormat).toBe('pe');
    expect(persistedAnalysis.suspiciousImports).toEqual(
      expect.arrayContaining(['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'])
    );

    const persistedFindings = getPersistedFindings().filter((f) => f.sampleId === sample.id);
    expect(persistedFindings.length).toBeGreaterThan(0);

    const persistedEvidence = getPersistedEvidence().filter((e) => e.sampleId === sample.id);
    expect(persistedEvidence.length).toBe(persistedFindings.length);

    // Verify GET /api/malware-intel/samples/:id returns the persisted chain
    const getRes = await fetch(`${baseUrl}/api/malware-intel/samples/${sample.id}`);
    expect(getRes.status).toBe(200);
    const getBody = await getRes.json();
    expect(getBody.sample.analysisRecord.id).toBe(persistedAnalysis.id);
    expect(getBody.sample.findingRecords.length).toBe(persistedFindings.length);
    expect(getBody.sample.evidenceRecords.length).toBe(persistedEvidence.length);
  });

  it('4 & 5. Enforces all 9 required evidence fields on every finding and verifies structured artifact evidence per agent', async () => {
    const invRes = await fetch(`${baseUrl}/api/investigations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: 'Audit Evidence & Agent Consumption',
        severity: 'Critical',
        evidence: {
          name: 'agent_audit_sample.ps1',
          content:
            'powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=\nhttp://185.220.101.44/payload.bin\nHKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
        },
      }),
    });

    expect(invRes.status).toBe(201);
    const invBody = await invRes.json();
    const inv = invBody.investigation;
    expect(inv.agentFindings.length).toBeGreaterThanOrEqual(5);

    const requiredFields = [
      'finding',
      'source',
      'artifact',
      'location',
      'evidence',
      'confidence',
      'analysis_method',
      'timestamp',
      'limitations',
    ];

    for (const agent of inv.agentFindings) {
      expect(agent.structuredEvidence).toBeDefined();
      expect(Array.isArray(agent.structuredEvidence.consumedArtifacts)).toBe(true);
      expect(agent.structuredEvidence.consumedArtifacts.length).toBeGreaterThan(0);

      for (const f of agent.findings) {
        for (const field of requiredFields) {
          expect(f[field], `Missing field "${field}" on finding in ${agent.agentId}`).toBeDefined();
        }
      }
    }

    // Verify client-side multiAgentAnalysis generateFinding also enforces all 9 fields + structuredEvidence
    const sampleArtifact: EvidenceArtifact = {
      id: 'art-audit-1',
      name: 'dropper.ps1',
      type: 'script',
      size: '1.2 KB',
      uploadedBy: 'Operator',
      uploadedAt: '10:00:00',
      status: 'Analyzing',
      sha256: 'a'.repeat(64),
      previewContent: 'powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA= https://evil-c2.org/gate.php 185.220.101.5',
    };

    const agentIds = ['malware-analysis', 'ioc-extraction', 'threat-intel', 'network-analysis', 'verification-agent'];
    const completedFindings: any[] = [];

    for (const agentId of agentIds) {
      const artifactWithPrior: EvidenceArtifact = {
        ...sampleArtifact,
        agentFindings: completedFindings,
      };
      const res = generateFinding(agentId, artifactWithPrior);
      expect(res.structuredEvidence).toBeDefined();
      expect(res.findings && res.findings.length).toBeGreaterThan(0);
      for (const f of res.findings || []) {
        for (const field of requiredFields) {
          expect((f as any)[field], `Client generateFinding(${agentId}) missing ${field}`).toBeDefined();
        }
      }
      completedFindings.push({
        agentId,
        agentName: agentId,
        status: 'complete',
        stepProgress: 100,
        ...res,
      });
    }
  });

  it('6 & 8. Executes the tool loop and strictly distinguishes NOT CONFIGURED, QUERY FAILED, NO MALICIOUS DETECTIONS, and UNSUPPORTED FILE TYPE', async () => {
    // 1) Clean indicator -> VirusTotal: NO MALICIOUS DETECTIONS
    const cleanRes = await fetch(`${baseUrl}/api/tools/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolId: 'virustotal',
        action: 'ip.lookup',
        indicatorValue: '8.8.8.8',
        requestedByAgent: 'threat-intel',
        caseId: 'case-tool-test',
      }),
    });
    expect(cleanRes.status).toBe(200);
    const cleanBody = await cleanRes.json();
    expect(cleanBody.status).toBe('NO_MALICIOUS_DETECTIONS');
    expect(cleanBody.responseSummary).toBe('VirusTotal: NO MALICIOUS DETECTIONS');

    // 2) Query failure -> VirusTotal: QUERY FAILED
    const failRes = await fetch(`${baseUrl}/api/tools/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolId: 'virustotal',
        action: 'ip.lookup',
        indicatorValue: '8.8.8.8',
        simulateFailure: true,
        requestedByAgent: 'threat-intel',
        caseId: 'case-tool-test',
      }),
    });
    expect(failRes.status).toBe(502);
    const failBody = await failRes.json();
    expect(failBody.status).toBe('QUERY_FAILED');
    expect(failBody.responseSummary).toBe('VirusTotal: QUERY FAILED');

    // 3) Disable VirusTotal -> VirusTotal: NOT CONFIGURED
    await fetch(`${baseUrl}/api/tools/virustotal/disable`, { method: 'POST' });
    const notConfRes = await fetch(`${baseUrl}/api/tools/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolId: 'virustotal',
        action: 'ip.lookup',
        indicatorValue: '185.220.101.44',
        requestedByAgent: 'threat-intel',
        caseId: 'case-tool-test',
      }),
    });
    expect(notConfRes.status).toBe(200);
    const notConfBody = await notConfRes.json();
    expect(notConfBody.status).toBe('NOT_CONFIGURED');
    expect(notConfBody.responseSummary).toBe('VirusTotal: NOT CONFIGURED');
    expect(notConfBody.verdict).toBe('unknown');

    // Re-enable VirusTotal for subsequent tests
    await fetch(`${baseUrl}/api/tools/virustotal/enable`, { method: 'POST' });

    // 4) Malicious indicator -> tool evidence stored & returned
    const malRes = await fetch(`${baseUrl}/api/tools/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolId: 'virustotal',
        action: 'ip.lookup',
        indicatorValue: '185.220.101.5',
        requestedByAgent: 'threat-intel',
        caseId: 'case-tool-test',
      }),
    });
    expect(malRes.status).toBe(200);
    const malBody = await malRes.json();
    expect(malBody.status).toBe('SUCCESS');
    expect(malBody.verdict).toBe('malicious');
    const storedToolEvidence = getPersistedEvidence().find((e) => e.indicator === '185.220.101.5');
    expect(storedToolEvidence).toBeDefined();

    // 5) Unsupported file type for static binary analysis -> Static Analysis: UNSUPPORTED FILE TYPE
    const unsupportedArtifact: EvidenceArtifact = {
      id: 'art-unsupported-1',
      name: 'network_diagram.png',
      type: 'screenshot',
      size: '450 KB',
      uploadedBy: 'Operator',
      uploadedAt: '10:05:00',
      status: 'Analyzing',
    };
    const staticFinding = generateFinding('malware-analysis', unsupportedArtifact);
    expect(staticFinding.summary).toContain('Static Analysis: UNSUPPORTED FILE TYPE');
    expect(staticFinding.findings?.[0]?.finding).toBe('Static Analysis: UNSUPPORTED FILE TYPE');
  });

  it('7. Emits real backend truth events in Live Activity for every pipeline stage', async () => {
    const invRes = await fetch(`${baseUrl}/api/investigations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: 'Live Activity Truth Verification',
        severity: 'High',
        evidence: {
          name: 'truth_beacon.exe',
          content: 'ReflectiveLoader VirtualAllocEx http://185.220.101.44/stage2.bin',
        },
      }),
    });
    expect(invRes.status).toBe(201);
    const invBody = await invRes.json();
    const invId = invBody.investigation.id;

    const eventsRes = await fetch(`${baseUrl}/api/investigations/${invId}/events`);
    expect(eventsRes.status).toBe(200);
    const eventsBody = await eventsRes.json();
    const eventTypes = eventsBody.events.map((e: any) => e.type);

    const expectedLifecycleEvents = [
      'UPLOAD_STARTED',
      'HASH_COMPLETED',
      'STATIC_ANALYSIS_STARTED',
      'STATIC_ANALYSIS_COMPLETED',
      'IOC_DISCOVERED',
      'MALWARE_ANALYSIS_STARTED',
      'TOOL_QUERY_STARTED',
      'TOOL_QUERY_COMPLETED',
      'AGENT_COMPLETED',
      'VERIFICATION_STARTED',
      'VERIFICATION_COMPLETED',
      'REPORT_GENERATED',
    ];

    for (const expectedType of expectedLifecycleEvents) {
      expect(eventTypes).toContain(expectedType);
    }
  });

  it('9. Completes the malware learning feedback loop so uploaded datasets influence subsequent sample detection', async () => {
    // Novel proprietary token not in static built-in rules
    const novelMalwareToken = `NEXSUS_APT_NOVEL_IMPLANT_WATERMARK_${Date.now()}`;
    const novelPayload = `int main() { const char* tag = "${novelMalwareToken}"; return 0; }`;

    // Before dataset training: upload a sample with only this novel watermark
    const preUploadRes = await fetch(`${baseUrl}/api/malware-intel/samples/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'pre_train_implant.bin',
        content: novelPayload,
      }),
    });
    expect(preUploadRes.status).toBe(200);
    const preBody = await preUploadRes.json();
    expect(preBody.sample.verdict).toBe('clean');

    // Upload a labeled dataset teaching the engine that novelMalwareToken is malicious family "ShadowNexusAPT"
    const datasetJson = JSON.stringify([
      {
        name: 'shadow_nexus_train_1.bin',
        label: 'malicious',
        family: 'ShadowNexusAPT',
        content: `sample_header ${novelMalwareToken} stage_loader_alpha`,
      },
      {
        name: 'shadow_nexus_train_2.bin',
        label: 'malicious',
        family: 'ShadowNexusAPT',
        content: `sample_header ${novelMalwareToken} stage_loader_beta`,
      },
    ]);

    const dsRes = await fetch(`${baseUrl}/api/malware-intel/datasets/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'ShadowNexus_APT_Dataset.json',
        content: datasetJson,
      }),
    });
    expect(dsRes.status).toBe(200);
    const dsBody = await dsRes.json();
    expect(dsBody.success).toBe(true);
    expect(dsBody.trainableRows).toBe(2);
    expect(dsBody.metrics.totalSamples).toBeGreaterThanOrEqual(8);

    // After dataset training: upload a new variant containing the learned token
    const postPayload = `int main() { const char* tag = "${novelMalwareToken}"; const char* build = "v2_new_hash"; return 0; }`;
    const postUploadRes = await fetch(`${baseUrl}/api/malware-intel/samples/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'post_train_implant_v2.bin',
        content: postPayload,
      }),
    });

    expect(postUploadRes.status).toBe(200);
    const postBody = await postUploadRes.json();
    expect(postBody.sample.verdict).toBe('malicious');
    expect(postBody.sample.family).toBe('ShadowNexusAPT');
    expect(
      postBody.sample.verdictDetail.observedCharacteristics.some((c: string) =>
        c.includes('Learned dataset match')
      )
    ).toBe(true);
  });
});
