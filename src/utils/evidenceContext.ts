/**
 * Phase 1 — Normalized EvidenceContext Builder
 *
 * Ensures every specialist agent consumes a single, deterministic EvidenceContext
 * produced once from the uploaded artifact bytes or evidence payload.
 */

import { EvidenceArtifact, EvidenceContext } from '../types';
import { analyzeUploadedBytes, computeSha256Hex } from './binaryAnalysis';
import { extractIOCs } from './iocExtraction';

export interface BuildEvidenceContextInput {
  fileId?: string;
  fileName: string;
  fileType?: string;
  size?: number;
  content?: Buffer | Uint8Array | string;
  artifact?: EvidenceArtifact;
  md5?: string;
  sha1?: string;
  sha256?: string;
}

export function buildEvidenceContext(input: BuildEvidenceContextInput | EvidenceArtifact): EvidenceContext {
  // Support passing an EvidenceArtifact directly
  if ('uploadedAt' in input && 'name' in input) {
    const art = input as EvidenceArtifact;
    if (art.evidenceContext) {
      return art.evidenceContext;
    }
    return buildEvidenceContext({
      fileId: art.id,
      fileName: art.name,
      fileType: art.type,
      size: art.malwareIntelSample?.sizeBytes || (art.size ? parseInt(art.size, 10) || 0 : 0),
      content: art.analysisContent || art.previewContent || '',
      artifact: art,
      sha256: art.sha256 || art.malwareIntelSample?.sha256,
      sha1: art.malwareIntelSample?.sha1,
      md5: art.malwareIntelSample?.md5,
    });
  }

  const params = input as BuildEvidenceContextInput;
  const art = params.artifact;
  const sample = art?.malwareIntelSample;
  const rawContent = params.content ?? art?.analysisContent ?? art?.previewContent ?? '';

  const byteResult = analyzeUploadedBytes(rawContent, params.fileName);

  const sha256 =
    params.sha256 ||
    sample?.sha256 ||
    byteResult.sha256 ||
    computeSha256Hex(typeof rawContent === 'string' ? Buffer.from(rawContent, 'utf8') : rawContent);

  const textRepresentation =
    typeof rawContent === 'string'
      ? rawContent
      : Buffer.isBuffer(rawContent)
        ? rawContent.toString('utf8')
        : Buffer.from(rawContent).toString('utf8');

  const extractedIocs = extractIOCs({
    fileName: params.fileName,
    previewContent: textRepresentation,
    staticStrings: {
      suspicious: sample?.features?.suspiciousStrings || byteResult.suspiciousStrings.map((s) => s.value),
      network: sample?.features?.networkIndicatorStrings || byteResult.networkStrings,
      persistence: sample?.features?.persistenceIndicatorStrings || byteResult.persistenceStrings,
    },
  });

  const strings = Array.from(
    new Set([
      ...(sample?.features?.suspiciousStrings || []),
      ...byteResult.stringsSample.map((s) => s.value),
    ]),
  );

  const urls = Array.from(
    new Set([
      ...extractedIocs.filter((i) => i.type === 'url' || i.type === 'embedded_url').map((i) => i.normalizedValue || i.value),
      ...byteResult.networkStrings.filter((s) => /^https?:\/\//i.test(s)),
    ]),
  );

  const domains = Array.from(
    new Set(
      extractedIocs
        .filter((i) => ['domain', 'fqdn', 'embedded_domain', 'c2_address'].includes(i.type))
        .map((i) => i.normalizedValue || i.value),
    ),
  );

  const ips = Array.from(
    new Set(
      extractedIocs
        .filter((i) => ['ipv4', 'ipv6'].includes(i.type))
        .map((i) => i.normalizedValue || i.value),
    ),
  );

  const filePaths = Array.from(
    new Set(
      extractedIocs
        .filter((i) => ['windows_path', 'linux_path', 'filename', 'pdb_path'].includes(i.type))
        .map((i) => i.normalizedValue || i.value),
    ),
  );

  const registryKeys = Array.from(
    new Set([
      ...extractedIocs
        .filter((i) => ['registry_path', 'registry_key'].includes(i.type))
        .map((i) => i.normalizedValue || i.value),
      ...byteResult.persistenceStrings,
    ]),
  );

  const imports = Array.from(
    new Set([
      ...(sample?.features?.peSuspiciousImportedApis || []),
      ...byteResult.importedApis,
    ]),
  );

  const sections = (sample?.features?.peSections || byteResult.sections || []).map((sec: any) => ({
    name: sec.name,
    virtualSize: sec.virtualSize ?? sec.rawSize ?? 0,
    virtualAddress: sec.virtualAddress ?? 0,
    rawSize: sec.rawSize ?? 0,
    rawAddress: sec.rawAddress ?? 0,
    entropy: sec.entropy ?? byteResult.entropy,
    rwx: Boolean(sec.rwx),
    characteristics: sec.characteristics ?? 0,
  }));

  const pe = byteResult.peHeaders
    ? {
        ...byteResult.peHeaders,
        importedDlls: imports.filter((i) => i.toLowerCase().endsWith('.dll')),
        suspiciousApis: byteResult.suspiciousImportedApis,
        rwxSections: byteResult.rwxSections,
      }
    : sample?.fileFormat === 'pe'
      ? {
          isPE: true,
          machine: sample.features?.architecture || 'x86-64 (AMD64)',
          subsystem: sample.features?.subsystem || 'WINDOWS_CUI',
          is64Bit: true,
          entryPointRva: sample.features?.entryPointRva || 0x1000,
          imageBase: '0x140000000',
          sectionCount: sections.length,
          timeDateStamp: 0,
          importedDlls: Object.keys(sample.features?.peImportedDlls || {}),
          suspiciousApis: sample.features?.peSuspiciousImportedApis || [],
          rwxSections: sample.features?.rwxSections || [],
        }
      : undefined;

  const elf = byteResult.elfHeaders
    ? { ...byteResult.elfHeaders }
    : sample?.fileFormat === 'elf'
      ? {
          isELF: true,
          class: '64-bit' as const,
          endianness: 'little' as const,
          machine: sample.features?.elfMachine || 'x86-64',
          type: sample.features?.elfType || 'EXEC',
        }
      : undefined;

  return {
    fileId: params.fileId || art?.id || `file-${sha256.slice(0, 12)}`,
    fileName: params.fileName,
    fileType: params.fileType || (byteResult.detectedFormat !== 'text' ? byteResult.detectedFormat : art?.type || 'unknown'),
    size: params.size || sample?.sizeBytes || byteResult.totalBytes,
    hashes: {
      md5: params.md5 || sample?.md5,
      sha1: params.sha1 || sample?.sha1,
      sha256,
    },
    strings,
    urls,
    domains,
    ips,
    filePaths,
    registryKeys,
    pe,
    elf,
    imports,
    exports: [],
    entropy: sample?.features?.entropyOverall ?? byteResult.entropy,
    sections,
    extractedArtifacts: extractedIocs.map((ioc) => ({
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
      mimeType: byteResult.mimeType,
      magicHex: byteResult.magicHex,
      isExecutable: byteResult.isExecutable,
      uniqueByteRatio: byteResult.uniqueByteRatio,
      printableStringRatio: byteResult.printableStringRatio,
      uploadedBy: art?.uploadedBy || sample?.uploadedBy || 'SOC Operator',
      caseId: art?.caseId || sample?.caseId || null,
    },
  };
}
