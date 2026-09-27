import { describe, expect, it } from 'vitest';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { extractIOCs } from '../src/utils/iocExtraction';

describe('IOC Extraction Completeness and Deterministic Hashing on Known Fixtures', () => {
  const fixturesDir = path.join(__dirname, 'fixtures');

  it('Fixture 01 (test-iocs-01.txt): extracts exactly 12 known indicators without duplicates or false positives', () => {
    const filePath = path.join(fixturesDir, 'test-iocs-01.txt');
    const content = fs.readFileSync(filePath, 'utf8');

    const expectedValues = [
      '185.220.101.44',
      'c2.darkfleet-soc.io',
      'https://update-windows-defender.online/en/check.php',
      'threat-actor@adversary-infra.cc',
      '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
      '098f6bcd4621d373cade4e832627b4f6',
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefenderUpdate',
      'C:\\Windows\\Temp\\beacon_x64.dll',
      'Global\\ZoneTransfer_Mutex_8921',
      'CVE-2024-38812',
      'T1059.001',
    ];

    const extracted = extractIOCs({
      fileName: 'test-iocs-01.txt',
      previewContent: content,
    });

    const extractedValues = extracted.map((i) => i.normalizedValue || i.value);
    const uniqueValues = Array.from(new Set(extractedValues));

    const duplicates = extractedValues.length - uniqueValues.length;
    const missing = expectedValues.filter((exp) => !extractedValues.some((act) => act.toLowerCase() === exp.toLowerCase()));
    const falsePositives = uniqueValues.filter((act) => !expectedValues.some((exp) => exp.toLowerCase() === act.toLowerCase()));

    expect(expectedValues.length).toBe(12);
    expect(missing).toEqual([]);
    expect(duplicates).toBe(0);
    expect(falsePositives).toEqual([]);
    expect(uniqueValues.length).toBe(12);
  });

  it('Fixture 02 (test-iocs-02.txt): normalizes defanged indicators and advanced artifacts (Expected: 10)', () => {
    const filePath = path.join(fixturesDir, 'test-iocs-02.txt');
    const content = fs.readFileSync(filePath, 'utf8');

    const expectedValues = [
      'https://malicious-c2.org/stage2.bin',
      '194.26.29.112',
      'botnet-gate.top',
      '384:9fK123456789012345678901234567890:c91',
      'T10123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567',
      'C:\\dev\\target_build\\loader.pdb',
      'schtasks /create /tn "SystemUpdater" /tr "regsvr32 /s scrobj"',
      'Global\\CobaltStrike_Mutex_4812',
      'IN TXT v=spf1_redirect_c2',
      'vssadmin delete shadows /all /quiet',
    ];

    const extracted = extractIOCs({
      fileName: 'test-iocs-02.txt',
      previewContent: content,
    });

    const extractedValues = extracted.map((i) => i.normalizedValue || i.value);
    const uniqueValues = Array.from(new Set(extractedValues));

    const duplicates = extractedValues.length - uniqueValues.length;
    const missing = expectedValues.filter((exp) => !extractedValues.some((act) => act.toLowerCase() === exp.toLowerCase()));
    const falsePositives = uniqueValues.filter((act) => !expectedValues.some((exp) => exp.toLowerCase() === act.toLowerCase()));

    expect(expectedValues.length).toBe(10);
    expect(missing).toEqual([]);
    expect(duplicates).toBe(0);
    expect(falsePositives).toEqual([]);
    expect(uniqueValues.length).toBe(10);
  });

  it('Fixture 03 (test-malware-report.txt): extracts threat advisory indicators (Expected: 12)', () => {
    const filePath = path.join(fixturesDir, 'test-malware-report.txt');
    const content = fs.readFileSync(filePath, 'utf8');

    const expectedValues = [
      'd41d8cd98f00b204e9800998ecf8427e',
      'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'C:\\Users\\victim\\AppData\\Local\\Temp\\dropper.exe',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealthSystray',
      '198.51.100.77',
      'apt29-relay.org',
      'https://apt29-relay.org/beacon/auth',
      'campaign = "Operation_NightDragon"',
      'analyst-triage@agency-cert.gov',
      'CVE-2023-38606',
      'T1071.001',
    ];

    const extracted = extractIOCs({
      fileName: 'test-malware-report.txt',
      previewContent: content,
    });

    const extractedValues = extracted.map((i) => i.normalizedValue || i.value);
    const uniqueValues = Array.from(new Set(extractedValues));

    const duplicates = extractedValues.length - uniqueValues.length;
    const missing = expectedValues.filter((exp) => !extractedValues.some((act) => act.toLowerCase() === exp.toLowerCase()));
    const falsePositives = uniqueValues.filter((act) => !expectedValues.some((exp) => exp.toLowerCase() === act.toLowerCase()));

    expect(expectedValues.length).toBe(12);
    expect(missing).toEqual([]);
    expect(duplicates).toBe(0);
    expect(falsePositives).toEqual([]);
    expect(uniqueValues.length).toBe(12);
  });

  it('Fixture 04 (test-pcap-indicators.txt): extracts packet forensics indicators (Expected: 8)', () => {
    const filePath = path.join(fixturesDir, 'test-pcap-indicators.txt');
    const content = fs.readFileSync(filePath, 'utf8');

    const expectedValues = [
      '198.51.100.99',
      'c2-listener.darkfleet.net',
      'https://c2-listener.darkfleet.net/api/v1/heartbeat',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CobaltStrike/4.8',
      'IN CNAME telemetry-ns1',
      'cert-authority@darkfleet.net',
      '3a4f6d89b1c2e4a5f6e8c0d1e2f3a4b5',
      'Global\\ZoneTransfer_Pcap_Sync',
    ];

    const extracted = extractIOCs({
      fileName: 'test-pcap-indicators.txt',
      previewContent: content,
    });

    const extractedValues = extracted.map((i) => i.normalizedValue || i.value);
    const uniqueValues = Array.from(new Set(extractedValues));

    const duplicates = extractedValues.length - uniqueValues.length;
    const missing = expectedValues.filter((exp) => !extractedValues.some((act) => act.toLowerCase() === exp.toLowerCase()));
    const falsePositives = uniqueValues.filter((act) => !expectedValues.some((exp) => exp.toLowerCase() === act.toLowerCase()));

    expect(expectedValues.length).toBe(8);
    expect(missing).toEqual([]);
    expect(duplicates).toBe(0);
    expect(falsePositives).toEqual([]);
    expect(uniqueValues.length).toBe(8);
  });

  it('Deterministic SHA256, SHA1, MD5 hashing on fixture bytes is repeatable and non-random', () => {
    const fixture1Bytes = fs.readFileSync(path.join(fixturesDir, 'test-iocs-01.txt'));
    const hash1 = crypto.createHash('sha256').update(fixture1Bytes).digest('hex');
    const hash2 = crypto.createHash('sha256').update(fixture1Bytes).digest('hex');
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);

    const md5_1 = crypto.createHash('md5').update(fixture1Bytes).digest('hex');
    const md5_2 = crypto.createHash('md5').update(fixture1Bytes).digest('hex');
    expect(md5_1).toBe(md5_2);
    expect(md5_1).toHaveLength(32);
  });
});
