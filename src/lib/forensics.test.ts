import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAssistantResponse, citationKey, type LocalFinding } from './assistant.ts';
import {
  analyzeContactPatterns,
  buildNetworkGraph,
  buildTowerTimeline,
  correlateIpdrCgnat,
  detectDeviceSimChanges,
  findCommonContacts,
  normalizePhoneNumber,
  parseTimestampIST,
} from './forensics.ts';
import {
  detectOperatorSchema,
  normalizeDatasetRows,
  parseDelimitedText,
} from './parser.ts';
import {
  buildDefaultCasePS03,
  SAMPLE_AIRTEL_CDR_TSV,
  SAMPLE_JIO_CDR_CSV,
} from './sampleData.ts';

test('normalizePhoneNumber normalizes Indian numbers across formats', () => {
  assert.equal(normalizePhoneNumber('9829077112'), '+919829077112');
  assert.equal(normalizePhoneNumber('09829077112'), '+919829077112');
  assert.equal(normalizePhoneNumber('+91 98290-77112'), '+919829077112');
  assert.equal(normalizePhoneNumber('919876543210'), '+919876543210');
  assert.equal(normalizePhoneNumber(''), '');
});

test('assistant cites only exact source rows and keeps the comparison preset', () => {
  const caseFile = buildDefaultCasePS03();
  const first = caseFile.cdrs[0];
  const otherOperator = caseFile.cdrs.find(row => row.sourceFile !== first.sourceFile)!;
  const reusedId = { ...otherOperator, id: first.id };
  caseFile.cdrs = [first, reusedId];
  const hash = caseFile.sources.find(source => source.fileName === first.sourceFile)!.sha256.slice(0, 12);
  const reference = `${first.sourceFile} Row #${first.rowNumber} · SHA-256 ${hash}`;
  const finding: LocalFinding = {
    title: 'Common contacts', summary: 'Recorded calls', rows: [], intent: 'common',
    subjects: caseFile.suspects.slice(0, 2).map(subject => subject.phone), night_only: true,
    evidence: [{ 'Source record': reference }, { 'Source record': reference }, { 'Source record': reference + 'wrong' }],
  };
  const result = buildAssistantResponse(caseFile, 'Common contacts after midnight', finding);
  assert.equal(result.evidenceCitations.length, 1);
  assert.equal(result.evidenceCitations[0].sourceFile, first.sourceFile);
  assert.notEqual(citationKey(result.evidenceCitations[0]), citationKey({ ...result.evidenceCitations[0], sourceFile: reusedId.sourceFile }));
  assert.equal(result.suggestedFilters[0].comparePhone, finding.subjects[1]);
  assert.equal(result.suggestedFilters[0].nightOnly, true);
  assert.ok(result.followUpQuestions.length);

  const unsupported = buildAssistantResponse(caseFile, 'Unknown question', {
    ...finding, summary: reference, evidence: [{ Comment: reference }],
  });
  assert.equal(unsupported.dataSupported, false);
  assert.equal(unsupported.evidenceCitations.length, 0);
  assert.equal(unsupported.suggestedFilters.length, 0);
});

test('case-level call counts use the observed side and exclude SMS', () => {
  const { cdrs, suspects } = buildDefaultCasePS03();
  const incoming = { ...cdrs[0], callType: 'VOICE_IN' as const, observedMsisdn: cdrs[0].callee };
  const sms = { ...incoming, callType: 'SMS_IN' as const };
  const result = analyzeContactPatterns([incoming, sms], suspects, 'ALL');
  assert.equal(result.totalCalls, 1);
  assert.equal(result.incomingCalls, 1);
  assert.equal(result.contacts[0].contactNumber, incoming.caller);
});

test('parseTimestampIST parses ISO-8601 and Airtel split DD/MM/YYYY into IST with night flag', () => {
  const jioTs = parseTimestampIST('2026-01-14T02:01:01+05:30');
  assert.ok(jioTs);
  assert.equal(jioTs.istHour, 2);
  assert.equal(jioTs.isNight, true);
  assert.equal(jioTs.iso, '2026-01-14T02:01:01+05:30');

  const airtelTs = parseTimestampIST(undefined, '14/01/2026', '14:22:10');
  assert.ok(airtelTs);
  assert.equal(airtelTs.istHour, 14);
  assert.equal(airtelTs.isNight, false);
  assert.equal(airtelTs.iso, '2026-01-14T14:22:10+05:30');

  assert.equal(parseTimestampIST('not-a-date'), null);
});

test('multi-operator auto-detection and strict validation reports bad rows cleanly', () => {
  const parsedAirtel = parseDelimitedText(SAMPLE_AIRTEL_CDR_TSV);
  assert.equal(parsedAirtel.delimiter, '\t');
  const detectedAirtel = detectOperatorSchema(parsedAirtel.headers, parsedAirtel.rows, 'Airtel_CDR.tsv');
  assert.equal(detectedAirtel.datasetType, 'cdr');
  assert.equal(detectedAirtel.operator, 'Airtel');
  assert.equal(detectedAirtel.confidence, 'high');

  const badCsv = `record_id,telco,timestamp,caller_msisdn,callee_msisdn,duration_sec\nR1,Jio,2026-01-14T03:00:00+05:30,9829077112,9876543210,45\nR2,Jio,BAD-DATE,,9876543210,12`;
  const parsedBad = parseDelimitedText(badCsv);
  const det = detectOperatorSchema(parsedBad.headers, parsedBad.rows, 'bad.csv');
  const res = normalizeDatasetRows({
    sourceId: 's-bad',
    fileName: 'bad.csv',
    datasetType: 'cdr',
    operator: 'Jio 5G',
    uploadedBy: 'tester',
    sha256: 'abc',
    rows: parsedBad.rows,
    columnMapping: det.suggestedMapping,
  });
  assert.equal(res.cdrs.length, 1);
  assert.equal(res.sourceMeta.rejectedRowCount, 1);
  assert.equal(res.issues[0].rowNumber, 3);
});

test('Case PS03 contact analysis, common contacts, network graph, tower hops, IMEI/SIM swaps, and CGNAT IPDR lookup', () => {
  const ps03 = buildDefaultCasePS03();
  assert.ok(ps03.cdrs.length >= 30, 'expected multi-operator normalized CDRs');
  assert.equal(ps03.ipdrs.length, 6);
  assert.equal(ps03.towers.length, 5);

  // 1. Contact patterns for Rohan Mehta
  const rohanAnalysis = analyzeContactPatterns(ps03.cdrs, ps03.suspects, '+919829077112');
  assert.equal(rohanAnalysis.targetName, 'Rohan Mehta');
  assert.ok(rohanAnalysis.nightCalls >= 15, 'Rohan should have strong night activity');
  assert.ok(rohanAnalysis.contacts.length >= 4);

  // 2. Common contacts between Rohan Mehta and Aman Verma
  const common = findCommonContacts(ps03.cdrs, ps03.suspects, [
    '+919829077112',
    '+919876543210',
  ]);
  const sharedPhones = common.sharedContacts.map((c) => c.contactNumber);
  assert.ok(sharedPhones.includes('+919876543211'), 'Vikash Sharma should be a shared contact');
  assert.ok(sharedPhones.includes('+919876543212'), 'Neha Singh should be a shared contact');
  assert.ok(sharedPhones.includes('+919811004421'), 'External bridge number should be detected');
  assert.ok(common.directLinks.length === 1 && common.directLinks[0].callCount >= 5);

  // 3. Network graph
  const graph = buildNetworkGraph(ps03.cdrs, ps03.suspects);
  assert.ok(graph.nodes.length >= 6);
  assert.ok(graph.edges.length >= 6);
  assert.ok(graph.nodes.some((n) => n.isSharedBridge && n.phone === '+919811004421'));

  // 4. Tower timeline for Rohan Mehta
  const timeline = buildTowerTimeline(ps03.cdrs, ps03.towers, '+919829077112');
  assert.ok(timeline.steps.length >= 20);
  assert.ok(timeline.transitions >= 4, 'Rohan should hop across Jaipur towers');
  const combinedTimeline = buildTowerTimeline(ps03.cdrs, ps03.towers, '+919829077112', undefined, ps03.ipdrs);
  const ipdrStep = combinedTimeline.steps.find(step => step.citation.recordType === 'ipdr');
  assert.ok(ipdrStep, 'serving cells logged in IPDR should have their own citations');
  assert.equal(ipdrStep.sourceFile, 'Carrier_IPDR.csv');

  // 5. IMEI & SIM change detection + Shared IMEI detection
  const deviceRes = detectDeviceSimChanges(ps03.cdrs, ps03.suspects);
  assert.ok(
    deviceRes.changes.some(
      (c) =>
        c.msisdn === '+919829077112' &&
        c.changeType === 'IMEI_CHANGE' &&
        c.previousValue === '356938035643801' &&
        c.newValue === '356938035643819'
    ),
    'Rohan IMEI change should be detected'
  );
  assert.ok(
    deviceRes.changes.some(
      (c) =>
        c.msisdn === '+919829077112' &&
        c.changeType === 'SIM_SWAP_IMSI' &&
        c.previousValue === '405870000000001' &&
        c.newValue === '405870000000019'
    ),
    'Rohan IMSI SIM swap should be detected'
  );
  assert.ok(
    deviceRes.sharedDevices.some((s) => s.imei === '356938035643819' && s.msisdns.length === 2),
    'Shared IMEI 356938035643819 between Rohan Mehta and Aman Verma should be detected'
  );

  // 6. CGNAT IPDR lookup (unique exact match + tolerance distinction)
  const ipdrExact = correlateIpdrCgnat(ps03.ipdrs, ps03.suspects, {
    publicIp: '157.34.12.89',
    sourcePort: 44120,
    observedTimeIso: '2026-01-14T02:18:45+05:30',
    protocol: 'TCP',
    toleranceSec: 5,
  });
  assert.equal(ipdrExact.uniqueSubscriber?.msisdn, '+919829077112');
  assert.equal(ipdrExact.uniqueSubscriber?.recordId, 'NAT-001');
  assert.equal(ipdrExact.matches[0].status, 'EXACT_MATCH');
  assert.equal(ipdrExact.matches[1].status, 'TOLERANCE_MATCH');
});

test('SAMPLE_JIO_CDR_CSV parses cleanly with 12 rows', () => {
  const parsed = parseDelimitedText(SAMPLE_JIO_CDR_CSV);
  assert.equal(parsed.rows.length, 12);
});
