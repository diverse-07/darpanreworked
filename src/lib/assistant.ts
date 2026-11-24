import type { AiQueryResponse, CaseFile, EvidenceCitation } from '../types/forensics.ts';
import { cdrToCitation, ipdrToCitation, isVoiceCall } from './forensics.ts';

export type LocalFinding = {
  title: string;
  summary: string;
  rows: Array<Record<string, unknown>>;
  evidence: Array<Record<string, unknown>>;
  intent: string;
  subjects: string[];
  night_only: boolean;
};

export function caseCitations(caseFile: CaseFile): EvidenceCitation[] {
  return [
    ...caseFile.cdrs.map(cdrToCitation),
    ...caseFile.ipdrs.map(ipdrToCitation),
    ...caseFile.towers.flatMap(tower => tower.sourceFile && tower.rowNumber ? [{
      sourceFile: tower.sourceFile,
      rowNumber: tower.rowNumber,
      recordId: tower.towerId,
      recordType: 'tower' as const,
      summary: `${tower.towerName} · ${tower.lat}, ${tower.lon}`,
    }] : []),
  ];
}

export function citationKey(citation: EvidenceCitation): string {
  return JSON.stringify([citation.recordType, citation.sourceFile, citation.rowNumber, citation.recordId]);
}

export function buildAssistantResponse(
  caseFile: CaseFile,
  question: string,
  finding: LocalFinding | null,
): AiQueryResponse {
  const digests = new Map(caseFile.sources.map(source => [source.fileName, source.sha256]));
  const citationByReference = new Map(caseCitations(caseFile).flatMap(citation => {
    const digest = digests.get(citation.sourceFile);
    if (!digest) return [];
    const reference = `${citation.sourceFile} Row #${citation.rowNumber} · SHA-256 ${digest.slice(0, 12)}`;
    return [[reference, citation] as const];
  }));
  const linked = new Map<string, EvidenceCitation>();
  const sectionExamples = new Map<string, EvidenceCitation>();
  for (const row of finding?.evidence ?? []) {
    for (const reference of [row['Source record'], row['Coordinates source']]) {
      if (typeof reference !== 'string') continue;
      const citation = citationByReference.get(reference);
      if (!citation) continue;
      linked.set(citationKey(citation), citation);
      if (typeof row.Section === 'string' && !sectionExamples.has(row.Section)) {
        sectionExamples.set(row.Section, citation);
      }
    }
  }
  const ordered = new Map(
    [...sectionExamples.values(), ...linked.values()].map(citation => [citationKey(citation), citation]),
  );
  const evidenceCitations = [...ordered.values()].slice(0, 30);
  const dataSupported = evidenceCitations.length > 0;
  const hindi = /[\u0900-\u097f]/.test(question);
  const unavailable = hindi
    ? 'अपलोड किए गए रिकॉर्ड इस सवाल का जवाब देने के लिए पर्याप्त नहीं हैं।'
    : 'The uploaded records do not support an answer to this question.';
  const summarySections = finding?.intent === 'summary' && dataSupported
    ? finding.rows.flatMap(row => typeof row.Section === 'string' && typeof row.Finding === 'string'
      ? [`${row.Section} — ${row.Finding}`] : [])
    : [];
  const answer = dataSupported && finding
    ? [hindi ? 'रिकॉर्ड पर आधारित विश्लेषण' : '', finding.summary, ...summarySections].filter(Boolean).join('\n\n')
    : [unavailable, finding && finding.evidence.length === 0 ? finding.summary : ''].filter(Boolean).join(' ');

  const suggestedFilters: AiQueryResponse['suggestedFilters'] = [];
  const followUpQuestions: string[] = [];
  const [suspectPhone, comparePhone] = finding?.subjects ?? [];
  if (dataSupported && finding && suspectPhone) {
    const knownSubjects = new Set(caseFile.suspects.map(person => person.phone));
    const hasCalls = caseFile.cdrs.some(row => isVoiceCall(row) && (row.caller === suspectPhone || row.callee === suspectPhone));
    const hasTower = caseFile.cdrs.some(row => row.observedMsisdn === suspectPhone && row.cellTowerId)
      || caseFile.ipdrs.some(row => row.msisdn === suspectPhone && row.cellTowerId);
    if (finding.intent === 'common' && comparePhone && knownSubjects.has(suspectPhone) && knownSubjects.has(comparePhone)) {
      suggestedFilters.push({ label: 'Open shared contacts', targetView: 'network', suspectPhone, comparePhone, nightOnly: finding.night_only });
    }
    if (hasCalls) {
      if (knownSubjects.has(suspectPhone)) {
        suggestedFilters.push({ label: 'Open contact activity', targetView: 'contacts', suspectPhone, nightOnly: finding.night_only });
      }
      if (finding.intent !== 'night') followUpQuestions.push(`Show night activity for ${suspectPhone}.`);
      else followUpQuestions.push(`Show top contacts for ${suspectPhone}.`);
    }
    if (hasTower) {
      if (knownSubjects.has(suspectPhone)) {
        suggestedFilters.push({ label: 'Open tower timeline', targetView: 'map', suspectPhone });
      }
      if (finding.intent !== 'movement') followUpQuestions.push(`Show the tower timeline for ${suspectPhone}.`);
    }
    if (finding.intent !== 'device' && (
        caseFile.cdrs.some(row => row.observedMsisdn === suspectPhone && (row.imei || row.imsi || row.iccid))
        || caseFile.ipdrs.some(row => row.msisdn === suspectPhone && (row.imei || row.imsi || row.iccid)))) {
      followUpQuestions.push(`Show IMEI and SIM changes for ${suspectPhone}.`);
    }
  }

  return {
    answer, dataSupported, language: hindi ? 'hi' : 'en', evidenceCitations,
    limitationsNote: linked.size > evidenceCitations.length
      ? `Showing the first ${evidenceCitations.length} of ${linked.size} cited records. Narrow the question to inspect more specific evidence.`
      : undefined,
    suggestedFilters, followUpQuestions, modelUsed: 'Local intent model + evidence rules',
  };
}
