export type OfficerRole = 'investigator' | 'reviewer' | 'admin';

export interface OfficerSession {
  id: string;
  username: string;
  displayName: string;
  badgeNumber: string;
  role: OfficerRole;
  unit: string;
}

export type DatasetType = 'cdr' | 'ipdr' | 'towers' | 'suspects';

export type OperatorPreset =
  | 'Jio 5G'
  | 'Airtel'
  | 'Vi'
  | 'BSNL'
  | 'Carrier IPDR'
  | 'Cell Tower Dump'
  | 'Suspect Registry'
  | 'Custom';

export interface EvidenceSource {
  id: string;
  fileName: string;
  datasetType: DatasetType;
  operator: string;
  uploadedAt: string;
  uploadedBy: string;
  sha256: string;
  rowCount: number;
  validRowCount: number;
  rejectedRowCount: number;
  missingFieldCounts: Record<string, number>;
  columnMapping: Record<string, string>;
  sampleWarnings: ValidationIssue[];
}

export interface ValidationIssue {
  rowNumber: number;
  field: string;
  severity: 'error' | 'warning';
  message: string;
  rawValue?: string;
}

export interface CdrRecord {
  id: string;
  sourceId: string;
  sourceFile: string;
  rowNumber: number;
  operator: string;
  timestampIso: string; // Normalized IST ISO string e.g. 2026-01-14T02:01:01+05:30
  epochMs: number;
  istHour: number; // 0..23 in IST
  isNight: boolean; // 00:00..05:59 IST
  caller: string; // Normalized +91XXXXXXXXXX
  callee: string; // Normalized +91XXXXXXXXXX
  observedMsisdn: string;
  callType: 'VOICE_OUT' | 'VOICE_IN' | 'SMS_OUT' | 'SMS_IN' | 'CALL';
  durationSec: number;
  imei?: string;
  imsi?: string;
  iccid?: string;
  cellTowerId?: string;
  rawFields?: Record<string, string>;
}

export interface IpdrRecord {
  id: string;
  sourceId: string;
  sourceFile: string;
  rowNumber: number;
  operator: string;
  sessionStartIso: string;
  sessionStartMs: number;
  sessionEndIso?: string;
  sessionEndMs?: number;
  isPointObservation: boolean;
  msisdn: string;
  imei?: string;
  imsi?: string;
  iccid?: string;
  publicIp: string;
  sourcePort?: number;
  allocPortStart?: number;
  allocPortEnd?: number;
  protocol: string;
  cellTowerId?: string;
  application?: string;
  service?: string;
  destinationHost?: string;
  sessionDurationSec?: number;
  rawFields?: Record<string, string>;
}

export interface CellTower {
  towerId: string;
  towerName: string;
  lat: number;
  lon: number;
  azimuthDegrees: number;
  sectorRadiusMeters?: number;
  sourceFile?: string;
  rowNumber?: number;
}

export interface SuspectProfile {
  suspectId: string;
  name: string;
  phone: string;
  knownImeis: string[];
  baseLocation: string;
  priorFirs: string[];
  roleLabel?: string;
  sourceFile?: string;
  rowNumber?: number;
}

export interface EvidenceCitation {
  sourceFile: string;
  rowNumber: number;
  recordId: string;
  recordType: 'cdr' | 'ipdr' | 'tower' | 'suspect';
  timestamp?: string;
  numbers?: string[];
  summary: string;
}

export interface VerifiedFinding {
  id: string;
  caseId: string;
  title: string;
  summary: string;
  source: 'ai_assistant' | 'manual_pin' | 'automated_rule';
  status: 'pending_review' | 'verified' | 'rejected';
  createdBy: string;
  createdAt: string;
  reviewedBy?: string;
  reviewedAt?: string;
  reviewerNote?: string;
  citations: EvidenceCitation[];
}

export interface AuditLogEntry {
  id: string;
  caseId: string;
  timestamp: string;
  actor: string;
  role: OfficerRole;
  action:
    | 'LOGIN'
    | 'ROLE_SWITCH'
    | 'CASE_CREATE'
    | 'EVIDENCE_IMPORT'
    | 'EVIDENCE_VIEW'
    | 'AI_QUERY'
    | 'IPDR_LOOKUP'
    | 'FINDING_PIN'
    | 'FINDING_VERIFY'
    | 'REPORT_EXPORT';
  detail: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface CaseFile {
  id: string;
  caseNumber: string;
  title: string;
  station: string;
  brief: string;
  createdAt: string;
  createdBy: string;
  status: 'Active' | 'Under Review' | 'Archived';
  sources: EvidenceSource[];
  suspects: SuspectProfile[];
  towers: CellTower[];
  cdrs: CdrRecord[];
  ipdrs: IpdrRecord[];
  findings: VerifiedFinding[];
}

export interface ContactPatternRow {
  contactNumber: string;
  contactName?: string;
  isSuspect: boolean;
  totalCalls: number;
  outgoingCalls: number;
  incomingCalls: number;
  totalDurationSec: number;
  avgDurationSec: number;
  nightCalls: number;
  firstContactIso: string;
  lastContactIso: string;
  operators: string[];
  anomalies: string[];
  records: CdrRecord[];
}

export interface ContactAnalysisResult {
  targetNumber: string;
  targetName?: string;
  totalCalls: number;
  outgoingCalls: number;
  incomingCalls: number;
  totalDurationSec: number;
  nightCalls: number;
  nightRatioPct: number;
  uniqueContacts: number;
  firstActivityIso?: string;
  lastActivityIso?: string;
  hourlyDistribution: Array<{ hour: number; label: string; total: number; night: boolean }>;
  contacts: ContactPatternRow[];
  unusualPatterns: Array<{
    title: string;
    detail: string;
    severity: 'warning' | 'alert';
    citations: EvidenceCitation[];
  }>;
}

export interface CommonContactEntry {
  contactNumber: string;
  contactName?: string;
  connectedSuspects: string[];
  totalSharedCalls: number;
  totalDurationSec: number;
  nightCalls: number;
  perSuspectCounts: Record<string, number>;
  citations: EvidenceCitation[];
}

export interface NetworkNode {
  id: string;
  label: string;
  phone: string;
  isSuspect: boolean;
  isSharedBridge: boolean;
  totalCalls: number;
  nightCalls: number;
  totalDurationSec: number;
  degree: number;
}

export interface NetworkEdge {
  source: string;
  target: string;
  callCount: number;
  totalDurationSec: number;
  nightCalls: number;
  operators: string[];
  sampleCitations: EvidenceCitation[];
}

export interface TowerTimelineStep {
  index: number;
  timestampIso: string;
  epochMs: number;
  towerId: string;
  towerName: string;
  lat?: number;
  lon?: number;
  azimuthDegrees?: number;
  recordId: string;
  sourceFile: string;
  rowNumber: number;
  operator: string;
  counterpart: string;
  durationSec: number;
  isNight: boolean;
  imei?: string;
  distanceFromPrevKm?: number;
  impliedSpeedKmh?: number;
  speedAnomaly?: boolean;
  isTransition: boolean;
}

export interface DeviceChangeEvent {
  id: string;
  msisdn: string;
  suspectName?: string;
  changeType: 'IMEI_CHANGE' | 'SIM_SWAP_IMSI' | 'SIM_SWAP_ICCID';
  previousValue: string;
  newValue: string;
  previousTimestampIso: string;
  newTimestampIso: string;
  previousCitation: EvidenceCitation;
  newCitation: EvidenceCitation;
}

export interface SharedDeviceAlert {
  imei: string;
  msisdns: Array<{ phone: string; name?: string; count: number; firstIso: string; lastIso: string }>;
  citations: EvidenceCitation[];
}

export type IpdrMatchStatus =
  | 'EXACT_MATCH'
  | 'OVERLAP_AMBIGUOUS'
  | 'TOLERANCE_MATCH'
  | 'OUT_OF_WINDOW';

export interface IpdrLookupMatch {
  record: IpdrRecord;
  suspectName?: string;
  status: IpdrMatchStatus;
  portMatchType: 'EXACT_SOURCE_PORT' | 'ALLOCATION_BLOCK' | 'ANY_PORT';
  timeDeltaSec: number;
  explanation: string;
  citation: EvidenceCitation;
}

export interface AiQueryResponse {
  answer: string;
  language: 'en' | 'hi' | 'hinglish';
  dataSupported: boolean;
  limitationsNote?: string;
  evidenceCitations: EvidenceCitation[];
  suggestedFilters: Array<{
    label: string;
    targetView: 'contacts' | 'network' | 'map' | 'ipdr';
    suspectPhone?: string;
    nightOnly?: boolean;
  }>;
  followUpQuestions: string[];
  modelUsed: string;
}
