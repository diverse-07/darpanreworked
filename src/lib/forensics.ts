import type {
  CaseFile,
  CdrRecord,
  CellTower,
  CommonContactEntry,
  ContactAnalysisResult,
  ContactPatternRow,
  DeviceChangeEvent,
  EvidenceCitation,
  IpdrLookupMatch,
  IpdrRecord,
  NetworkEdge,
  NetworkNode,
  SharedDeviceAlert,
  SuspectProfile,
  TowerTimelineStep,
} from '../types/forensics.ts';

const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;

/**
 * Normalizes Indian and international phone numbers to canonical E.164-like form.
 * Handles spaces, dashes, leading 0, 10-digit Indian mobiles, and +91 prefixes.
 */
export function normalizePhoneNumber(raw: string | undefined | null): string {
  if (!raw) return '';
  const trimmed = String(raw).trim();
  if (!trimmed) return '';
  const hasPlus = trimmed.startsWith('+');
  const digits = trimmed.replace(/\D/g, '');
  if (!digits) return '';
  if (digits.length === 10 && /^[6-9]/.test(digits)) {
    return `+91${digits}`;
  }
  if (digits.length === 11 && digits.startsWith('0') && /^[6-9]/.test(digits.slice(1))) {
    return `+91${digits.slice(1)}`;
  }
  if (digits.length === 12 && digits.startsWith('91')) {
    return `+${digits}`;
  }
  return hasPlus ? `+${digits}` : `+${digits}`;
}

/**
 * Parses timestamps in ISO-8601 (with or without offset), Indian DD/MM/YYYY + HH:MM:SS,
 * DD-MM-YYYY, or YYYY-MM-DD HH:MM:SS formats, normalizing to IST (+05:30).
 */
export function parseTimestampIST(
  timestampRaw?: string,
  dateRaw?: string,
  timeRaw?: string
): { iso: string; epochMs: number; istHour: number; isNight: boolean } | null {
  let epochMs: number | null = null;

  const combined =
    timestampRaw && timestampRaw.trim()
      ? timestampRaw.trim()
      : dateRaw && dateRaw.trim()
        ? `${dateRaw.trim()} ${(timeRaw || '00:00:00').trim()}`.trim()
        : '';

  if (!combined) return null;

  // 1. Check DD/MM/YYYY or DD-MM-YYYY with optional HH:MM:SS(.mmm)
  const dmyMatch = combined.match(
    /^(\d{1,2})[/-](\d{1,2})[/-](\d{4})(?:[T\s]+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?)?$/
  );
  if (dmyMatch) {
    const day = Number(dmyMatch[1]);
    const month = Number(dmyMatch[2]);
    const year = Number(dmyMatch[3]);
    const hour = Number(dmyMatch[4] ?? 0);
    const minute = Number(dmyMatch[5] ?? 0);
    const second = Number(dmyMatch[6] ?? 0);
    const ms = Number((dmyMatch[7] ?? '0').padEnd(3, '0'));
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
      return null;
    }
    const utcMs = Date.UTC(year, month - 1, day, hour, minute, second, ms) - IST_OFFSET_MS;
    epochMs = utcMs;
  }

  // 2. Check ISO-8601 or YYYY-MM-DD HH:MM:SS
  if (epochMs === null) {
    let normalized = combined;
    if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}/.test(normalized)) {
      normalized = normalized.replace(/\s+/, 'T');
    }
    // If no timezone designator present, treat as IST (+05:30)
    if (
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(normalized) &&
      !/([zZ]|[+-]\d{2}:?\d{2})$/.test(normalized)
    ) {
      normalized = `${normalized}+05:30`;
    }
    const parsed = Date.parse(normalized);
    if (!Number.isNaN(parsed)) {
      epochMs = parsed;
    }
  }

  if (epochMs === null || Number.isNaN(epochMs)) return null;

  const istDate = new Date(epochMs + IST_OFFSET_MS);
  const yyyy = istDate.getUTCFullYear();
  const mm = String(istDate.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(istDate.getUTCDate()).padStart(2, '0');
  const hh = String(istDate.getUTCHours()).padStart(2, '0');
  const mi = String(istDate.getUTCMinutes()).padStart(2, '0');
  const ss = String(istDate.getUTCSeconds()).padStart(2, '0');
  const istHour = istDate.getUTCHours();

  return {
    iso: `${yyyy}-${mm}-${dd}T${hh}:${mi}:${ss}+05:30`,
    epochMs,
    istHour,
    isNight: istHour >= 0 && istHour < 6,
  };
}

export function formatISTDisplay(iso: string | undefined): string {
  if (!iso) return '—';
  const match = iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})/);
  if (!match) return iso;
  return `${match[3]}/${match[2]}/${match[1]} ${match[4]} IST`;
}

export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  const hrs = Math.floor(s / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const rem = s % 60;
  if (hrs > 0) return `${hrs}h ${mins}m ${rem}s`;
  if (mins > 0) return `${mins}m ${rem}s`;
  return `${rem}s`;
}

export function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

export function cdrToCitation(r: CdrRecord): EvidenceCitation {
  return {
    sourceFile: r.sourceFile,
    rowNumber: r.rowNumber,
    recordId: r.id,
    recordType: 'cdr',
    timestamp: r.timestampIso,
    numbers: [r.caller, r.callee],
    summary: `${r.operator} call ${r.caller} -> ${r.callee} (${r.durationSec}s${r.cellTowerId ? `, Tower ${r.cellTowerId}` : ''})`,
  };
}

export function ipdrToCitation(r: IpdrRecord): EvidenceCitation {
  return {
    sourceFile: r.sourceFile,
    rowNumber: r.rowNumber,
    recordId: r.id,
    recordType: 'ipdr',
    timestamp: r.sessionStartIso,
    numbers: [r.msisdn],
    summary: `${r.operator} IPDR ${r.publicIp}:${r.sourcePort ?? '?'} (${r.protocol}) -> ${r.msisdn}${r.application ? ` [${r.application}]` : ''}`,
  };
}

export interface AnalysisFilters {
  startIso?: string;
  endIso?: string; // Exclusive end per Darpan specification
  nightOnly?: boolean;
  operator?: string;
}

export function filterCdrs(cdrs: CdrRecord[], filters?: AnalysisFilters): CdrRecord[] {
  if (!filters) return cdrs;
  const startMs = filters.startIso ? parseTimestampIST(filters.startIso)?.epochMs : undefined;
  const endMs = filters.endIso ? parseTimestampIST(filters.endIso)?.epochMs : undefined;

  return cdrs.filter((r) => {
    if (startMs !== undefined && r.epochMs < startMs) return false;
    if (endMs !== undefined && r.epochMs >= endMs) return false;
    if (filters.nightOnly && !r.isNight) return false;
    if (filters.operator && filters.operator !== 'ALL' && r.operator !== filters.operator) {
      return false;
    }
    return true;
  });
}

export function isVoiceCall(record: CdrRecord): boolean {
  return record.callType !== 'SMS_IN' && record.callType !== 'SMS_OUT';
}

/**
 * Analyzes communication patterns for a specific MSISDN (or entire case if targetNumber is 'ALL').
 */
export function analyzeContactPatterns(
  cdrs: CdrRecord[],
  suspects: SuspectProfile[],
  targetNumber: string,
  filters?: AnalysisFilters
): ContactAnalysisResult {
  const suspectByPhone = new Map<string, SuspectProfile>();
  for (const s of suspects) {
    suspectByPhone.set(normalizePhoneNumber(s.phone), s);
  }

  const normalizedTarget = targetNumber === 'ALL' ? 'ALL' : normalizePhoneNumber(targetNumber);
  const filtered = filterCdrs(cdrs, filters).filter((r) => {
    if (!isVoiceCall(r)) return false;
    if (normalizedTarget === 'ALL') return true;
    return r.caller === normalizedTarget || r.callee === normalizedTarget;
  });

  const sorted = [...filtered].sort((a, b) => a.epochMs - b.epochMs);

  const hourlyDistribution = Array.from({ length: 24 }, (_, hour) => ({
    hour,
    label: `${String(hour).padStart(2, '0')}:00`,
    total: 0,
    night: hour < 6,
  }));

  const contactMap = new Map<
    string,
    {
      totalCalls: number;
      outgoingCalls: number;
      incomingCalls: number;
      totalDurationSec: number;
      nightCalls: number;
      firstContactIso: string;
      lastContactIso: string;
      operators: Set<string>;
      records: CdrRecord[];
    }
  >();

  let outgoingCalls = 0;
  let incomingCalls = 0;
  let totalDurationSec = 0;
  let nightCalls = 0;

  for (const r of sorted) {
    hourlyDistribution[r.istHour].total += 1;
    totalDurationSec += r.durationSec;
    if (r.isNight) nightCalls += 1;

    const subject = normalizedTarget === 'ALL'
      ? (r.observedMsisdn === r.callee ? r.callee : r.caller)
      : normalizedTarget;
    const isOutgoing = r.caller === subject;
    if (isOutgoing) outgoingCalls += 1;
    else incomingCalls += 1;

    const counterpart = isOutgoing ? r.callee : r.caller;

    const existing = contactMap.get(counterpart);
    if (!existing) {
      contactMap.set(counterpart, {
        totalCalls: 1,
        outgoingCalls: isOutgoing ? 1 : 0,
        incomingCalls: isOutgoing ? 0 : 1,
        totalDurationSec: r.durationSec,
        nightCalls: r.isNight ? 1 : 0,
        firstContactIso: r.timestampIso,
        lastContactIso: r.timestampIso,
        operators: new Set([r.operator]),
        records: [r],
      });
    } else {
      existing.totalCalls += 1;
      if (isOutgoing) existing.outgoingCalls += 1;
      else existing.incomingCalls += 1;
      existing.totalDurationSec += r.durationSec;
      if (r.isNight) existing.nightCalls += 1;
      if (r.timestampIso < existing.firstContactIso) existing.firstContactIso = r.timestampIso;
      if (r.timestampIso > existing.lastContactIso) existing.lastContactIso = r.timestampIso;
      existing.operators.add(r.operator);
      existing.records.push(r);
    }
  }

  const contacts: ContactPatternRow[] = Array.from(contactMap.entries())
    .map(([contactNumber, agg]) => {
      const profile = suspectByPhone.get(contactNumber);
      const anomalies: string[] = [];
      const nightShare = agg.totalCalls > 0 ? agg.nightCalls / agg.totalCalls : 0;
      if (agg.nightCalls >= 3 && nightShare >= 0.5) {
        anomalies.push(`Heavy night activity (${Math.round(nightShare * 100)}% between 00:00–06:00 IST)`);
      }
      if (agg.totalCalls >= 4 && (agg.incomingCalls === 0 || agg.outgoingCalls === 0)) {
        anomalies.push(
          agg.incomingCalls === 0 ? 'Strictly one-way outgoing' : 'Strictly one-way incoming'
        );
      }
      const shortCalls = agg.records.filter((rec) => rec.durationSec > 0 && rec.durationSec <= 15).length;
      if (shortCalls >= 3) {
        anomalies.push(`${shortCalls} brief burst calls (<=15s)`);
      }
      return {
        contactNumber,
        contactName: profile?.name,
        isSuspect: Boolean(profile),
        totalCalls: agg.totalCalls,
        outgoingCalls: agg.outgoingCalls,
        incomingCalls: agg.incomingCalls,
        totalDurationSec: agg.totalDurationSec,
        avgDurationSec: agg.totalCalls > 0 ? Math.round(agg.totalDurationSec / agg.totalCalls) : 0,
        nightCalls: agg.nightCalls,
        firstContactIso: agg.firstContactIso,
        lastContactIso: agg.lastContactIso,
        operators: Array.from(agg.operators),
        anomalies,
        records: agg.records,
      };
    })
    .sort((a, b) => b.totalCalls - a.totalCalls || b.totalDurationSec - a.totalDurationSec);

  const unusualPatterns: ContactAnalysisResult['unusualPatterns'] = [];

  // Check concentrated nocturnal window
  const nightRatioPct = sorted.length > 0 ? Math.round((nightCalls / sorted.length) * 100) : 0;
  if (nightCalls >= 5 && nightRatioPct >= 40) {
    const nightSample = sorted.filter((r) => r.isNight).slice(0, 4).map(cdrToCitation);
    unusualPatterns.push({
      title: 'Concentrated Nocturnal Activity (00:00–06:00 IST)',
      detail: `${nightCalls} of ${sorted.length} calls (${nightRatioPct}%) occurred during late-night hours.`,
      severity: 'alert',
      citations: nightSample,
    });
  }

  // Check rapid call bursts (>= 5 calls within 10 minutes)
  for (let i = 0; i < sorted.length; i++) {
    let j = i;
    while (j < sorted.length && sorted[j].epochMs - sorted[i].epochMs <= 10 * 60 * 1000) {
      j++;
    }
    const burstSize = j - i;
    if (burstSize >= 6) {
      unusualPatterns.push({
        title: 'High-Frequency Rapid Call Burst',
        detail: `${burstSize} consecutive calls logged within a 10-minute window starting ${formatISTDisplay(sorted[i].timestampIso)}.`,
        severity: 'warning',
        citations: sorted.slice(i, Math.min(i + 4, j)).map(cdrToCitation),
      });
      break;
    }
  }

  const targetProfile =
    normalizedTarget !== 'ALL' ? suspectByPhone.get(normalizedTarget) : undefined;

  return {
    targetNumber: normalizedTarget,
    targetName: targetProfile?.name,
    totalCalls: sorted.length,
    outgoingCalls,
    incomingCalls,
    totalDurationSec,
    nightCalls,
    nightRatioPct,
    uniqueContacts: contacts.length,
    firstActivityIso: sorted[0]?.timestampIso,
    lastActivityIso: sorted[sorted.length - 1]?.timestampIso,
    hourlyDistribution,
    contacts,
    unusualPatterns,
  };
}

/**
 * Cross-suspect correlation: finds shared third-party contacts contacted by 2+ selected suspects,
 * as well as direct calls between the selected suspects.
 */
export function findCommonContacts(
  cdrs: CdrRecord[],
  suspects: SuspectProfile[],
  selectedPhones: string[],
  filters?: AnalysisFilters
): {
  sharedContacts: CommonContactEntry[];
  directLinks: Array<{
    from: string;
    to: string;
    callCount: number;
    totalDurationSec: number;
    nightCalls: number;
    citations: EvidenceCitation[];
  }>;
} {
  const normalizedSelected = Array.from(
    new Set(selectedPhones.map(normalizePhoneNumber).filter(Boolean))
  );
  const selectedSet = new Set(normalizedSelected);
  const suspectByPhone = new Map<string, SuspectProfile>();
  for (const s of suspects) {
    suspectByPhone.set(normalizePhoneNumber(s.phone), s);
  }

  const filtered = filterCdrs(cdrs, filters).filter(isVoiceCall);

  const thirdPartyMap = new Map<
    string,
    {
      suspects: Set<string>;
      perSuspectCounts: Record<string, number>;
      totalDurationSec: number;
      nightCalls: number;
      records: CdrRecord[];
    }
  >();

  const directMap = new Map<
    string,
    {
      from: string;
      to: string;
      callCount: number;
      totalDurationSec: number;
      nightCalls: number;
      records: CdrRecord[];
    }
  >();

  for (const r of filtered) {
    const callerIn = selectedSet.has(r.caller);
    const calleeIn = selectedSet.has(r.callee);

    if (callerIn && calleeIn && r.caller !== r.callee) {
      const pairKey = [r.caller, r.callee].sort().join('||');
      const existing = directMap.get(pairKey);
      if (!existing) {
        directMap.set(pairKey, {
          from: r.caller,
          to: r.callee,
          callCount: 1,
          totalDurationSec: r.durationSec,
          nightCalls: r.isNight ? 1 : 0,
          records: [r],
        });
      } else {
        existing.callCount += 1;
        existing.totalDurationSec += r.durationSec;
        if (r.isNight) existing.nightCalls += 1;
        existing.records.push(r);
      }
    } else if (callerIn !== calleeIn) {
      const suspectPhone = callerIn ? r.caller : r.callee;
      const thirdParty = callerIn ? r.callee : r.caller;
      const existing = thirdPartyMap.get(thirdParty);
      if (!existing) {
        thirdPartyMap.set(thirdParty, {
          suspects: new Set([suspectPhone]),
          perSuspectCounts: { [suspectPhone]: 1 },
          totalDurationSec: r.durationSec,
          nightCalls: r.isNight ? 1 : 0,
          records: [r],
        });
      } else {
        existing.suspects.add(suspectPhone);
        existing.perSuspectCounts[suspectPhone] =
          (existing.perSuspectCounts[suspectPhone] ?? 0) + 1;
        existing.totalDurationSec += r.durationSec;
        if (r.isNight) existing.nightCalls += 1;
        existing.records.push(r);
      }
    }
  }

  const sharedContacts: CommonContactEntry[] = Array.from(thirdPartyMap.entries())
    .filter(([, agg]) => agg.suspects.size >= 2)
    .map(([contactNumber, agg]) => ({
      contactNumber,
      contactName: suspectByPhone.get(contactNumber)?.name,
      connectedSuspects: Array.from(agg.suspects),
      totalSharedCalls: agg.records.length,
      totalDurationSec: agg.totalDurationSec,
      nightCalls: agg.nightCalls,
      perSuspectCounts: agg.perSuspectCounts,
      citations: agg.records.slice(0, 8).map(cdrToCitation),
    }))
    .sort((a, b) => b.connectedSuspects.length - a.connectedSuspects.length || b.totalSharedCalls - a.totalSharedCalls);

  const directLinks = Array.from(directMap.values())
    .map((d) => ({
      from: d.from,
      to: d.to,
      callCount: d.callCount,
      totalDurationSec: d.totalDurationSec,
      nightCalls: d.nightCalls,
      citations: d.records.slice(0, 8).map(cdrToCitation),
    }))
    .sort((a, b) => b.callCount - a.callCount);

  return { sharedContacts, directLinks };
}

/**
 * Builds an undirected weighted communication network graph for visual exploration.
 */
export function buildNetworkGraph(
  cdrs: CdrRecord[],
  suspects: SuspectProfile[],
  filters?: AnalysisFilters
): { nodes: NetworkNode[]; edges: NetworkEdge[] } {
  const suspectByPhone = new Map<string, SuspectProfile>();
  for (const s of suspects) {
    suspectByPhone.set(normalizePhoneNumber(s.phone), s);
  }
  const filtered = filterCdrs(cdrs, filters).filter(isVoiceCall);

  const nodeStats = new Map<
    string,
    { totalCalls: number; nightCalls: number; totalDurationSec: number; neighbors: Set<string>; suspectNeighbors: Set<string> }
  >();
  const edgeMap = new Map<
    string,
    {
      source: string;
      target: string;
      callCount: number;
      totalDurationSec: number;
      nightCalls: number;
      operators: Set<string>;
      records: CdrRecord[];
    }
  >();

  const ensureNode = (phone: string) => {
    if (!nodeStats.has(phone)) {
      nodeStats.set(phone, {
        totalCalls: 0,
        nightCalls: 0,
        totalDurationSec: 0,
        neighbors: new Set(),
        suspectNeighbors: new Set(),
      });
    }
    return nodeStats.get(phone)!;
  };

  for (const r of filtered) {
    if (!r.caller || !r.callee || r.caller === r.callee) continue;
    const n1 = ensureNode(r.caller);
    const n2 = ensureNode(r.callee);
    n1.totalCalls += 1;
    n2.totalCalls += 1;
    n1.totalDurationSec += r.durationSec;
    n2.totalDurationSec += r.durationSec;
    if (r.isNight) {
      n1.nightCalls += 1;
      n2.nightCalls += 1;
    }
    n1.neighbors.add(r.callee);
    n2.neighbors.add(r.caller);
    if (suspectByPhone.has(r.callee)) n1.suspectNeighbors.add(r.callee);
    if (suspectByPhone.has(r.caller)) n2.suspectNeighbors.add(r.caller);

    const [a, b] = [r.caller, r.callee].sort();
    const key = `${a}||${b}`;
    const edge = edgeMap.get(key);
    if (!edge) {
      edgeMap.set(key, {
        source: a,
        target: b,
        callCount: 1,
        totalDurationSec: r.durationSec,
        nightCalls: r.isNight ? 1 : 0,
        operators: new Set([r.operator]),
        records: [r],
      });
    } else {
      edge.callCount += 1;
      edge.totalDurationSec += r.durationSec;
      if (r.isNight) edge.nightCalls += 1;
      edge.operators.add(r.operator);
      edge.records.push(r);
    }
  }

  const nodes: NetworkNode[] = Array.from(nodeStats.entries())
    .map(([phone, st]) => {
      const profile = suspectByPhone.get(phone);
      return {
        id: phone,
        label: profile ? profile.name : phone,
        phone,
        isSuspect: Boolean(profile),
        isSharedBridge: !profile && st.suspectNeighbors.size >= 2,
        totalCalls: st.totalCalls,
        nightCalls: st.nightCalls,
        totalDurationSec: st.totalDurationSec,
        degree: st.neighbors.size,
      };
    })
    .sort((a, b) => Number(b.isSuspect) - Number(a.isSuspect) || b.totalCalls - a.totalCalls);

  const edges: NetworkEdge[] = Array.from(edgeMap.values())
    .map((e) => ({
      source: e.source,
      target: e.target,
      callCount: e.callCount,
      totalDurationSec: e.totalDurationSec,
      nightCalls: e.nightCalls,
      operators: Array.from(e.operators),
      sampleCitations: e.records.slice(0, 6).map(cdrToCitation),
    }))
    .sort((a, b) => b.callCount - a.callCount);

  return { nodes, edges };
}

/**
 * Builds chronological cell-tower movement timeline for a target MSISDN.
 * Attaches tower observations strictly where observedMsisdn === target (prevents attributing
 * the counterpart's tower to the suspect).
 */
export function buildTowerTimeline(
  cdrs: CdrRecord[],
  towers: CellTower[],
  targetNumber: string,
  filters?: AnalysisFilters,
  ipdrs: IpdrRecord[] = [],
): {
  steps: TowerTimelineStep[];
  towerSummary: Array<{
    towerId: string;
    towerName: string;
    lat?: number;
    lon?: number;
    azimuthDegrees?: number;
    hitCount: number;
    nightHits: number;
    firstSeenIso: string;
    lastSeenIso: string;
  }>;
  transitions: number;
  maxImpliedSpeedKmh: number;
} {
  const normalizedTarget = normalizePhoneNumber(targetNumber);
  const towerMap = new Map<string, CellTower>();
  for (const t of towers) {
    towerMap.set(t.towerId.toUpperCase(), t);
  }

  const callObservations = filterCdrs(cdrs, filters)
    .filter(row => row.cellTowerId && row.observedMsisdn === normalizedTarget)
    .map(row => ({ ...row, citation: cdrToCitation(row), counterpart: row.caller === normalizedTarget ? row.callee : row.caller }));
  const startMs = filters?.startIso ? parseTimestampIST(filters.startIso)?.epochMs : undefined;
  const endMs = filters?.endIso ? parseTimestampIST(filters.endIso)?.epochMs : undefined;
  const sessionObservations = ipdrs.flatMap(row => {
    if (!row.cellTowerId || row.msisdn !== normalizedTarget) return [];
    const epochMs = row.sessionStartMs;
    const isNight = new Date(epochMs + IST_OFFSET_MS).getUTCHours() < 6;
    if ((filters?.nightOnly && !isNight) ||
        (startMs !== undefined && epochMs < startMs) ||
        (endMs !== undefined && epochMs >= endMs) ||
        (filters?.operator && filters.operator !== 'ALL' && filters.operator !== row.operator)) return [];
    return [{
      ...row, epochMs, isNight, timestampIso: row.sessionStartIso,
      citation: ipdrToCitation(row), counterpart: row.publicIp, durationSec: row.sessionDurationSec ?? 0,
    }];
  });
  const relevant = [...callObservations, ...sessionObservations].sort((a, b) => a.epochMs - b.epochMs);

  const steps: TowerTimelineStep[] = [];
  const summaryMap = new Map<
    string,
    {
      towerId: string;
      towerName: string;
      lat?: number;
      lon?: number;
      azimuthDegrees?: number;
      hitCount: number;
      nightHits: number;
      firstSeenIso: string;
      lastSeenIso: string;
    }
  >();

  let transitions = 0;
  let maxImpliedSpeedKmh = 0;

  for (let i = 0; i < relevant.length; i++) {
    const r = relevant[i];
    const towerId = r.cellTowerId!;
    const meta = towerMap.get(towerId.toUpperCase());
    const prev = steps[steps.length - 1];
    const isTransition = Boolean(prev && prev.towerId !== towerId);
    if (isTransition) transitions += 1;

    let distanceFromPrevKm: number | undefined;
    let impliedSpeedKmh: number | undefined;
    let speedAnomaly = false;

    if (
      prev &&
      isTransition &&
      meta &&
      prev.lat !== undefined &&
      prev.lon !== undefined
    ) {
      distanceFromPrevKm = Number(haversineKm(prev.lat, prev.lon, meta.lat, meta.lon).toFixed(2));
      const dtHours = (r.epochMs - prev.epochMs) / (1000 * 3600);
      if (dtHours > 0) {
        impliedSpeedKmh = Math.round(distanceFromPrevKm / dtHours);
        if (impliedSpeedKmh > maxImpliedSpeedKmh) maxImpliedSpeedKmh = impliedSpeedKmh;
        if (impliedSpeedKmh > 120 && distanceFromPrevKm > 1.5) {
          speedAnomaly = true;
        }
      }
    }

    steps.push({
      index: i + 1,
      timestampIso: r.timestampIso,
      epochMs: r.epochMs,
      towerId,
      towerName: meta?.towerName ?? `Unmapped Tower (${towerId})`,
      lat: meta?.lat,
      lon: meta?.lon,
      azimuthDegrees: meta?.azimuthDegrees,
      recordId: r.id,
      citation: r.citation,
      sourceFile: r.sourceFile,
      rowNumber: r.rowNumber,
      operator: r.operator,
      counterpart: r.counterpart,
      durationSec: r.durationSec,
      isNight: r.isNight,
      imei: r.imei,
      distanceFromPrevKm,
      impliedSpeedKmh,
      speedAnomaly,
      isTransition,
    });

    const existing = summaryMap.get(towerId);
    if (!existing) {
      summaryMap.set(towerId, {
        towerId,
        towerName: meta?.towerName ?? `Unmapped Tower (${towerId})`,
        lat: meta?.lat,
        lon: meta?.lon,
        azimuthDegrees: meta?.azimuthDegrees,
        hitCount: 1,
        nightHits: r.isNight ? 1 : 0,
        firstSeenIso: r.timestampIso,
        lastSeenIso: r.timestampIso,
      });
    } else {
      existing.hitCount += 1;
      if (r.isNight) existing.nightHits += 1;
      existing.lastSeenIso = r.timestampIso;
    }
  }

  const towerSummary = Array.from(summaryMap.values()).sort((a, b) => b.hitCount - a.hitCount);
  return { steps, towerSummary, transitions, maxImpliedSpeedKmh };
}

/**
 * Detects chronological IMEI changes, SIM (IMSI / ICCID) swaps per MSISDN,
 * AND cross-suspect shared IMEI handsets across the entire case.
 */
export function detectDeviceSimChanges(
  cdrs: CdrRecord[],
  suspects: SuspectProfile[],
  targetNumber?: string
): {
  changes: DeviceChangeEvent[];
  sharedDevices: SharedDeviceAlert[];
} {
  const suspectByPhone = new Map<string, SuspectProfile>();
  for (const s of suspects) {
    suspectByPhone.set(normalizePhoneNumber(s.phone), s);
  }

  const normalizedTarget =
    targetNumber && targetNumber !== 'ALL' ? normalizePhoneNumber(targetNumber) : undefined;

  const byObserved = new Map<string, CdrRecord[]>();
  const imeiUsage = new Map<
    string,
    Map<string, { count: number; firstIso: string; lastIso: string; records: CdrRecord[] }>
  >();

  for (const r of cdrs) {
    const obs = r.observedMsisdn;
    if (!obs) continue;
    if (!byObserved.has(obs)) byObserved.set(obs, []);
    byObserved.get(obs)!.push(r);

    if (r.imei && r.imei.trim()) {
      const imei = r.imei.trim();
      if (!imeiUsage.has(imei)) imeiUsage.set(imei, new Map());
      const mMap = imeiUsage.get(imei)!;
      const entry = mMap.get(obs);
      if (!entry) {
        mMap.set(obs, {
          count: 1,
          firstIso: r.timestampIso,
          lastIso: r.timestampIso,
          records: [r],
        });
      } else {
        entry.count += 1;
        if (r.timestampIso < entry.firstIso) entry.firstIso = r.timestampIso;
        if (r.timestampIso > entry.lastIso) entry.lastIso = r.timestampIso;
        entry.records.push(r);
      }
    }
  }

  const changes: DeviceChangeEvent[] = [];

  for (const [msisdn, recs] of byObserved.entries()) {
    if (normalizedTarget && msisdn !== normalizedTarget) continue;
    const sorted = [...recs].sort((a, b) => a.epochMs - b.epochMs);
    const suspectName = suspectByPhone.get(msisdn)?.name;

    let lastImeiRec: CdrRecord | undefined;
    let lastImsiRec: CdrRecord | undefined;
    let lastIccidRec: CdrRecord | undefined;

    for (const r of sorted) {
      if (r.imei && r.imei.trim()) {
        if (lastImeiRec && lastImeiRec.imei !== r.imei) {
          changes.push({
            id: `imei-${msisdn}-${r.id}`,
            msisdn,
            suspectName,
            changeType: 'IMEI_CHANGE',
            previousValue: lastImeiRec.imei!,
            newValue: r.imei,
            previousTimestampIso: lastImeiRec.timestampIso,
            newTimestampIso: r.timestampIso,
            previousCitation: cdrToCitation(lastImeiRec),
            newCitation: cdrToCitation(r),
          });
        }
        lastImeiRec = r;
      }

      if (r.imsi && r.imsi.trim()) {
        if (lastImsiRec && lastImsiRec.imsi !== r.imsi) {
          changes.push({
            id: `imsi-${msisdn}-${r.id}`,
            msisdn,
            suspectName,
            changeType: 'SIM_SWAP_IMSI',
            previousValue: lastImsiRec.imsi!,
            newValue: r.imsi,
            previousTimestampIso: lastImsiRec.timestampIso,
            newTimestampIso: r.timestampIso,
            previousCitation: cdrToCitation(lastImsiRec),
            newCitation: cdrToCitation(r),
          });
        }
        lastImsiRec = r;
      }

      if (r.iccid && r.iccid.trim()) {
        if (lastIccidRec && lastIccidRec.iccid !== r.iccid) {
          changes.push({
            id: `iccid-${msisdn}-${r.id}`,
            msisdn,
            suspectName,
            changeType: 'SIM_SWAP_ICCID',
            previousValue: lastIccidRec.iccid!,
            newValue: r.iccid,
            previousTimestampIso: lastIccidRec.timestampIso,
            newTimestampIso: r.timestampIso,
            previousCitation: cdrToCitation(lastIccidRec),
            newCitation: cdrToCitation(r),
          });
        }
        lastIccidRec = r;
      }
    }
  }

  const sharedDevices: SharedDeviceAlert[] = [];
  for (const [imei, mMap] of imeiUsage.entries()) {
    if (mMap.size >= 2) {
      const msisdns = Array.from(mMap.entries()).map(([phone, st]) => ({
        phone,
        name: suspectByPhone.get(phone)?.name,
        count: st.count,
        firstIso: st.firstIso,
        lastIso: st.lastIso,
      }));
      const citations: EvidenceCitation[] = [];
      for (const st of mMap.values()) {
        if (st.records[0]) citations.push(cdrToCitation(st.records[0]));
      }
      sharedDevices.push({ imei, msisdns, citations });
    }
  }

  changes.sort((a, b) => a.newTimestampIso.localeCompare(b.newTimestampIso));
  return { changes, sharedDevices };
}

/**
 * Correlates observed Public IPv4, source port, IST timestamp, tolerance window,
 * and protocol against CGNAT / IPDR allocation records.
 * Distinguishes exact unique matches, overlapping ambiguous matches, tolerance-only
 * matches, and out-of-window rows.
 */
export function correlateIpdrCgnat(
  ipdrs: IpdrRecord[],
  suspects: SuspectProfile[],
  query: {
    publicIp: string;
    sourcePort?: number;
    observedTimeIso: string;
    protocol?: string;
    toleranceSec?: number;
  }
): {
  matches: IpdrLookupMatch[];
  summaryVerdict: string;
  uniqueSubscriber?: { msisdn: string; name?: string; recordId: string };
} {
  const suspectByPhone = new Map<string, SuspectProfile>();
  for (const s of suspects) {
    suspectByPhone.set(normalizePhoneNumber(s.phone), s);
  }

  const ipTrimmed = query.publicIp.trim();
  const parsedTime = parseTimestampIST(query.observedTimeIso);
  const queryMs = parsedTime?.epochMs;
  const toleranceSec = Math.max(0, query.toleranceSec ?? 5);
  const protoUpper = (query.protocol ?? 'ANY').toUpperCase();

  if (!ipTrimmed || queryMs === undefined) {
    return {
      matches: [],
      summaryVerdict: 'Provide a valid public IPv4 address and IST timestamp to run correlation.',
    };
  }

  const candidates = ipdrs.filter((r) => {
    if (r.publicIp.trim() !== ipTrimmed) return false;
    if (protoUpper !== 'ANY' && r.protocol.toUpperCase() !== protoUpper) return false;
    return true;
  });

  const scored: Array<{
    record: IpdrRecord;
    portMatched: boolean;
    portMatchType: 'EXACT_SOURCE_PORT' | 'ALLOCATION_BLOCK' | 'ANY_PORT';
    inExactWindow: boolean;
    inToleranceWindow: boolean;
    timeDeltaSec: number;
  }> = [];

  for (const r of candidates) {
    let portMatched = true;
    let portMatchType: 'EXACT_SOURCE_PORT' | 'ALLOCATION_BLOCK' | 'ANY_PORT' = 'ANY_PORT';
    if (query.sourcePort !== undefined && !Number.isNaN(query.sourcePort)) {
      if (r.sourcePort !== undefined && r.sourcePort === query.sourcePort) {
        portMatched = true;
        portMatchType = 'EXACT_SOURCE_PORT';
      } else if (
        r.allocPortStart !== undefined &&
        r.allocPortEnd !== undefined &&
        query.sourcePort >= r.allocPortStart &&
        query.sourcePort <= r.allocPortEnd
      ) {
        portMatched = true;
        portMatchType = 'ALLOCATION_BLOCK';
      } else {
        portMatched = false;
      }
    }

    if (!portMatched) continue;

    const startMs = r.sessionStartMs;
    const endMs = r.sessionEndMs ?? r.sessionStartMs;
    let timeDeltaSec = 0;
    let inExactWindow = false;
    let inToleranceWindow = false;

    if (queryMs >= startMs && queryMs <= endMs) {
      inExactWindow = true;
      inToleranceWindow = true;
      timeDeltaSec = 0;
    } else {
      const distMs = queryMs < startMs ? startMs - queryMs : queryMs - endMs;
      timeDeltaSec = Number((distMs / 1000).toFixed(3));
      inToleranceWindow = timeDeltaSec <= toleranceSec;
    }

    scored.push({
      record: r,
      portMatched,
      portMatchType,
      inExactWindow,
      inToleranceWindow,
      timeDeltaSec,
    });
  }

  const exactHits = scored.filter((s) => s.inExactWindow);
  const exactDistinctSubs = new Set(exactHits.map((s) => s.record.msisdn));
  const isAmbiguous = exactDistinctSubs.size > 1;

  const matches: IpdrLookupMatch[] = scored
    .map((s) => {
      const suspectName = suspectByPhone.get(s.record.msisdn)?.name;
      let status: IpdrLookupMatch['status'];
      let explanation: string;

      if (s.inExactWindow) {
        status = isAmbiguous ? 'OVERLAP_AMBIGUOUS' : 'EXACT_MATCH';
        explanation = isAmbiguous
          ? `Overlapping CGNAT session inside exact window (${s.portMatchType}); multiple subscribers share ${ipTrimmed}.`
          : `Observed timestamp falls strictly within logged session window (${s.portMatchType.replace(/_/g, ' ').toLowerCase()}).`;
      } else if (s.inToleranceWindow) {
        status = 'TOLERANCE_MATCH';
        explanation = `Outside exact session bounds by ${s.timeDeltaSec}s (within ±${toleranceSec}s clock-drift tolerance).`;
      } else {
        status = 'OUT_OF_WINDOW';
        explanation = `Matching IP/port allocation but ${s.timeDeltaSec}s outside the observed timestamp window.`;
      }

      return {
        record: s.record,
        suspectName,
        status,
        portMatchType: s.portMatchType,
        timeDeltaSec: s.timeDeltaSec,
        explanation,
        citation: ipdrToCitation(s.record),
      };
    })
    .sort((a, b) => {
      const order = { EXACT_MATCH: 0, OVERLAP_AMBIGUOUS: 1, TOLERANCE_MATCH: 2, OUT_OF_WINDOW: 3 };
      return order[a.status] - order[b.status] || a.timeDeltaSec - b.timeDeltaSec;
    });

  let summaryVerdict = 'No matching IPDR/CGNAT records found for this IP, port, and protocol.';
  let uniqueSubscriber: { msisdn: string; name?: string; recordId: string } | undefined;

  if (exactHits.length > 0 && !isAmbiguous) {
    const hit = exactHits[0];
    const name = suspectByPhone.get(hit.record.msisdn)?.name;
    uniqueSubscriber = {
      msisdn: hit.record.msisdn,
      name,
      recordId: hit.record.id,
    };
    summaryVerdict = `Unique logged subscriber identified: ${name ? `${name} (${hit.record.msisdn})` : hit.record.msisdn} via ${hit.record.id} (${hit.record.sourceFile} · Row ${hit.record.rowNumber}).`;
  } else if (isAmbiguous) {
    summaryVerdict = `Ambiguous CGNAT overlap: ${exactDistinctSubs.size} distinct subscribers matched inside the exact time window. Officer verification required.`;
  } else if (matches.some((m) => m.status === 'TOLERANCE_MATCH')) {
    summaryVerdict = `No exact-window hit; ${matches.filter((m) => m.status === 'TOLERANCE_MATCH').length} subscriber(s) matched only within the ±${toleranceSec}s clock-drift tolerance.`;
  } else if (matches.length > 0) {
    summaryVerdict = `${matches.length} allocation(s) matched IP/port, but all are out of the observed time window.`;
  }

  return { matches, summaryVerdict, uniqueSubscriber };
}

/**
 * Generates deterministic grounded analytical context for the AI Investigation Assistant.
 * Ensures Gemini answers ONLY from verified uploaded records and cites exact source files & rows.
 */
export function buildAiEvidenceContext(caseFile: CaseFile, question: string): {
  contextText: string;
  availableCitations: EvidenceCitation[];
} {
  const qLower = question.toLowerCase();
  const suspects = caseFile.suspects;

  // Detect mentioned suspects by name or phone digits
  const mentionedSuspects = suspects.filter((s) => {
    const nameParts = s.name.toLowerCase().split(/\s+/);
    const digits = s.phone.replace(/\D/g, '');
    const last10 = digits.slice(-10);
    return (
      nameParts.some((p) => p.length >= 3 && qLower.includes(p)) ||
      qLower.includes(last10) ||
      qLower.includes(s.phone.toLowerCase())
    );
  });

  const targetPhones =
    mentionedSuspects.length > 0
      ? mentionedSuspects.map((s) => normalizePhoneNumber(s.phone))
      : suspects.slice(0, 3).map((s) => normalizePhoneNumber(s.phone));

  const lines: string[] = [];
  const citations: EvidenceCitation[] = [];
  const seenCitationKeys = new Set<string>();
  const addCitation = (c: EvidenceCitation) => {
    const k = `${c.sourceFile}:${c.rowNumber}:${c.recordId}`;
    if (!seenCitationKeys.has(k)) {
      seenCitationKeys.add(k);
      citations.push(c);
    }
  };

  lines.push(`CASE: ${caseFile.caseNumber} — ${caseFile.title} (${caseFile.station})`);
  lines.push(`BRIEF: ${caseFile.brief}`);
  lines.push(
    `IMPORTED SOURCES (${caseFile.sources.length}): ${caseFile.sources
      .map((s) => `${s.fileName} [${s.datasetType}, ${s.operator}, ${s.validRowCount} valid rows]`)
      .join('; ')}`
  );
  lines.push(
    `SUSPECTS (${suspects.length}): ${suspects
      .map((s) => `${s.name} (${s.phone}, Base: ${s.baseLocation}, Known IMEIs: ${s.knownImeis.join('/') || 'none'}, Prior FIRs: ${s.priorFirs.join('/') || 'none'})`)
      .join(' | ')}`
  );

  // Per-suspect contact summaries
  for (const phone of targetPhones.slice(0, 3)) {
    const analysis = analyzeContactPatterns(caseFile.cdrs, suspects, phone);
    lines.push(
      `\nCONTACT PATTERN FOR ${analysis.targetName ?? phone} (${phone}): Total=${analysis.totalCalls} calls (Out=${analysis.outgoingCalls}, In=${analysis.incomingCalls}), Duration=${formatDuration(analysis.totalDurationSec)}, Night 00:00-06:00 IST=${analysis.nightCalls} (${analysis.nightRatioPct}%), First=${analysis.firstActivityIso ?? 'N/A'}, Last=${analysis.lastActivityIso ?? 'N/A'}.`
    );
    lines.push(
      `Top Contacts: ${analysis.contacts
        .slice(0, 6)
        .map((c) => {
          const sample = c.records[0];
          if (sample) addCitation(cdrToCitation(sample));
          return `${c.contactName ?? c.contactNumber} (${c.contactNumber}): ${c.totalCalls} calls, ${c.totalDurationSec}s, night=${c.nightCalls} [e.g., ${sample.sourceFile}:Row ${sample.rowNumber}, id=${sample.id}, ts=${sample.timestampIso}]`;
        })
        .join(' | ')}`
    );

    const timeline = buildTowerTimeline(caseFile.cdrs, caseFile.towers, phone);
    if (timeline.steps.length > 0) {
      lines.push(
        `TOWER TIMELINE FOR ${analysis.targetName ?? phone}: ${timeline.steps.length} observations, ${timeline.transitions} tower hops, max implied speed=${timeline.maxImpliedSpeedKmh} km/h. Towers used: ${timeline.towerSummary
          .map((t) => `${t.towerId} (${t.towerName}): ${t.hitCount} hits (${t.firstSeenIso} to ${t.lastSeenIso})`)
          .join('; ')}`
      );
      const transitions = timeline.steps.filter((st, idx) => idx === 0 || st.isTransition).slice(0, 8);
      lines.push(
        `Key Tower Events: ${transitions
          .map((st) => {
            const matchedRec = caseFile.cdrs.find((c) => c.id === st.recordId);
            if (matchedRec) addCitation(cdrToCitation(matchedRec));
            return `${st.timestampIso} @ ${st.towerId} (${st.towerName}) [${st.sourceFile}:Row ${st.rowNumber}, id=${st.recordId}]`;
          })
          .join(' -> ')}`
      );
    }
  }

  // Common contacts across suspects
  const commonTargetPhones =
    mentionedSuspects.length >= 2
      ? mentionedSuspects.map((s) => s.phone)
      : suspects.slice(0, 2).map((s) => s.phone);
  if (commonTargetPhones.length >= 2) {
    const common = findCommonContacts(caseFile.cdrs, suspects, commonTargetPhones);
    lines.push(
      `\nCROSS-SUSPECT CORRELATION (${commonTargetPhones.join(' vs ')}): ${common.sharedContacts.length} shared third-party contacts, ${common.directLinks.length} direct links.`
    );
    for (const sc of common.sharedContacts.slice(0, 6)) {
      sc.citations.slice(0, 3).forEach(addCitation);
      lines.push(
        `  Shared Contact: ${sc.contactName ?? sc.contactNumber} (${sc.contactNumber}) — ${sc.totalSharedCalls} calls (${Object.entries(sc.perSuspectCounts)
          .map(([p, cnt]) => `${p}:${cnt}`)
          .join(', ')}) [Refs: ${sc.citations
          .slice(0, 3)
          .map((c) => `${c.sourceFile}:Row ${c.rowNumber}`)
          .join(', ')}]`
      );
    }
    for (const dl of common.directLinks.slice(0, 4)) {
      dl.citations.slice(0, 2).forEach(addCitation);
      lines.push(
        `  Direct Link: ${dl.from} <-> ${dl.to}: ${dl.callCount} calls, ${dl.totalDurationSec}s, night=${dl.nightCalls} [Refs: ${dl.citations
          .slice(0, 2)
          .map((c) => `${c.sourceFile}:Row ${c.rowNumber}`)
          .join(', ')}]`
      );
    }
  }

  // Device & SIM changes across case
  const deviceAnalysis = detectDeviceSimChanges(caseFile.cdrs, suspects);
  lines.push(
    `\nIMEI / SIM CHANGES (${deviceAnalysis.changes.length} events) & SHARED HANDSETS (${deviceAnalysis.sharedDevices.length}):`
  );
  for (const ch of deviceAnalysis.changes.slice(0, 10)) {
    addCitation(ch.previousCitation);
    addCitation(ch.newCitation);
    lines.push(
      `  ${ch.changeType} for ${ch.suspectName ?? ch.msisdn} (${ch.msisdn}): ${ch.previousValue} (${ch.previousTimestampIso}, ${ch.previousCitation.sourceFile}:Row ${ch.previousCitation.rowNumber}) -> ${ch.newValue} (${ch.newTimestampIso}, ${ch.newCitation.sourceFile}:Row ${ch.newCitation.rowNumber})`
    );
  }
  for (const sh of deviceAnalysis.sharedDevices) {
    sh.citations.forEach(addCitation);
    lines.push(
      `  SHARED IMEI ${sh.imei}: used by ${sh.msisdns
        .map((m) => `${m.name ?? m.phone} (${m.phone}, ${m.count} calls)`)
        .join(' AND ')} [Refs: ${sh.citations.map((c) => `${c.sourceFile}:Row ${c.rowNumber}`).join(', ')}]`
    );
  }

  // IPDR records summary
  lines.push(`\nIPDR / CGNAT RECORDS (${caseFile.ipdrs.length} total):`);
  for (const ip of caseFile.ipdrs.slice(0, 12)) {
    addCitation(ipdrToCitation(ip));
    const subName = suspects.find((s) => normalizePhoneNumber(s.phone) === ip.msisdn)?.name;
    lines.push(
      `  ${ip.id} [${ip.sourceFile}:Row ${ip.rowNumber}] ${ip.operator}: ${ip.msisdn}${subName ? ` (${subName})` : ''}, IP=${ip.publicIp}, SrcPort=${ip.sourcePort ?? 'N/A'}, AllocRange=${ip.allocPortStart ?? '?'}-${ip.allocPortEnd ?? '?'}, Proto=${ip.protocol}, Start=${ip.sessionStartIso}, End=${ip.sessionEndIso ?? 'point'}, Tower=${ip.cellTowerId ?? 'N/A'}, App=${ip.application ?? 'Not supplied'}, Service=${ip.service ?? 'Not supplied'}, Dest=${ip.destinationHost ?? 'Not supplied'}`
    );
  }

  return { contextText: lines.join('\n'), availableCitations: citations };
}
