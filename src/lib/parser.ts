import Papa from 'papaparse';
import type {
  CdrRecord,
  CellTower,
  DatasetType,
  EvidenceSource,
  IpdrRecord,
  OperatorPreset,
  SuspectProfile,
  ValidationIssue,
} from '../types/forensics.ts';
import { normalizePhoneNumber, parseTimestampIST } from './forensics.ts';

export interface ParsedRawTable {
  headers: string[];
  rows: Record<string, string>[];
  delimiter: string;
}

export interface SchemaDetectionResult {
  datasetType: DatasetType;
  operator: OperatorPreset;
  confidence: 'high' | 'medium' | 'low';
  suggestedMapping: Record<string, string>;
}

export const CDR_CANONICAL_FIELDS = [
  { key: 'record_id', label: 'Record / Call ID', required: false },
  { key: 'operator', label: 'Operator / Telco', required: false },
  { key: 'timestamp', label: 'Timestamp (ISO / Combined)', required: false },
  { key: 'date', label: 'Call Date (Split DD/MM/YYYY)', required: false },
  { key: 'time', label: 'Call Time (Split HH:MM:SS)', required: false },
  { key: 'caller', label: 'Caller / A-Number', required: true },
  { key: 'callee', label: 'Callee / B-Number', required: true },
  { key: 'duration_sec', label: 'Duration / Billsec (sec)', required: false },
  { key: 'call_type', label: 'Call Type / Direction', required: false },
  { key: 'imei', label: 'Handset IMEI', required: false },
  { key: 'imsi', label: 'Subscriber IMSI', required: false },
  { key: 'iccid', label: 'SIM ICCID', required: false },
  { key: 'cell_tower_id', label: 'Serving Cell / Tower ID', required: false },
  { key: 'observed_msisdn', label: 'Observed / Served MSISDN', required: false },
] as const;

export const IPDR_CANONICAL_FIELDS = [
  { key: 'record_id', label: 'Session / NAT ID', required: false },
  { key: 'operator', label: 'Operator / Telco', required: false },
  { key: 'session_start', label: 'Session Start (IST/ISO)', required: true },
  { key: 'session_end', label: 'Session End (Optional)', required: false },
  { key: 'msisdn', label: 'Subscriber MSISDN', required: true },
  { key: 'public_ip', label: 'Public IPv4', required: true },
  { key: 'source_port', label: 'Source Port', required: false },
  { key: 'alloc_port_start', label: 'CGNAT Alloc Port Start', required: false },
  { key: 'alloc_port_end', label: 'CGNAT Alloc Port End', required: false },
  { key: 'protocol', label: 'Protocol (TCP/UDP)', required: false },
  { key: 'cell_tower_id', label: 'Serving Cell Tower ID', required: false },
  { key: 'imei', label: 'IMEI', required: false },
  { key: 'imsi', label: 'IMSI', required: false },
  { key: 'iccid', label: 'ICCID', required: false },
  { key: 'application', label: 'Application Indicator', required: false },
  { key: 'service', label: 'Service Category', required: false },
  { key: 'destination_host', label: 'Destination Host/IP', required: false },
] as const;

export const TOWER_CANONICAL_FIELDS = [
  { key: 'tower_id', label: 'Tower / Cell ID', required: true },
  { key: 'tower_name', label: 'Tower / Site Name', required: true },
  { key: 'lat', label: 'Latitude', required: true },
  { key: 'lon', label: 'Longitude', required: true },
  { key: 'azimuth_degrees', label: 'Azimuth (Degrees)', required: false },
] as const;

export const SUSPECT_CANONICAL_FIELDS = [
  { key: 'suspect_id', label: 'Suspect ID', required: false },
  { key: 'name', label: 'Suspect Name', required: true },
  { key: 'phone', label: 'Phone / MSISDN', required: true },
  { key: 'known_imeis', label: 'Known IMEIs (| separated)', required: false },
  { key: 'base_location', label: 'Base Location', required: false },
  { key: 'prior_firs', label: 'Prior FIRs', required: false },
] as const;

const HEADER_ALIASES: Record<string, string[]> = {
  record_id: ['record_id', 'call id', 'call_id', 'session_id', 'nat_id', 'id', 'sr_no'],
  operator: ['telco', 'operator', 'carrier', 'network', 'provider', 'tsp'],
  timestamp: ['timestamp', 'call_timestamp', 'datetime', 'start_time', 'event_time', 'date_time'],
  date: ['call date', 'call_date', 'date', 'event_date'],
  time: ['call time', 'call_time', 'time', 'event_time_only'],
  caller: ['caller_msisdn', 'a-number', 'a_number', 'a_party', 'calling_number', 'caller', 'calling_party', 'source_number'],
  callee: ['callee_msisdn', 'b-number', 'b_number', 'b_party', 'called_number', 'callee', 'called_party', 'dest_number'],
  duration_sec: ['duration_sec', 'billsec', 'duration', 'dur_sec', 'call_duration', 'seconds'],
  call_type: ['call_type', 'type', 'direction', 'service_type', 'event_type'],
  imei: ['imei', 'handset imei', 'handset_imei', 'device_imei'],
  imsi: ['imsi', 'subscriber imsi', 'subscriber_imsi'],
  iccid: ['iccid', 'sim iccid', 'sim_iccid', 'sim_serial'],
  cell_tower_id: ['cell_tower_id', 'serving cell', 'serving_cell', 'cell_id', 'tower_id', 'first_cgi', 'cgi', 'lac_ci'],
  observed_msisdn: ['observed_msisdn', 'served msisdn', 'served_msisdn', 'target_msisdn', 'subscriber_number'],
  session_start: ['session_start', 'start_timestamp', 'nat_start', 'start_time', 'timestamp'],
  session_end: ['session_end', 'end_timestamp', 'nat_end', 'end_time'],
  msisdn: ['caller_msisdn', 'msisdn', 'subscriber_msisdn', 'phone', 'mobile'],
  public_ip: ['public_ip', 'nat_ip', 'translated_ip', 'public_ipv4', 'ip_address', 'ip'],
  source_port: ['source_port', 'src_port', 'nat_port', 'port', 'translated_port'],
  alloc_port_start: ['alloc_port_start', 'port_start', 'port_range_start', 'cgnat_port_start'],
  alloc_port_end: ['alloc_port_end', 'port_end', 'port_range_end', 'cgnat_port_end'],
  protocol: ['protocol', 'proto', 'l4_proto'],
  application: ['application', 'app', 'app_name', 'app_indicator'],
  service: ['service', 'service_category', 'category'],
  destination_host: ['destination_host', 'dest_host', 'destination_ip', 'dst_host', 'sni'],
  tower_id: ['tower_id', 'cell_id', 'cell_tower_id', 'site_id', 'cgi'],
  tower_name: ['tower_name', 'site_name', 'location', 'address', 'area'],
  lat: ['lat', 'latitude', 'cell_lat'],
  lon: ['lon', 'lng', 'longitude', 'long', 'cell_lon'],
  azimuth_degrees: ['azimuth_degrees', 'azimuth', 'bearing', 'sector_azimuth'],
  suspect_id: ['suspect_id', 'id', 'profile_id'],
  name: ['name', 'suspect_name', 'full_name', 'alias'],
  phone: ['phone', 'msisdn', 'mobile', 'phone_number'],
  known_imeis: ['known_imeis', 'imeis', 'imei'],
  base_location: ['base_location', 'address', 'city', 'location'],
  prior_firs: ['prior_firs', 'firs', 'fir_no', 'cases'],
};

/**
 * Parses CSV or TSV text into normalized header + row records.
 */
export function parseDelimitedText(text: string): ParsedRawTable {
  const cleaned = text.replace(/^\uFEFF/, '').trim();
  if (!cleaned) return { headers: [], rows: [], delimiter: ',' };
  const firstLine = cleaned.split(/\r?\n/)[0] || '';
  const tabCount = (firstLine.match(/\t/g) || []).length;
  const commaCount = (firstLine.match(/,/g) || []).length;
  const semiCount = (firstLine.match(/;/g) || []).length;
  const delimiter = tabCount > commaCount && tabCount >= semiCount ? '\t' : semiCount > commaCount ? ';' : ',';

  const result = Papa.parse<Record<string, string>>(cleaned, {
    header: true,
    delimiter,
    skipEmptyLines: false,
    transformHeader: (h) => h.trim(),
  });

  const headers = (result.meta.fields || []).map((h) => h.trim()).filter(Boolean);
  const rows = (result.data || []).map((row) => {
    const out: Record<string, string> = {};
    for (const h of headers) {
      out[h] = row[h] !== undefined && row[h] !== null ? String(row[h]).trim() : '';
    }
    return out;
  });

  return { headers, rows, delimiter };
}

function matchHeadersToFields(headers: string[], fieldKeys: readonly string[]): Record<string, string> {
  const mapping: Record<string, string> = {};
  const usedHeaders = new Set<string>();

  for (const key of fieldKeys) {
    const aliases = HEADER_ALIASES[key] || [key];
    for (const alias of aliases) {
      const found = headers.find(
        (h) => !usedHeaders.has(h) && h.toLowerCase().trim() === alias.toLowerCase()
      );
      if (found) {
        mapping[key] = found;
        usedHeaders.add(found);
        break;
      }
    }
  }
  return mapping;
}

/**
 * Auto-detects whether an uploaded table is CDR (Jio/Airtel/Vi/BSNL), IPDR, Cell Tower Dump, or Suspects.
 */
export function detectOperatorSchema(
  headers: string[],
  sampleRows: Record<string, string>[],
  fileName = ''
): SchemaDetectionResult {
  const lowerHeaders = headers.map((h) => h.toLowerCase().trim());
  const fnLower = fileName.toLowerCase();

  // 1. IPDR check
  if (
    lowerHeaders.includes('public_ip') ||
    lowerHeaders.includes('nat_ip') ||
    lowerHeaders.includes('alloc_port_start') ||
    fnLower.includes('ipdr')
  ) {
    return {
      datasetType: 'ipdr',
      operator: 'Carrier IPDR',
      confidence: 'high',
      suggestedMapping: matchHeadersToFields(
        headers,
        IPDR_CANONICAL_FIELDS.map((f) => f.key)
      ),
    };
  }

  // 2. Cell Tower Dump check
  if (
    (lowerHeaders.includes('lat') || lowerHeaders.includes('latitude')) &&
    (lowerHeaders.includes('lon') || lowerHeaders.includes('longitude') || lowerHeaders.includes('lng'))
  ) {
    return {
      datasetType: 'towers',
      operator: 'Cell Tower Dump',
      confidence: 'high',
      suggestedMapping: matchHeadersToFields(
        headers,
        TOWER_CANONICAL_FIELDS.map((f) => f.key)
      ),
    };
  }

  // 3. Suspects Registry check
  if (
    lowerHeaders.includes('suspect_id') ||
    lowerHeaders.includes('prior_firs') ||
    lowerHeaders.includes('known_imeis') ||
    fnLower.includes('suspect')
  ) {
    return {
      datasetType: 'suspects',
      operator: 'Suspect Registry',
      confidence: 'high',
      suggestedMapping: matchHeadersToFields(
        headers,
        SUSPECT_CANONICAL_FIELDS.map((f) => f.key)
      ),
    };
  }

  // 4. CDR operator detection
  const suggestedMapping = matchHeadersToFields(
    headers,
    CDR_CANONICAL_FIELDS.map((f) => f.key)
  );

  let operator: OperatorPreset = 'Custom';
  const firstTelco = (
    sampleRows[0]?.[suggestedMapping.operator || ''] ||
    sampleRows[0]?.telco ||
    sampleRows[0]?.Operator ||
    ''
  ).toLowerCase();

  if (lowerHeaders.includes('a-number') || lowerHeaders.includes('billsec') || firstTelco.includes('airtel') || fnLower.includes('airtel')) {
    operator = 'Airtel';
  } else if (firstTelco.includes('jio') || fnLower.includes('jio')) {
    operator = 'Jio 5G';
  } else if (firstTelco.includes('vi') || firstTelco.includes('vodafone') || fnLower.includes('vi_')) {
    operator = 'Vi';
  } else if (firstTelco.includes('bsnl') || fnLower.includes('bsnl')) {
    operator = 'BSNL';
  }

  const hasCore =
    Boolean(suggestedMapping.caller) &&
    Boolean(suggestedMapping.callee) &&
    Boolean(suggestedMapping.timestamp || suggestedMapping.date);

  return {
    datasetType: 'cdr',
    operator,
    confidence: hasCore ? 'high' : suggestedMapping.caller ? 'medium' : 'low',
    suggestedMapping,
  };
}

export async function computeSha256Hex(content: string | Uint8Array<ArrayBuffer>): Promise<string> {
  const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : content;
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}

export interface NormalizationOutput {
  sourceMeta: EvidenceSource;
  cdrs: CdrRecord[];
  ipdrs: IpdrRecord[];
  towers: CellTower[];
  suspects: SuspectProfile[];
  issues: ValidationIssue[];
}

/**
 * Validates and normalizes parsed operator rows using the investigator's column mapping.
 * Reports exact 1-indexed row numbers (including header offset = row 2 for first data row)
 * and missing-field counts without silently corrupting invalid rows.
 */
export function normalizeDatasetRows(params: {
  sourceId: string;
  fileName: string;
  datasetType: DatasetType;
  operator: string;
  uploadedBy: string;
  sha256: string;
  rows: Record<string, string>[];
  columnMapping: Record<string, string>;
  observedFallbackRole?: 'caller' | 'callee';
}): NormalizationOutput {
  const {
    sourceId,
    fileName,
    datasetType,
    operator,
    uploadedBy,
    sha256,
    rows,
    columnMapping,
    observedFallbackRole = 'caller',
  } = params;

  const issues: ValidationIssue[] = [];
  const missingFieldCounts: Record<string, number> = {};
  const incMissing = (field: string) => {
    missingFieldCounts[field] = (missingFieldCounts[field] ?? 0) + 1;
  };

  const getVal = (row: Record<string, string>, canonicalKey: string): string => {
    const mappedCol = columnMapping[canonicalKey];
    if (!mappedCol) return '';
    return (row[mappedCol] ?? '').trim();
  };

  const cdrs: CdrRecord[] = [];
  const ipdrs: IpdrRecord[] = [];
  const towers: CellTower[] = [];
  const suspects: SuspectProfile[] = [];
  let rejectedRowCount = 0;

  rows.forEach((row, idx) => {
    if (Object.values(row).every(value => value === '')) return;
    const rowNumber = idx + 2; // Row 1 is CSV header

    if (datasetType === 'cdr') {
      const callerRaw = getVal(row, 'caller');
      const calleeRaw = getVal(row, 'callee');
      const tsRaw = getVal(row, 'timestamp');
      const dateRaw = getVal(row, 'date');
      const timeRaw = getVal(row, 'time');

      const caller = normalizePhoneNumber(callerRaw);
      const callee = normalizePhoneNumber(calleeRaw);
      const parsedTs = parseTimestampIST(tsRaw, dateRaw, timeRaw);

      if (!caller) {
        rejectedRowCount++;
        incMissing('caller');
        issues.push({
          rowNumber,
          field: 'caller',
          severity: 'error',
          message: 'Missing or invalid caller MSISDN',
          rawValue: callerRaw,
        });
        return;
      }
      if (!callee) {
        rejectedRowCount++;
        incMissing('callee');
        issues.push({
          rowNumber,
          field: 'callee',
          severity: 'error',
          message: 'Missing or invalid callee MSISDN',
          rawValue: calleeRaw,
        });
        return;
      }
      if (!parsedTs) {
        rejectedRowCount++;
        incMissing('timestamp');
        issues.push({
          rowNumber,
          field: 'timestamp',
          severity: 'error',
          message: 'Invalid or unparseable timestamp/date',
          rawValue: tsRaw || `${dateRaw} ${timeRaw}`,
        });
        return;
      }

      const durRaw = getVal(row, 'duration_sec');
      const durNum = durRaw ? Number(durRaw) : 0;
      if (durRaw && (Number.isNaN(durNum) || durNum < 0)) {
        issues.push({
          rowNumber,
          field: 'duration_sec',
          severity: 'warning',
          message: 'Non-numeric duration defaulted to 0s',
          rawValue: durRaw,
        });
      }

      const imei = getVal(row, 'imei') || undefined;
      const imsi = getVal(row, 'imsi') || undefined;
      const iccid = getVal(row, 'iccid') || undefined;
      const cellTowerId = getVal(row, 'cell_tower_id') || undefined;
      const observedRaw = getVal(row, 'observed_msisdn');
      const observedMsisdn =
        normalizePhoneNumber(observedRaw) ||
        (observedFallbackRole === 'callee' ? callee : caller);

      if (!imei) incMissing('imei');
      if (!imsi) incMissing('imsi');
      if (!cellTowerId) incMissing('cell_tower_id');

      const rawType = getVal(row, 'call_type').toUpperCase();
      let callType: CdrRecord['callType'] = 'CALL';
      if (rawType.includes('SMS') && rawType.includes('IN')) callType = 'SMS_IN';
      else if (rawType.includes('SMS')) callType = 'SMS_OUT';
      else if (rawType.includes('IN') || rawType.includes('MTC')) callType = 'VOICE_IN';
      else if (rawType.includes('OUT') || rawType.includes('MOC')) callType = 'VOICE_OUT';

      const rowOperator = getVal(row, 'operator') || operator || 'Unknown';
      const id = getVal(row, 'record_id') || `${sourceId}-R${rowNumber}`;

      cdrs.push({
        id,
        sourceId,
        sourceFile: fileName,
        rowNumber,
        operator: rowOperator,
        timestampIso: parsedTs.iso,
        epochMs: parsedTs.epochMs,
        istHour: parsedTs.istHour,
        isNight: parsedTs.isNight,
        caller,
        callee,
        observedMsisdn,
        callType,
        durationSec: Number.isNaN(durNum) || durNum < 0 ? 0 : Math.round(durNum),
        imei,
        imsi,
        iccid,
        cellTowerId,
        rawFields: row,
      });
    } else if (datasetType === 'ipdr') {
      const msisdn = normalizePhoneNumber(getVal(row, 'msisdn'));
      const publicIp = getVal(row, 'public_ip');
      const startParsed = parseTimestampIST(getVal(row, 'session_start'));
      const endRaw = getVal(row, 'session_end');
      const endParsed = endRaw ? parseTimestampIST(endRaw) : null;

      if (!msisdn || !publicIp || !startParsed) {
        rejectedRowCount++;
        if (!msisdn) incMissing('msisdn');
        if (!publicIp) incMissing('public_ip');
        if (!startParsed) incMissing('session_start');
        issues.push({
          rowNumber,
          field: !publicIp ? 'public_ip' : !msisdn ? 'msisdn' : 'session_start',
          severity: 'error',
          message: 'IPDR row missing required MSISDN, Public IP, or Session Start',
        });
        return;
      }

      const ipv4Valid = /^(\d{1,3}\.){3}\d{1,3}$/.test(publicIp);
      if (!ipv4Valid) {
        rejectedRowCount++;
        issues.push({
          rowNumber,
          field: 'public_ip',
          severity: 'error',
          message: 'Invalid IPv4 address format',
          rawValue: publicIp,
        });
        return;
      }

      const parsePort = (v: string) => {
        if (!v) return undefined;
        const n = Number(v);
        return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : undefined;
      };

      const sourcePort = parsePort(getVal(row, 'source_port'));
      const allocPortStart = parsePort(getVal(row, 'alloc_port_start'));
      const allocPortEnd = parsePort(getVal(row, 'alloc_port_end'));
      const application = getVal(row, 'application') || undefined;
      const service = getVal(row, 'service') || undefined;
      const destinationHost = getVal(row, 'destination_host') || undefined;

      if (!application) incMissing('application');
      if (!endParsed) incMissing('session_end');

      const durationSec =
        endParsed && endParsed.epochMs >= startParsed.epochMs
          ? Number(((endParsed.epochMs - startParsed.epochMs) / 1000).toFixed(2))
          : undefined;

      ipdrs.push({
        id: getVal(row, 'record_id') || `${sourceId}-IP${rowNumber}`,
        sourceId,
        sourceFile: fileName,
        rowNumber,
        operator: getVal(row, 'operator') || operator || 'Carrier IPDR',
        sessionStartIso: startParsed.iso,
        sessionStartMs: startParsed.epochMs,
        sessionEndIso: endParsed?.iso,
        sessionEndMs: endParsed?.epochMs,
        isPointObservation: !endParsed,
        msisdn,
        imei: getVal(row, 'imei') || undefined,
        imsi: getVal(row, 'imsi') || undefined,
        iccid: getVal(row, 'iccid') || undefined,
        publicIp,
        sourcePort,
        allocPortStart,
        allocPortEnd,
        protocol: (getVal(row, 'protocol') || 'TCP').toUpperCase(),
        cellTowerId: getVal(row, 'cell_tower_id') || undefined,
        application,
        service,
        destinationHost,
        sessionDurationSec: durationSec,
        rawFields: row,
      });
    } else if (datasetType === 'towers') {
      const towerId = getVal(row, 'tower_id');
      const towerName = getVal(row, 'tower_name') || towerId;
      const lat = Number(getVal(row, 'lat'));
      const lon = Number(getVal(row, 'lon'));
      const azRaw = getVal(row, 'azimuth_degrees');
      const azimuthDegrees = azRaw ? Number(azRaw) : 0;

      if (!towerId || Number.isNaN(lat) || Number.isNaN(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) {
        rejectedRowCount++;
        issues.push({
          rowNumber,
          field: !towerId ? 'tower_id' : 'lat/lon',
          severity: 'error',
          message: 'Tower row missing valid tower ID or geographic coordinates',
        });
        return;
      }

      towers.push({
        towerId,
        towerName,
        lat,
        lon,
        azimuthDegrees: Number.isNaN(azimuthDegrees) ? 0 : azimuthDegrees,
        sectorRadiusMeters: 1200,
        sourceFile: fileName,
        rowNumber,
      });
    } else if (datasetType === 'suspects') {
      const name = getVal(row, 'name');
      const phone = normalizePhoneNumber(getVal(row, 'phone'));
      if (!name || !phone) {
        rejectedRowCount++;
        issues.push({
          rowNumber,
          field: !name ? 'name' : 'phone',
          severity: 'error',
          message: 'Suspect record missing required name or phone number',
        });
        return;
      }
      const imeisRaw = getVal(row, 'known_imeis');
      const firsRaw = getVal(row, 'prior_firs');
      suspects.push({
        suspectId: getVal(row, 'suspect_id') || `s-${rowNumber}`,
        name,
        phone,
        knownImeis: imeisRaw ? imeisRaw.split(/[|,;]/).map((s) => s.trim()).filter(Boolean) : [],
        baseLocation: getVal(row, 'base_location') || 'Unknown',
        priorFirs: firsRaw ? firsRaw.split(/[|,;]/).map((s) => s.trim()).filter(Boolean) : [],
        sourceFile: fileName,
        rowNumber,
      });
    }
  });

  const validRowCount =
    datasetType === 'cdr'
      ? cdrs.length
      : datasetType === 'ipdr'
        ? ipdrs.length
        : datasetType === 'towers'
          ? towers.length
          : suspects.length;

  const sourceMeta: EvidenceSource = {
    id: sourceId,
    fileName,
    datasetType,
    operator,
    uploadedAt: new Date().toISOString(),
    uploadedBy,
    sha256,
    rowCount: rows.length,
    validRowCount,
    rejectedRowCount,
    missingFieldCounts,
    columnMapping,
    sampleWarnings: issues.slice(0, 25),
  };

  return { sourceMeta, cdrs, ipdrs, towers, suspects, issues };
}
