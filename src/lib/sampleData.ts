import type { AuditLogEntry, CaseFile } from '../types/forensics.ts';
import {
  detectOperatorSchema,
  normalizeDatasetRows,
  parseDelimitedText,
} from './parser.ts';

/**
 * Authentic synthetic sample files modeled on Darpan Forensics Case PS03 (Jaipur Cyber-Telecom Ring).
 * Strictly synthetic records for training and demonstration; zero real personal data.
 */
export const SAMPLE_SUSPECTS_CSV = `suspect_id,name,phone,known_imeis,base_location,prior_firs
s1,Rohan Mehta,+919829077112,356938035643801|356938035643819,"Shyam Nagar, Jaipur",DEMO-FIR-014
s2,Aman Verma,+919876543210,356938035643819,"Mansarovar, Jaipur",DEMO-FIR-017
s3,Vikash Sharma,+919876543211,356938035643827,"Mansarovar, Jaipur",
s4,Neha Singh,+919876543212,356938035643835,"Shyam Nagar, Jaipur",
s5,Rajat Kumar,+919876543213,356938035643843,"Malviya Nagar, Jaipur",DEMO-FIR-022`;

export const SAMPLE_TOWERS_CSV = `tower_id,tower_name,lat,lon,azimuth_degrees
RJ-JPR-MAN-042,Sector 7 Mansarovar Jaipur,26.8524,75.7682,120
RJ-JPR-SHY-019,Shyam Nagar Jaipur,26.8916,75.7687,65
RJ-JPR-MAL-008,Malviya Nagar Jaipur,26.8590,75.8102,250
RJ-JPR-CSH-011,C-Scheme Central Jaipur,26.9068,75.8042,180
RJ-JPR-TNK-024,Tonk Road Durgapura Jaipur,26.8475,75.7955,310`;

export const SAMPLE_JIO_CDR_CSV = `record_id,telco,timestamp,caller_msisdn,callee_msisdn,duration_sec,call_type,imei,imsi,cell_tower_id,iccid,observed_msisdn
JIO-001,Jio 5G,2026-01-13T18:14:20+05:30,+919829077112,+919876543210,94,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-SHY-019,8991870000000000001,+919829077112
JIO-002,Jio 5G,2026-01-13T19:42:11+05:30,+919876543211,+919829077112,48,VOICE_IN,356938035643801,405870000000001,RJ-JPR-SHY-019,8991870000000000001,+919829077112
JIO-003,Jio 5G,2026-01-13T21:05:33+05:30,+919829077112,+919876543212,135,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-CSH-011,8991870000000000001,+919829077112
JIO-004,Jio 5G,2026-01-13T22:30:10+05:30,+919829077112,+919811004421,210,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-MAN-042,8991870000000000001,+919829077112
JIO-005,Jio 5G,2026-01-14T02:01:01+05:30,+919829077112,+919876543210,25,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-MAN-042,8991870000000000001,+919829077112
JIO-006,Jio 5G,2026-01-14T02:02:02+05:30,+919829077112,+919876543211,28,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-MAN-042,8991870000000000001,+919829077112
JIO-007,Jio 5G,2026-01-14T02:03:03+05:30,+919829077112,+919876543212,31,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-MAN-042,8991870000000000001,+919829077112
JIO-008,Jio 5G,2026-01-14T02:04:15+05:30,+919829077112,+919876543210,12,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-MAN-042,8991870000000000001,+919829077112
JIO-009,Jio 5G,2026-01-14T02:05:44+05:30,+919829077112,+919876543211,14,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-MAN-042,8991870000000000001,+919829077112
JIO-010,Jio 5G,2026-01-14T02:07:12+05:30,+919829077112,+919876543212,43,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-MAN-042,8991870000000000001,+919829077112
JIO-011,Jio 5G,2026-01-14T02:09:10+05:30,+919829077112,+919876543210,52,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-MAN-042,8991870000000000001,+919829077112
JIO-012,Jio 5G,2026-01-14T02:10:40+05:30,+919829077112,+919876543213,78,VOICE_OUT,356938035643801,405870000000001,RJ-JPR-MAN-042,8991870000000000001,+919829077112`;

export const SAMPLE_AIRTEL_CDR_TSV = `Call ID\tOperator\tCall Date\tCall Time\tA-Number\tB-Number\tBillsec\tHandset IMEI\tSubscriber IMSI\tServing Cell\tSIM ICCID\tServed MSISDN
AIR-101\tAirtel\t14/01/2026\t02:12:12\t+919829077112\t+919876543210\t61\t356938035643801\t405870000000001\tRJ-JPR-MAN-042\t8991870000000000001\t+919829077112
AIR-102\tAirtel\t14/01/2026\t02:14:14\t+919829077112\t+919876543212\t67\t356938035643801\t405870000000001\tRJ-JPR-MAN-042\t8991870000000000001\t+919829077112
AIR-103\tAirtel\t14/01/2026\t02:15:15\t+919829077112\t+919876543210\t70\t356938035643801\t405870000000001\tRJ-JPR-SHY-019\t8991870000000000001\t+919829077112
AIR-104\tAirtel\t14/01/2026\t02:17:17\t+919829077112\t+919876543211\t76\t356938035643801\t405870000000001\tRJ-JPR-SHY-019\t8991870000000000001\t+919829077112
AIR-105\tAirtel\t14/01/2026\t02:20:20\t+919829077112\t+919876543212\t85\t356938035643801\t405870000000001\tRJ-JPR-SHY-019\t8991870000000000001\t+919829077112
AIR-106\tAirtel\t14/01/2026\t01:48:10\t+919876543210\t+919876543211\t142\t356938035643819\t405870000000002\tRJ-JPR-MAN-042\t8991870000000000002\t+919876543210
AIR-107\tAirtel\t14/01/2026\t01:54:30\t+919876543210\t+919876543212\t118\t356938035643819\t405870000000002\tRJ-JPR-MAN-042\t8991870000000000002\t+919876543210
AIR-108\tAirtel\t14/01/2026\t02:19:10\t+919876543210\t+919876543211\t92\t356938035643819\t405870000000002\tRJ-JPR-MAN-042\t8991870000000000002\t+919876543210
AIR-109\tAirtel\t14/01/2026\t02:26:05\t+919876543210\t+919811004421\t184\t356938035643819\t405870000000002\tRJ-JPR-MAL-008\t8991870000000000002\t+919876543210
AIR-110\tAirtel\t14/01/2026\t11:18:45\t+919876543210\t+919876543212\t64\t356938035643819\t405870000000002\tRJ-JPR-TNK-024\t8991870000000000002\t+919876543210
AIR-111\tAirtel\t14/01/2026\t14:22:10\t+919876543210\t+919876543213\t129\t356938035643819\t405870000000002\tRJ-JPR-MAL-008\t8991870000000000002\t+919876543210`;

export const SAMPLE_VI_CDR_CSV = `record_id,telco,timestamp,caller_msisdn,callee_msisdn,duration_sec,call_type,imei,imsi,cell_tower_id,iccid,observed_msisdn
VI-201,Vi,2026-01-14T02:24:24+05:30,+919829077112,+919876543210,97,VOICE_OUT,356938035643819,405870000000001,RJ-JPR-SHY-019,8991870000000000001,+919829077112
VI-202,Vi,2026-01-14T02:25:25+05:30,+919829077112,+919876543211,100,VOICE_OUT,356938035643819,405870000000019,RJ-JPR-SHY-019,8991870000000000019,+919829077112
VI-203,Vi,2026-01-14T02:27:27+05:30,+919829077112,+919876543212,106,VOICE_OUT,356938035643819,405870000000019,RJ-JPR-SHY-019,8991870000000000019,+919829077112
VI-204,Vi,2026-01-14T02:30:30+05:30,+919829077112,+919876543210,115,VOICE_OUT,356938035643819,405870000000019,RJ-JPR-MAN-042,8991870000000000019,+919829077112
VI-205,Vi,2026-01-14T02:34:34+05:30,+919829077112,+919876543211,127,VOICE_OUT,356938035643819,405870000000019,RJ-JPR-MAL-008,8991870000000000019,+919829077112
VI-206,Vi,2026-01-14T09:12:00+05:30,+919876543211,+919876543212,88,VOICE_OUT,356938035643827,405870000000003,RJ-JPR-MAN-042,8991870000000000003,+919876543211
VI-207,Vi,2026-01-14T10:45:15+05:30,+919876543211,+919876543213,154,VOICE_OUT,356938035643827,405870000000003,RJ-JPR-MAL-008,8991870000000000003,+919876543211
VI-208,Vi,2026-01-14T13:18:40+05:30,+919876543211,+919811004421,72,VOICE_OUT,356938035643827,405870000000003,RJ-JPR-TNK-024,8991870000000000003,+919876543211`;

export const SAMPLE_BSNL_CDR_CSV = `record_id,telco,timestamp,caller_msisdn,callee_msisdn,duration_sec,call_type,imei,imsi,cell_tower_id,iccid,observed_msisdn
BSNL-301,BSNL,2026-01-14T02:41:41+05:30,+919829077112,+919876543212,148,VOICE_OUT,356938035643819,405870000000019,RJ-JPR-MAN-042,8991870000000000019,+919829077112
BSNL-302,BSNL,2026-01-14T02:45:45+05:30,+919829077112,+919876543210,160,VOICE_OUT,356938035643819,405870000000019,RJ-JPR-SHY-019,8991870000000000019,+919829077112
BSNL-303,BSNL,2026-01-14T03:12:00+05:30,+919876543213,+919829077112,215,VOICE_IN,356938035643819,405870000000019,RJ-JPR-CSH-011,8991870000000000019,+919829077112
BSNL-304,BSNL,2026-01-14T15:30:22+05:30,+919829077112,+919876543210,54,VOICE_OUT,356938035643819,405870000000019,RJ-JPR-TNK-024,8991870000000000019,+919829077112
BSNL-305,BSNL,2026-01-14T17:10:05+05:30,+919876543212,+919876543210,112,VOICE_OUT,356938035643835,405870000000004,RJ-JPR-SHY-019,8991870000000000004,+919876543212`;

export const SAMPLE_IPDR_CSV = `record_id,telco,session_start,session_end,caller_msisdn,imei,imsi,public_ip,source_port,alloc_port_start,alloc_port_end,protocol,cell_tower_id,iccid,application,service,destination_host
NAT-001,Jio 5G,2026-01-14T02:18:42+05:30,2026-01-14T02:19:04+05:30,+919829077112,356938035643801,405870000000001,157.34.12.89,44120,44000,44250,TCP,RJ-JPR-SHY-019,8991870000000000001,Synthetic Messaging,Encrypted Chat,messaging.example
NAT-002,Airtel,2026-01-14T02:18:36+05:30,2026-01-14T02:18:41+05:30,+919876543210,356938035643819,405870000000002,157.34.12.89,44120,44000,44250,TCP,RJ-JPR-MAN-042,8991870000000000002,UPI Banking Portal,Financial Transfer,payments.demo.in
NAT-003,Vi,2026-01-14T02:18:41+05:30,2026-01-14T02:19:00+05:30,+919876543211,356938035643827,405870000000003,157.34.12.89,44310,44300,44400,UDP,RJ-JPR-MAN-042,8991870000000000003,VoIP Relay,Voice over IP,stun.voip.example
NAT-004,Jio 5G,2026-01-14T02:24:50+05:30,2026-01-14T02:27:15+05:30,+919829077112,356938035643819,405870000000019,157.34.12.89,51204,51000,51500,TCP,RJ-JPR-SHY-019,8991870000000000019,Cloud File Drop,File Transfer,drop.storage.example
NAT-005,Airtel,2026-01-14T02:26:10+05:30,2026-01-14T02:29:40+05:30,+919876543210,356938035643819,405870000000002,49.36.218.44,33180,33000,33500,TCP,RJ-JPR-MAL-008,8991870000000000002,Crypto Exchange API,Financial / Web3,api.ledger.example
NAT-006,Vi,2026-01-14T10:48:00+05:30,,+919876543211,356938035643827,405870000000003,106.215.90.14,60112,60000,60200,UDP,RJ-JPR-MAL-008,8991870000000000003,VPN Tunnel,Anonymization,wg-node04.example`;

export const DOWNLOADABLE_SAMPLES: Array<{
  fileName: string;
  label: string;
  description: string;
  content: string;
  mimeType: string;
}> = [
  {
    fileName: 'Jio_CDR.csv',
    label: 'Jio 5G CDR (CSV)',
    description: 'ISO-8601 IST timestamps with canonical operator headers',
    content: SAMPLE_JIO_CDR_CSV,
    mimeType: 'text/csv',
  },
  {
    fileName: 'Airtel_CDR.tsv',
    label: 'Airtel CDR (TSV)',
    description: 'Tab-separated format with split DD/MM/YYYY date & time columns',
    content: SAMPLE_AIRTEL_CDR_TSV,
    mimeType: 'text/tab-separated-values',
  },
  {
    fileName: 'Vi_CDR.csv',
    label: 'Vi CDR (CSV)',
    description: 'Contains Rohan Mehta IMEI switch & IMSI/ICCID SIM swap rows',
    content: SAMPLE_VI_CDR_CSV,
    mimeType: 'text/csv',
  },
  {
    fileName: 'Carrier_IPDR.csv',
    label: 'Carrier CGNAT IPDR (CSV)',
    description: 'Public IPv4, CGNAT port blocks, timestamps & app indicators',
    content: SAMPLE_IPDR_CSV,
    mimeType: 'text/csv',
  },
  {
    fileName: 'BSNL_CDR.csv',
    label: 'BSNL CDR (CSV)',
    description: 'Synthetic incoming and outgoing call records',
    content: SAMPLE_BSNL_CDR_CSV,
    mimeType: 'text/csv',
  },
  {
    fileName: 'CCTNS_Suspects.csv',
    label: 'Synthetic subject register (CSV)',
    description: 'Case identities and associated phone numbers',
    content: SAMPLE_SUSPECTS_CSV,
    mimeType: 'text/csv',
  },
  {
    fileName: 'RJ_UP_Cell_Dump.csv',
    label: 'Jaipur Cell Tower Dump (CSV)',
    description: 'Serving cell coordinates and sector azimuth angles',
    content: SAMPLE_TOWERS_CSV,
    mimeType: 'text/csv',
  },
];

function deterministicHash(seed: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x243f6a88;
  for (let i = 0; i < seed.length; i++) {
    h1 = Math.imul(h1 ^ seed.charCodeAt(i), 0x01000193);
    h2 = Math.imul(h2 ^ (seed.charCodeAt(i) + i), 0x85ebca6b);
  }
  const hex =
    (h1 >>> 0).toString(16).padStart(8, '0') +
    (h2 >>> 0).toString(16).padStart(8, '0');
  return (hex + hex + hex + hex).slice(0, 64);
}

/**
 * Builds the default pre-loaded synthetic Case PS03 workspace synchronously.
 */
export function buildDefaultCasePS03(): CaseFile {
  const bundles: Array<{
    id: string;
    fileName: string;
    content: string;
  }> = [
    { id: 'src-suspects', fileName: 'CCTNS_Suspects.csv', content: SAMPLE_SUSPECTS_CSV },
    { id: 'src-towers', fileName: 'RJ_UP_Cell_Dump.csv', content: SAMPLE_TOWERS_CSV },
    { id: 'src-jio', fileName: 'Jio_CDR.csv', content: SAMPLE_JIO_CDR_CSV },
    { id: 'src-airtel', fileName: 'Airtel_CDR.tsv', content: SAMPLE_AIRTEL_CDR_TSV },
    { id: 'src-vi', fileName: 'Vi_CDR.csv', content: SAMPLE_VI_CDR_CSV },
    { id: 'src-bsnl', fileName: 'BSNL_CDR.csv', content: SAMPLE_BSNL_CDR_CSV },
    { id: 'src-ipdr', fileName: 'Carrier_IPDR.csv', content: SAMPLE_IPDR_CSV },
  ];

  const caseFile: CaseFile = {
    id: 'case-ps03',
    caseNumber: 'PS03-JPR-2026',
    title: 'Jaipur Cyber-Telecom Fraud Ring',
    station: 'Cyber Crime Police Station, Jaipur (Synthetic PS03)',
    brief:
      'Synthetic investigation into coordinated late-night telecom activity across Mansarovar, Shyam Nagar, and Malviya Nagar sectors in Jaipur. Focuses on Rohan Mehta (+919829077112) and Aman Verma (+919876543210), potential shared third-party handlers, mid-night IMEI/SIM swap events, and CGNAT public IP 157.34.12.89 attribution.',
    createdAt: '2026-01-14T08:00:00+05:30',
    createdBy: 'Insp. Kavita Rathore',
    status: 'Active',
    sources: [],
    suspects: [],
    towers: [],
    cdrs: [],
    ipdrs: [],
    findings: [
      {
        id: 'find-init-1',
        caseId: 'case-ps03',
        title: 'Shared Handset IMEI Overlap (Rohan Mehta & Aman Verma)',
        summary:
          'Handset IMEI 356938035643819 appears on Aman Verma (+919876543210) at 01:48:10 IST and subsequently on Rohan Mehta (+919829077112) starting 02:24:24 IST after Rohan switched away from IMEI 356938035643801.',
        source: 'automated_rule',
        status: 'pending_review',
        createdBy: 'Darpan Correlation Engine',
        createdAt: '2026-01-14T08:15:00+05:30',
        citations: [
          {
            sourceFile: 'Airtel_CDR.tsv',
            rowNumber: 7,
            recordId: 'AIR-106',
            recordType: 'cdr',
            timestamp: '2026-01-14T01:48:10+05:30',
            numbers: ['+919876543210', '+919876543211'],
            summary: 'Airtel call +919876543210 -> +919876543211 using IMEI 356938035643819',
          },
          {
            sourceFile: 'Vi_CDR.csv',
            rowNumber: 2,
            recordId: 'VI-201',
            recordType: 'cdr',
            timestamp: '2026-01-14T02:24:24+05:30',
            numbers: ['+919829077112', '+919876543210'],
            summary: 'Vi call +919829077112 -> +919876543210 switched to IMEI 356938035643819',
          },
        ],
      },
      {
        id: 'find-init-2',
        caseId: 'case-ps03',
        title: 'Unique CGNAT IP Attribution for 157.34.12.89:44120',
        summary:
          'At 02:18:45 IST on 14/01/2026, TCP traffic from public IP 157.34.12.89 port 44120 uniquely maps to Rohan Mehta (+919829077112) via NAT-001 (Jio 5G, Shyam Nagar tower, application: Synthetic Messaging).',
        source: 'automated_rule',
        status: 'verified',
        createdBy: 'Insp. Kavita Rathore',
        createdAt: '2026-01-14T08:22:00+05:30',
        reviewedBy: 'DSP Arvind Shekhawat',
        reviewedAt: '2026-01-14T09:05:00+05:30',
        reviewerNote: 'Cross-checked against Carrier_IPDR.csv row 2; timestamp falls cleanly within 02:18:42–02:19:04 IST window.',
        citations: [
          {
            sourceFile: 'Carrier_IPDR.csv',
            rowNumber: 2,
            recordId: 'NAT-001',
            recordType: 'ipdr',
            timestamp: '2026-01-14T02:18:42+05:30',
            numbers: ['+919829077112'],
            summary: 'Jio 5G IPDR 157.34.12.89:44120 (TCP) -> +919829077112 [Synthetic Messaging]',
          },
        ],
      },
    ],
  };

  for (const b of bundles) {
    const parsed = parseDelimitedText(b.content);
    const detected = detectOperatorSchema(parsed.headers, parsed.rows, b.fileName);
    const norm = normalizeDatasetRows({
      sourceId: b.id,
      fileName: b.fileName,
      datasetType: detected.datasetType,
      operator: detected.operator,
      uploadedBy: 'Insp. Kavita Rathore',
      sha256: deterministicHash(`${b.fileName}:${b.content}`),
      rows: parsed.rows,
      columnMapping: detected.suggestedMapping,
    });
    caseFile.sources.push(norm.sourceMeta);
    caseFile.cdrs.push(...norm.cdrs);
    caseFile.ipdrs.push(...norm.ipdrs);
    caseFile.towers.push(...norm.towers);
    caseFile.suspects.push(...norm.suspects);
  }

  return caseFile;
}

export function buildInitialAuditLogs(): AuditLogEntry[] {
  return [
    {
      id: 'aud-1',
      caseId: 'case-ps03',
      timestamp: '2026-01-14T08:02:11+05:30',
      actor: 'Insp. Kavita Rathore',
      role: 'investigator',
      action: 'EVIDENCE_IMPORT',
      detail: 'Imported 7 multi-operator synthetic evidence files (Jio 5G, Airtel TSV, Vi, BSNL, IPDR, Cell Dump, CCTNS Suspects) with SHA-256 verification.',
    },
    {
      id: 'aud-2',
      caseId: 'case-ps03',
      timestamp: '2026-01-14T08:20:04+05:30',
      actor: 'Insp. Kavita Rathore',
      role: 'investigator',
      action: 'IPDR_LOOKUP',
      detail: 'Executed CGNAT correlation for 157.34.12.89:44120 TCP @ 2026-01-14T02:18:45+05:30 -> Unique match NAT-001 (+919829077112).',
    },
    {
      id: 'aud-3',
      caseId: 'case-ps03',
      timestamp: '2026-01-14T09:05:00+05:30',
      actor: 'DSP Arvind Shekhawat',
      role: 'reviewer',
      action: 'FINDING_VERIFY',
      detail: 'Verified finding "Unique CGNAT IP Attribution for 157.34.12.89:44120" against primary source Carrier_IPDR.csv Row 2.',
    },
  ];
}
