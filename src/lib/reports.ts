import * as XLSX from 'xlsx';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { AuditLogEntry, CaseFile, OfficerSession } from '../types/forensics.ts';
import {
  analyzeContactPatterns,
  detectDeviceSimChanges,
  findCommonContacts,
  formatDuration,
  formatISTDisplay,
  isVoiceCall,
} from './forensics.ts';

/**
 * Neutralizes spreadsheet formula injection (cells beginning with =, +, -, @, \t, \r).
 */
export function sanitizeCell(value: unknown): string | number {
  if (typeof value === 'number') return value;
  const s = value === undefined || value === null ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) {
    return `'${s}`;
  }
  return s;
}

const nightHeaders = ['Timestamp (IST)', 'Operator', 'Caller', 'Callee', 'Duration (sec)', 'Source File', 'Source Row'];

function nightActivityRows(caseFile: CaseFile): Array<Array<string | number>> {
  return caseFile.cdrs.filter(row => row.isNight && isVoiceCall(row))
    .sort((a, b) => a.epochMs - b.epochMs)
    .map(row => [formatISTDisplay(row.timestampIso), row.operator, row.caller, row.callee, row.durationSec, row.sourceFile, row.rowNumber]);
}

/**
 * Exports a comprehensive multi-sheet Excel (.xlsx) draft investigation workbook.
 * Includes normalized CDR/IPDR sheets, shared contacts, IMEI/SIM changes,
 * verified findings, SHA-256 custody manifest, and an unsigned Section 63 BSA worksheet.
 */
export function exportCaseExcelWorkbook(
  caseFile: CaseFile,
  officer: OfficerSession,
  auditLogs: AuditLogEntry[]
): void {
  const wb = XLSX.utils.book_new();
  const generatedAt = new Date().toISOString();

  // Sheet 1: Case Executive Summary
  const summaryRows = [
    ['DARPAN FORENSICS — DRAFT TELECOM INVESTIGATION WORKBOOK'],
    ['NOTICE', 'DRAFT FOR OFFICER REVIEW ONLY. AI OBSERVATIONS REQUIRE INDEPENDENT VERIFICATION AGAINST PRIMARY TELECOM RECORDS.'],
    [],
    ['Case Number', sanitizeCell(caseFile.caseNumber)],
    ['Case Title', sanitizeCell(caseFile.title)],
    ['Police Station / Unit', sanitizeCell(caseFile.station)],
    ['Prepared By', sanitizeCell(`${officer.displayName} (${officer.badgeNumber}, ${officer.role.toUpperCase()})`)],
    ['Generated At (UTC)', sanitizeCell(generatedAt)],
    ['Case Brief', sanitizeCell(caseFile.brief)],
    [],
    ['Total Evidence Files', caseFile.sources.length],
    ['Normalized CDR Records', caseFile.cdrs.length],
    ['Normalized IPDR Records', caseFile.ipdrs.length],
    ['Mapped Cell Towers', caseFile.towers.length],
    ['Registered Suspects', caseFile.suspects.length],
    ['Officer-Verified Findings', caseFile.findings.filter((f) => f.status === 'verified').length],
    ['Pending Review Findings', caseFile.findings.filter((f) => f.status === 'pending_review').length],
  ];
  const wsSummary = XLSX.utils.aoa_to_sheet(summaryRows);
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Case Summary');

  // Sheet 2: Findings & Verification
  const findingHeaders = [
    'Finding ID',
    'Status',
    'Title',
    'Analytical Summary',
    'Source Type',
    'Created By',
    'Reviewed By',
    'Reviewer Note',
    'Evidence Citations',
  ];
  const findingData = caseFile.findings.map((f) => [
    sanitizeCell(f.id),
    sanitizeCell(f.status.toUpperCase()),
    sanitizeCell(f.title),
    sanitizeCell(f.summary),
    sanitizeCell(f.source),
    sanitizeCell(f.createdBy),
    sanitizeCell(f.reviewedBy || 'Pending Officer Review'),
    sanitizeCell(f.reviewerNote || ''),
    sanitizeCell(f.citations.map((c) => `${c.sourceFile}:Row ${c.rowNumber} (${c.recordId})`).join('; ')),
  ]);
  XLSX.utils.book_append_sheet(
    wb,
    XLSX.utils.aoa_to_sheet([findingHeaders, ...findingData]),
    'Findings & Review'
  );

  // Sheet 3: Common Contacts & Device Changes
  const suspectPhones = caseFile.suspects.slice(0, 5).map((s) => s.phone);
  const common = findCommonContacts(caseFile.cdrs, caseFile.suspects, suspectPhones);
  const deviceRes = detectDeviceSimChanges(caseFile.cdrs, caseFile.suspects);

  const corrRows: Array<Array<string | number>> = [
    ['SHARED THIRD-PARTY CONTACTS ACROSS SUSPECTS'],
    ['Contact Number', 'Known Name', 'Connected Suspects', 'Total Calls', 'Total Duration (s)', 'Night Calls', 'Sample Citations'],
    ...common.sharedContacts.map((sc) => [
      sanitizeCell(sc.contactNumber),
      sanitizeCell(sc.contactName || 'Unidentified External'),
      sanitizeCell(sc.connectedSuspects.join(', ')),
      sc.totalSharedCalls,
      sc.totalDurationSec,
      sc.nightCalls,
      sanitizeCell(sc.citations.slice(0, 4).map((c) => `${c.sourceFile}:Row ${c.rowNumber}`).join('; ')),
    ]),
    [],
    ['IMEI / SIM (IMSI & ICCID) CHANGE EVENTS'],
    ['MSISDN', 'Suspect', 'Change Type', 'Previous Value', 'New Value', 'Prev Timestamp (IST)', 'New Timestamp (IST)', 'Citations'],
    ...deviceRes.changes.map((ch) => [
      sanitizeCell(ch.msisdn),
      sanitizeCell(ch.suspectName || 'Unknown'),
      sanitizeCell(ch.changeType),
      sanitizeCell(ch.previousValue),
      sanitizeCell(ch.newValue),
      sanitizeCell(formatISTDisplay(ch.previousTimestampIso)),
      sanitizeCell(formatISTDisplay(ch.newTimestampIso)),
      sanitizeCell(`${ch.previousCitation.sourceFile}:Row ${ch.previousCitation.rowNumber} -> ${ch.newCitation.sourceFile}:Row ${ch.newCitation.rowNumber}`),
    ]),
    [],
    ['CROSS-SUSPECT SHARED IMEI HANDSETS'],
    ['IMEI', 'MSISDNs Observed', 'Citations'],
    ...deviceRes.sharedDevices.map((sh) => [
      sanitizeCell(sh.imei),
      sanitizeCell(sh.msisdns.map((m) => `${m.name || m.phone} (${m.phone}, ${m.count} calls)`).join(' | ')),
      sanitizeCell(sh.citations.map((c) => `${c.sourceFile}:Row ${c.rowNumber}`).join('; ')),
    ]),
  ];
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(corrRows), 'Correlation & Devices');

  // Sheet 4: Normalized CDRs
  const cdrHeaders = [
    'Record ID',
    'Source File',
    'Source Row',
    'Operator',
    'Timestamp (IST)',
    'Night (00-06 IST)',
    'Caller MSISDN',
    'Callee MSISDN',
    'Observed MSISDN',
    'Duration (sec)',
    'IMEI',
    'IMSI',
    'ICCID',
    'Cell Tower ID',
  ];
  const cdrRows = caseFile.cdrs.map((r) => [
    sanitizeCell(r.id),
    sanitizeCell(r.sourceFile),
    r.rowNumber,
    sanitizeCell(r.operator),
    sanitizeCell(r.timestampIso),
    r.isNight ? 'YES' : 'NO',
    sanitizeCell(r.caller),
    sanitizeCell(r.callee),
    sanitizeCell(r.observedMsisdn),
    r.durationSec,
    sanitizeCell(r.imei || ''),
    sanitizeCell(r.imsi || ''),
    sanitizeCell(r.iccid || ''),
    sanitizeCell(r.cellTowerId || ''),
  ]);
  XLSX.utils.book_append_sheet(
    wb,
    XLSX.utils.aoa_to_sheet([cdrHeaders, ...cdrRows]),
    'Normalized CDRs'
  );

  // Sheet 5: Normalized IPDRs
  const ipdrHeaders = [
    'Record ID',
    'Source File',
    'Source Row',
    'Operator',
    'Session Start (IST)',
    'Session End (IST)',
    'MSISDN',
    'Public IPv4',
    'Source Port',
    'Alloc Port Start',
    'Alloc Port End',
    'Protocol',
    'Cell Tower',
    'Application Indicator',
    'Service',
    'Destination Host',
  ];
  const ipdrRows = caseFile.ipdrs.map((r) => [
    sanitizeCell(r.id),
    sanitizeCell(r.sourceFile),
    r.rowNumber,
    sanitizeCell(r.operator),
    sanitizeCell(r.sessionStartIso),
    sanitizeCell(r.sessionEndIso || 'Point Observation'),
    sanitizeCell(r.msisdn),
    sanitizeCell(r.publicIp),
    r.sourcePort ?? '',
    r.allocPortStart ?? '',
    r.allocPortEnd ?? '',
    sanitizeCell(r.protocol),
    sanitizeCell(r.cellTowerId || ''),
    sanitizeCell(r.application || ''),
    sanitizeCell(r.service || ''),
    sanitizeCell(r.destinationHost || ''),
  ]);
  XLSX.utils.book_append_sheet(
    wb,
    XLSX.utils.aoa_to_sheet([ipdrHeaders, ...ipdrRows]),
    'Normalized IPDRs'
  );

  // Sheet 6: Chain of Custody & Unsigned Section 63 BSA Worksheet
  const custodyRows: Array<Array<string | number>> = [
    ['CHAIN OF CUSTODY — SHA-256 FILE MANIFEST'],
    ['Source File', 'Dataset Type', 'Operator', 'Valid Rows', 'Rejected Rows', 'Uploaded By', 'Uploaded At', 'SHA-256 Digest'],
    ...caseFile.sources.map((s) => [
      sanitizeCell(s.fileName),
      sanitizeCell(s.datasetType.toUpperCase()),
      sanitizeCell(s.operator),
      s.validRowCount,
      s.rejectedRowCount,
      sanitizeCell(s.uploadedBy),
      sanitizeCell(s.uploadedAt),
      sanitizeCell(s.sha256),
    ]),
    [],
    ['UNSIGNED SECTION 63 (BHARATIYA SAKSHYA ADHINIYAM, 2023) CERTIFICATE WORKSHEET'],
    ['Status', 'UNSIGNED DRAFT — Must be completed and signed by the Nodal Officer / Certifying Authority'],
    ['Case / FIR Reference', sanitizeCell(caseFile.caseNumber)],
    ['Investigating Unit', sanitizeCell(caseFile.station)],
    ['Part A — Device / System Particulars', 'Enter telecom operator lawful-interception / billing server details here'],
    ['Part B — Hash Verification', 'Verify SHA-256 digests listed above against original operator-supplied electronic files'],
    ['Certifying Officer Signature & Seal', '____________________________________________'],
    [],
    ['RECENT CASE ACTIVITY AUDIT LOG (LAST 25 EVENTS)'],
    ['Timestamp', 'Officer', 'Role', 'Action', 'Detail'],
    ...auditLogs.slice(0, 25).map((a) => [
      sanitizeCell(a.timestamp),
      sanitizeCell(a.actor),
      sanitizeCell(a.role.toUpperCase()),
      sanitizeCell(a.action),
      sanitizeCell(a.detail),
    ]),
  ];
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(custodyRows), 'Custody & Sec 63');

  const nightRows = nightActivityRows(caseFile);
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([
    ['Night activity (00:00-06:00 IST)', nightRows.length],
    nightHeaders,
    ...nightRows.map(row => row.map(sanitizeCell)),
  ]), 'Night Activity');

  const safeName = caseFile.caseNumber.replace(/[^a-zA-Z0-9_-]/g, '_');
  XLSX.writeFile(wb, `Darpan_Draft_Report_${safeName}.xlsx`);
}

/**
 * Generates a court-ready Draft Investigation Report PDF with verification status,
 * evidence tables, truncation disclosures, and SHA-256 chain of custody.
 */
export function exportCasePdfReport(
  caseFile: CaseFile,
  officer: OfficerSession
): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();

  // Header Banner
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, 84, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.text('DARPAN FORENSICS — DRAFT INVESTIGATION REPORT', 40, 36);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(203, 213, 225);
  doc.text(
    `Case ${caseFile.caseNumber} · ${caseFile.title} · Prepared by ${officer.displayName} (${officer.role.toUpperCase()})`,
    40,
    56
  );
  doc.text(
    `Generated: ${new Date().toISOString()}  |  DRAFT — Requires Officer Verification Before Filing`,
    40,
    70
  );

  // Brief & Scope Notice
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text('1. Case Overview & Verification Safeguard', 40, 108);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(51, 65, 85);
  const briefLines = doc.splitTextToSize(caseFile.brief, pageWidth - 80);
  doc.text(briefLines, 40, 124);

  let yPos = 128 + briefLines.length * 13;
  doc.setDrawColor(217, 119, 6);
  doc.setFillColor(255, 251, 235);
  doc.roundedRect(40, yPos, pageWidth - 80, 36, 4, 4, 'FD');
  doc.setTextColor(146, 64, 14);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.text(
    'ACCOUNTABILITY NOTICE: All automated correlations and AI-generated analytical notes are investigative leads only.',
    50,
    yPos + 14
  );
  doc.setFont('helvetica', 'normal');
  doc.text(
    'Every conclusion must be independently verified against original operator-certified CDR/IPDR records under Section 63 BSA.',
    50,
    yPos + 27
  );

  yPos += 54;

  // Section 2: Findings Table
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text('2. Recorded & Verified Investigative Findings', 40, yPos);

  autoTable(doc, {
    startY: yPos + 8,
    head: [['Status', 'Finding', 'Evidence Citations', 'Officer Review']],
    body: caseFile.findings.map((f) => [
      f.status.replace('_', ' ').toUpperCase(),
      `${f.title}\n${f.summary}`,
      f.citations.map((c) => `${c.sourceFile} (Row ${c.rowNumber})`).join('\n'),
      f.reviewedBy ? `${f.reviewedBy}\n${f.reviewerNote || ''}` : 'Pending Review',
    ]),
    styles: { fontSize: 8, cellPadding: 5, valign: 'top' },
    headStyles: { fillColor: [30, 58, 138], textColor: 255 },
    columnStyles: {
      0: { cellWidth: 68 },
      1: { cellWidth: 215 },
      2: { cellWidth: 120 },
      3: { cellWidth: 112 },
    },
    margin: { left: 40, right: 40 },
  });

  // Section 3: Key Communication & Device Summary
  const afterFindingsY = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY ?? yPos + 80;
  const primarySuspect = caseFile.suspects[0];
  const primaryAnalysis = primarySuspect
    ? analyzeContactPatterns(caseFile.cdrs, caseFile.suspects, primarySuspect.phone)
    : null;
  const deviceRes = detectDeviceSimChanges(caseFile.cdrs, caseFile.suspects);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('3. Device / SIM Swaps & Shared Handsets', 40, afterFindingsY + 24);

  autoTable(doc, {
    startY: afterFindingsY + 32,
    head: [['Subject', 'Event Type', 'Previous -> New', 'Timestamp (IST)', 'Source Ref']],
    body: [
      ...deviceRes.changes.map((c) => [
        `${c.suspectName || c.msisdn}\n${c.msisdn}`,
        c.changeType.replace(/_/g, ' '),
        `${c.previousValue} -> ${c.newValue}`,
        formatISTDisplay(c.newTimestampIso),
        `${c.newCitation.sourceFile}:Row ${c.newCitation.rowNumber}`,
      ]),
      ...deviceRes.sharedDevices.map((s) => [
        s.msisdns.map((m) => m.name || m.phone).join(' & '),
        'SHARED IMEI HANDSET',
        s.imei,
        formatISTDisplay(s.msisdns[0]?.firstIso),
        s.citations.map((c) => `${c.sourceFile}:R${c.rowNumber}`).join(', '),
      ]),
    ],
    styles: { fontSize: 8, cellPadding: 5 },
    headStyles: { fillColor: [15, 23, 42], textColor: 255 },
    margin: { left: 40, right: 40 },
  });

  // Section 4: Top Contacts & Custody on Page 2
  doc.addPage();
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text(
    `4. Top Contact Activity${primaryAnalysis ? ` (${primaryAnalysis.targetName ?? primaryAnalysis.targetNumber})` : ''}`,
    40,
    46
  );

  if (primaryAnalysis) {
    const truncated = primaryAnalysis.contacts.length > 15;
    autoTable(doc, {
      startY: 54,
      head: [['Contact', 'Total Calls', 'Out / In', 'Duration', 'Night Calls', 'Anomalies']],
      body: primaryAnalysis.contacts.slice(0, 15).map((c) => [
        `${c.contactName ? `${c.contactName}\n` : ''}${c.contactNumber}`,
        String(c.totalCalls),
        `${c.outgoingCalls} / ${c.incomingCalls}`,
        formatDuration(c.totalDurationSec),
        String(c.nightCalls),
        c.anomalies.join('; ') || 'Nominal',
      ]),
      styles: { fontSize: 8, cellPadding: 5 },
      headStyles: { fillColor: [30, 58, 138], textColor: 255 },
      margin: { left: 40, right: 40 },
    });
    if (truncated) {
      const endY = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY ?? 220;
      doc.setFontSize(8);
      doc.setTextColor(146, 64, 14);
      doc.text(
        `Note: Showing top 15 of ${primaryAnalysis.contacts.length} contacts. Export Excel workbook for complete un-truncated rows.`,
        40,
        endY + 14
      );
    }
  }

  const afterContactsY =
    (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY ?? 240;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('5. Chain-of-Custody Source Manifest (SHA-256)', 40, afterContactsY + 32);

  autoTable(doc, {
    startY: afterContactsY + 40,
    head: [['File Name', 'Type', 'Operator', 'Valid / Rejected', 'SHA-256 Digest (Prefix)']],
    body: caseFile.sources.map((s) => [
      s.fileName,
      s.datasetType.toUpperCase(),
      s.operator,
      `${s.validRowCount} / ${s.rejectedRowCount}`,
      `${s.sha256.slice(0, 28)}...`,
    ]),
    styles: { fontSize: 8, cellPadding: 5 },
    headStyles: { fillColor: [15, 23, 42], textColor: 255 },
    margin: { left: 40, right: 40 },
  });

  const nightRows = nightActivityRows(caseFile);
  if (nightRows.length) {
    const sample = nightRows.slice(0, 30);
    doc.addPage();
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('6. Night Activity (00:00-06:00 IST)', 40, 46);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.text(nightRows.length > sample.length
      ? `Showing the first ${sample.length} of ${nightRows.length} calls. The Excel draft includes all rows.`
      : `${nightRows.length} recorded calls in the night-time window.`, 40, 63);
    autoTable(doc, {
      startY: 73,
      head: [nightHeaders],
      body: sample,
      styles: { fontSize: 8, cellPadding: 5 },
      headStyles: { fillColor: [15, 23, 42], textColor: 255 },
      margin: { left: 40, right: 40 },
    });
  }

  const safeName = caseFile.caseNumber.replace(/[^a-zA-Z0-9_-]/g, '_');
  doc.save(`Darpan_Draft_Report_${safeName}.pdf`);
}
