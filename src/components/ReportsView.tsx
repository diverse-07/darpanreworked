import React, { useState } from 'react';
import {
  CheckCircle2,
  Download,
  FileSpreadsheet,
  FileText,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import type {
  AuditLogEntry,
  CaseFile,
  EvidenceCitation,
  OfficerSession,
} from '../types/forensics.ts';
import { exportCaseExcelWorkbook, exportCasePdfReport } from '../lib/reports.ts';
import { formatISTDisplay } from '../lib/forensics.ts';

interface ReportsViewProps {
  caseFile: CaseFile;
  officer: OfficerSession | null;
  auditLogs: AuditLogEntry[];
  onInspectCitation: (citation: EvidenceCitation) => void;
  onReviewFinding: (
    findingId: string,
    status: 'verified' | 'rejected',
    note: string
  ) => Promise<void>;
  onLogReportExport: (detail: string) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  caseFile,
  officer,
  auditLogs,
  onInspectCitation,
  onReviewFinding,
  onLogReportExport,
}) => {
  const canVerify = officer?.role === 'reviewer' || officer?.role === 'admin';
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [busyId, setBusyId] = useState<string | null>(null);
  const [exportMessage, setExportMessage] = useState<string | null>(null);

  const handleExportPdf = () => {
    if (!officer) return;
    exportCasePdfReport(caseFile, officer);
    const msg = `Generated Draft Investigation Report PDF for ${caseFile.caseNumber} (${caseFile.findings.length} findings).`;
    setExportMessage(msg);
    onLogReportExport(msg);
  };

  const handleExportExcel = () => {
    if (!officer) return;
    exportCaseExcelWorkbook(caseFile, officer, auditLogs);
    const msg = `Generated Multi-Sheet Excel Workbook (.xlsx) with Section 63 BSA worksheet for ${caseFile.caseNumber}.`;
    setExportMessage(msg);
    onLogReportExport(msg);
  };

  const handleVerifyAction = async (findingId: string, status: 'verified' | 'rejected') => {
    setBusyId(findingId);
    try {
      await onReviewFinding(findingId, status, notes[findingId] || '');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Draft Export Actions */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-white">
            Draft Investigation Reports &amp; Section 63 BSA Package
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 max-w-2xl">
            Export court-reviewable draft PDFs and multi-sheet Excel workbooks containing complete
            normalized CDR/IPDR sheets, shared contacts, IMEI/SIM changes, SHA-256 chain of custody,
            and an unsigned Section 63 BSA certificate worksheet.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={handleExportPdf}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-blue-700 hover:bg-blue-800 text-white transition-colors whitespace-nowrap"
          >
            <FileText className="w-4 h-4" />
            <span>Export Draft PDF</span>
          </button>
          <button
            type="button"
            onClick={handleExportExcel}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-100 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap"
          >
            <FileSpreadsheet className="w-4 h-4 text-emerald-700 dark:text-emerald-400" />
            <span>Export Excel (.xlsx)</span>
          </button>
        </div>
      </section>

      {exportMessage && (
        <div
          role="status"
          className="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/60 text-xs text-emerald-900 dark:text-emerald-200 flex items-center gap-2"
        >
          <Download className="w-4 h-4 shrink-0" />
          <span>{exportMessage}</span>
        </div>
      )}

      {/* Human Verification Queue */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-blue-700 dark:text-blue-400" />
              <span>Officer Verification Queue ({caseFile.findings.length} findings)</span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              AI and automated observations require explicit Senior Reviewer verification against
              primary operator records before being treated as investigative conclusions.
            </p>
          </div>
          {!canVerify && (
            <span className="text-[11px] font-medium text-amber-800 dark:text-amber-300">
              Switch to Senior Reviewer or Admin role in Access &amp; Audit to record sign-off
            </span>
          )}
        </div>

        <div className="divide-y divide-slate-200 dark:divide-slate-800">
          {caseFile.findings.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">
              No findings pinned yet. Pin findings from the AI Investigator, IPDR Lookup, or Evidence
              Inspector.
            </div>
          ) : (
            caseFile.findings.map((finding) => (
              <div key={finding.id} className="p-5 space-y-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="space-y-1 max-w-3xl">
                    <div className="flex flex-wrap items-center gap-x-2 text-xs">
                      <span
                        className={
                          finding.status === 'verified'
                            ? 'font-semibold text-emerald-700 dark:text-emerald-400'
                            : finding.status === 'rejected'
                              ? 'font-semibold text-red-700 dark:text-red-400'
                              : 'font-semibold text-amber-700 dark:text-amber-400'
                        }
                      >
                        {finding.status === 'verified'
                          ? 'Officer Verified'
                          : finding.status === 'rejected'
                            ? 'Rejected'
                            : 'Pending Officer Review'}
                      </span>
                      <span aria-hidden="true" className="text-slate-400">
                        ·
                      </span>
                      <span className="text-slate-500 dark:text-slate-400">
                        Source: {finding.source.replace('_', ' ')}
                      </span>
                      <span aria-hidden="true" className="text-slate-400">
                        ·
                      </span>
                      <span className="text-slate-500 dark:text-slate-400">
                        Logged by {finding.createdBy}
                      </span>
                    </div>
                    <h4 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
                      {finding.title}
                    </h4>
                    <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                      {finding.summary}
                    </p>
                  </div>
                </div>

                {/* Linked Evidence Citations */}
                {finding.citations.length > 0 && (
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
                      Citations:
                    </span>
                    {finding.citations.map((c, idx) => (
                      <button
                        key={`${c.sourceFile}-${c.rowNumber}-${idx}`}
                        type="button"
                        onClick={() => onInspectCitation(c)}
                        className="font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                      >
                        [{c.sourceFile} · Row {c.rowNumber}]
                      </button>
                    ))}
                  </div>
                )}

                {/* Review Outcome or Action Controls */}
                {finding.reviewedBy && (
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 text-xs text-slate-700 dark:text-slate-300">
                    <span className="font-semibold">Reviewed by {finding.reviewedBy}</span>{' '}
                    <span className="font-mono text-[11px] text-slate-500">
                      ({formatISTDisplay(finding.reviewedAt)})
                    </span>
                    {finding.reviewerNote && <p className="mt-1">{finding.reviewerNote}</p>}
                  </div>
                )}

                {canVerify && (
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <input
                      type="text"
                      aria-label={`Verification note for ${finding.title}`}
                      value={notes[finding.id] ?? finding.reviewerNote ?? ''}
                      onChange={(e) =>
                        setNotes((prev) => ({ ...prev, [finding.id]: e.target.value }))
                      }
                      placeholder="Add officer verification remark (checked against operator row)..."
                      className="flex-1 min-w-[220px] text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-1.5 text-slate-900 dark:text-slate-100"
                    />
                    <button
                      type="button"
                      disabled={busyId === finding.id}
                      onClick={() => handleVerifyAction(finding.id, 'verified')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-700 hover:bg-emerald-800 text-white disabled:opacity-50"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Verify Finding</span>
                    </button>
                    <button
                      type="button"
                      disabled={busyId === finding.id}
                      onClick={() => handleVerifyAction(finding.id, 'rejected')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-red-200 dark:border-red-900/60 text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 disabled:opacity-50"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Reject</span>
                    </button>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
};
