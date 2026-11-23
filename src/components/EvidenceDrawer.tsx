import React from 'react';
import { BookmarkPlus, FileText, Hash, X } from 'lucide-react';
import type { CaseFile, EvidenceCitation } from '../types/forensics.ts';
import { formatDuration, formatISTDisplay } from '../lib/forensics.ts';

interface EvidenceDrawerProps {
  citation: EvidenceCitation | null;
  activeCase: CaseFile | null;
  onClose: () => void;
  onDownloadOriginal: (id: string, name: string) => Promise<void>;
  onPinFinding: (title: string, summary: string, citations: EvidenceCitation[]) => void;
}

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({
  citation,
  activeCase,
  onClose,
  onDownloadOriginal,
  onPinFinding,
}) => {
  if (!citation || !activeCase) return null;

  const cdrRecord =
    citation.recordType === 'cdr'
      ? activeCase.cdrs.find(
          (r) =>
            r.id === citation.recordId ||
            (r.sourceFile === citation.sourceFile && r.rowNumber === citation.rowNumber)
        )
      : undefined;

  const ipdrRecord =
    citation.recordType === 'ipdr'
      ? activeCase.ipdrs.find(
          (r) =>
            r.id === citation.recordId ||
            (r.sourceFile === citation.sourceFile && r.rowNumber === citation.rowNumber)
        )
      : undefined;

  const sourceMeta = activeCase.sources.find((s) => s.fileName === citation.sourceFile);
  const rawFields = cdrRecord?.rawFields || ipdrRecord?.rawFields;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      role="dialog"
      aria-modal="true"
      aria-label="Primary Source Evidence Inspector"
    >
      <div
        className="fixed inset-0 bg-slate-950/40 backdrop-blur-[1px]"
        onClick={onClose}
        aria-hidden="true"
      />
      <div className="relative z-10 w-full max-w-lg bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 h-full flex flex-col shadow-xl">
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Source record · {citation.recordType.toUpperCase()}
            </p>
            <h2 className="font-display font-semibold text-base text-slate-900 dark:text-white truncate">
              {citation.sourceFile} · Row {citation.rowNumber}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close evidence inspector"
            className="p-2 rounded-lg text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {sourceMeta && <button type="button" onClick={() => void onDownloadOriginal(sourceMeta.id, sourceMeta.fileName)}
            className="text-sm border border-slate-600 rounded-md px-3 py-2">Download original source</button>}
          {/* Custody Strip */}
          <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 space-y-1.5">
            <div className="flex items-center gap-2 text-xs font-medium text-slate-700 dark:text-slate-200">
              <FileText className="w-3.5 h-3.5 text-blue-700 dark:text-blue-400" />
              <span>Record ID:</span>
              <span className="font-mono">{citation.recordId}</span>
            </div>
            {sourceMeta && (
              <div className="flex items-start gap-2 text-xs text-slate-500 dark:text-slate-400">
                <Hash className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                <span className="font-mono break-all text-[11px]">
                  SHA-256: {sourceMeta.sha256}
                </span>
              </div>
            )}
          </div>

          {/* Normalized Fields */}
          {cdrRecord && (
            <section className="space-y-2.5">
              <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                Normalized CDR Record
              </h3>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 text-xs border-t border-slate-200 dark:border-slate-800 pt-3">
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Timestamp (IST)</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {formatISTDisplay(cdrRecord.timestampIso)}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Operator / Window</dt>
                  <dd className="font-medium text-slate-900 dark:text-slate-100">
                    {cdrRecord.operator} · {cdrRecord.isNight ? 'Night (00–06 IST)' : 'Daytime'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Caller (A-Party)</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {cdrRecord.caller}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Callee (B-Party)</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {cdrRecord.callee}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Duration</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {formatDuration(cdrRecord.durationSec)} ({cdrRecord.durationSec}s)
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Serving Cell Tower</dt>
                  <dd className="font-mono font-medium text-slate-900 dark:text-slate-100">
                    {cdrRecord.cellTowerId || 'Not supplied'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Handset IMEI</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {cdrRecord.imei || 'Not supplied'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Subscriber IMSI</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {cdrRecord.imsi || 'Not supplied'}
                  </dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-slate-500 dark:text-slate-400">SIM ICCID</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {cdrRecord.iccid || 'Not supplied'}
                  </dd>
                </div>
              </dl>
            </section>
          )}

          {ipdrRecord && (
            <section className="space-y-2.5">
              <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                Normalized IPDR / CGNAT Session
              </h3>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5 text-xs border-t border-slate-200 dark:border-slate-800 pt-3">
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Session Start (IST)</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {formatISTDisplay(ipdrRecord.sessionStartIso)}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Session End (IST)</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {ipdrRecord.sessionEndIso
                      ? formatISTDisplay(ipdrRecord.sessionEndIso)
                      : 'Point Observation'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Subscriber MSISDN</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {ipdrRecord.msisdn}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Public IPv4 / Protocol</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {ipdrRecord.publicIp} ({ipdrRecord.protocol})
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Source Port</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {ipdrRecord.sourcePort ?? '—'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">CGNAT Port Block</dt>
                  <dd className="font-mono tabular-nums font-medium text-slate-900 dark:text-slate-100">
                    {ipdrRecord.allocPortStart !== undefined && ipdrRecord.allocPortEnd !== undefined
                      ? `${ipdrRecord.allocPortStart}–${ipdrRecord.allocPortEnd}`
                      : 'Not supplied'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Application Indicator</dt>
                  <dd className="font-medium text-slate-900 dark:text-slate-100">
                    {ipdrRecord.application || 'Not supplied'}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">Destination Host</dt>
                  <dd className="font-mono text-slate-900 dark:text-slate-100">
                    {ipdrRecord.destinationHost || 'Not supplied'}
                  </dd>
                </div>
              </dl>
            </section>
          )}

          {/* Raw Operator Row */}
          {rawFields && Object.keys(rawFields).length > 0 && (
            <section className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                Unmodified Operator Row Fields
              </h3>
              <div className="border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-xs">
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                    {Object.entries(rawFields).map(([k, v]) => (
                      <tr key={k}>
                        <td className="px-3 py-2 font-medium text-slate-500 dark:text-slate-400 bg-slate-50/70 dark:bg-slate-800/40 w-2/5">
                          {k}
                        </td>
                        <td className="px-3 py-2 font-mono text-slate-900 dark:text-slate-100 break-all">
                          {v || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </div>

        {/* Footer Action */}
        <div className="px-5 py-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            Verify against operator certificate before court submission.
          </p>
          <button
            type="button"
            onClick={() => {
              onPinFinding(
                `Evidence Pin: ${citation.sourceFile} Row ${citation.rowNumber}`,
                citation.summary,
                [citation]
              );
              onClose();
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 dark:bg-blue-700 dark:hover:bg-blue-600 text-white whitespace-nowrap shrink-0"
          >
            <BookmarkPlus className="w-3.5 h-3.5" />
            <span>Pin to Report</span>
          </button>
        </div>
      </div>
    </div>
  );
};
