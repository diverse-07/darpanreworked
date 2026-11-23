import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Search,
} from 'lucide-react';
import type { CaseFile, EvidenceCitation } from '../types/forensics.ts';
import {
  analyzeContactPatterns,
  cdrToCitation,
  formatDuration,
  formatISTDisplay,
} from '../lib/forensics.ts';

interface ContactAnalysisViewProps {
  caseFile: CaseFile;
  initialSuspectPhone?: string;
  initialNightOnly?: boolean;
  onInspectCitation: (citation: EvidenceCitation) => void;
}

export const ContactAnalysisView: React.FC<ContactAnalysisViewProps> = ({
  caseFile,
  initialSuspectPhone,
  initialNightOnly = false,
  onInspectCitation,
}) => {
  const defaultTarget =
    initialSuspectPhone || caseFile.suspects[0]?.phone || 'ALL';
  const [targetPhone, setTargetPhone] = useState<string>(defaultTarget);
  const [nightOnly, setNightOnly] = useState<boolean>(initialNightOnly);
  const [operatorFilter, setOperatorFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedContact, setExpandedContact] = useState<string | null>(null);

  const operators = useMemo(() => {
    return Array.from(new Set(caseFile.cdrs.map((r) => r.operator))).sort();
  }, [caseFile.cdrs]);

  const analysis = useMemo(
    () =>
      analyzeContactPatterns(caseFile.cdrs, caseFile.suspects, targetPhone, {
        nightOnly,
        operator: operatorFilter,
      }),
    [caseFile, targetPhone, nightOnly, operatorFilter]
  );

  const filteredContacts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return analysis.contacts;
    return analysis.contacts.filter(
      (c) =>
        c.contactNumber.toLowerCase().includes(q) ||
        (c.contactName || '').toLowerCase().includes(q)
    );
  }, [analysis.contacts, searchQuery]);

  return (
    <div className="space-y-5">
      {/* Filter Toolbar */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-wrap items-end gap-3">
        <div className="min-w-[220px] flex-1">
          <label
            htmlFor="contact-subject-select"
            className="block text-[11px] font-medium text-slate-500 dark:text-slate-400 mb-1"
          >
            Target Suspect / MSISDN
          </label>
          <select
            id="contact-subject-select"
            value={targetPhone}
            onChange={(e) => {
              setTargetPhone(e.target.value);
              setExpandedContact(null);
            }}
            className="w-full text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
          >
            <option value="ALL">All Case Numbers (Aggregate)</option>
            {caseFile.suspects.map((s) => (
              <option key={s.phone} value={s.phone}>
                {s.name} ({s.phone})
              </option>
            ))}
          </select>
        </div>

        <div className="min-w-[150px]">
          <label
            htmlFor="contact-operator-select"
            className="block text-[11px] font-medium text-slate-500 dark:text-slate-400 mb-1"
          >
            Operator
          </label>
          <select
            id="contact-operator-select"
            value={operatorFilter}
            onChange={(e) => setOperatorFilter(e.target.value)}
            className="w-full text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
          >
            <option value="ALL">All Operators</option>
            {operators.map((op) => (
              <option key={op} value={op}>
                {op}
              </option>
            ))}
          </select>
        </div>

        <div className="min-w-[190px] flex-1">
          <label
            htmlFor="contact-search"
            className="block text-[11px] font-medium text-slate-500 dark:text-slate-400 mb-1"
          >
            Filter Contact
          </label>
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              id="contact-search"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Name or +91 number"
              className="w-full text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg pl-8 pr-3 py-2 text-slate-900 dark:text-slate-100"
            />
          </div>
        </div>

        <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg">
          <button
            type="button"
            onClick={() => setNightOnly(false)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              !nightOnly
                ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400'
            }`}
          >
            All Hours
          </button>
          <button
            type="button"
            onClick={() => setNightOnly(true)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              nightOnly
                ? 'bg-white dark:bg-slate-900 text-amber-800 dark:text-amber-300 shadow-sm'
                : 'text-slate-600 dark:text-slate-400'
            }`}
          >
            Night 00–06 IST
          </button>
        </div>
      </section>

      {/* Summary Metrics */}
      <section className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5">
          <p className="text-[11px] text-slate-500 dark:text-slate-400">Total Calls</p>
          <p className="mt-1 font-mono tabular-nums text-xl font-semibold text-slate-900 dark:text-white">
            {analysis.totalCalls}
          </p>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5">
          <p className="text-[11px] text-slate-500 dark:text-slate-400">Out / In Ratio</p>
          <p className="mt-1 font-mono tabular-nums text-xl font-semibold text-slate-900 dark:text-white">
            {analysis.outgoingCalls} / {analysis.incomingCalls}
          </p>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5">
          <p className="text-[11px] text-slate-500 dark:text-slate-400">Talk Duration</p>
          <p className="mt-1 font-mono tabular-nums text-xl font-semibold text-slate-900 dark:text-white">
            {formatDuration(analysis.totalDurationSec)}
          </p>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5">
          <p className="text-[11px] text-slate-500 dark:text-slate-400">Night Share</p>
          <p className="mt-1 font-mono tabular-nums text-xl font-semibold text-amber-700 dark:text-amber-400">
            {analysis.nightCalls} ({analysis.nightRatioPct}%)
          </p>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 col-span-2 lg:col-span-1">
          <p className="text-[11px] text-slate-500 dark:text-slate-400">Unique Contacts</p>
          <p className="mt-1 font-mono tabular-nums text-xl font-semibold text-slate-900 dark:text-white">
            {analysis.uniqueContacts}
          </p>
        </div>
      </section>

      {/* Unusual Pattern Alerts */}
      {analysis.unusualPatterns.length > 0 && (
        <section className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {analysis.unusualPatterns.map((p, idx) => (
            <div
              key={idx}
              className={`p-4 rounded-xl border text-xs space-y-1.5 ${
                p.severity === 'alert'
                  ? 'bg-red-50/60 dark:bg-red-950/25 border-red-200 dark:border-red-900/60'
                  : 'bg-amber-50/60 dark:bg-amber-950/25 border-amber-200 dark:border-amber-900/60'
              }`}
            >
              <div className="flex items-center gap-2 font-semibold text-slate-900 dark:text-white">
                <AlertTriangle className="w-4 h-4 text-amber-700 dark:text-amber-400 shrink-0" />
                <span>{p.title}</span>
              </div>
              <p className="text-slate-700 dark:text-slate-300">{p.detail}</p>
              <div className="flex flex-wrap gap-2 pt-0.5">
                {p.citations.map((c) => (
                  <button
                    key={`${c.sourceFile}-${c.rowNumber}`}
                    type="button"
                    onClick={() => onInspectCitation(c)}
                    className="font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                  >
                    [{c.sourceFile} · Row {c.rowNumber}]
                  </button>
                ))}
              </div>
            </div>
          ))}
        </section>
      )}

      {/* Top Contacts Data Grid with Expandable Primary Records */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
              Frequent Contacts — {analysis.targetName || analysis.targetNumber}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Click any contact row to expand underlying operator CDR records and verify evidence
            </p>
          </div>
          {analysis.firstActivityIso && (
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
              Window: {formatISTDisplay(analysis.firstActivityIso)} →{' '}
              {formatISTDisplay(analysis.lastActivityIso)}
            </span>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400">
                <th className="py-2.5 px-4 font-medium">Contact</th>
                <th className="py-2.5 px-3 font-medium text-right">Calls</th>
                <th className="py-2.5 px-3 font-medium">Out / In Balance</th>
                <th className="py-2.5 px-3 font-medium text-right">Total Dur.</th>
                <th className="py-2.5 px-3 font-medium text-right">Night (00–06)</th>
                <th className="py-2.5 px-3 font-medium">First / Last Seen (IST)</th>
                <th className="py-2.5 px-4 font-medium">Pattern Flags</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {filteredContacts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No contacts match the active filters.
                  </td>
                </tr>
              ) : (
                filteredContacts.map((row) => {
                  const isExpanded = expandedContact === row.contactNumber;
                  const outPct =
                    row.totalCalls > 0
                      ? Math.round((row.outgoingCalls / row.totalCalls) * 100)
                      : 0;
                  return (
                    <React.Fragment key={row.contactNumber}>
                      <tr className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40">
                        <td className="py-2.5 px-4">
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedContact(isExpanded ? null : row.contactNumber)
                            }
                            aria-expanded={isExpanded}
                            className="flex items-center gap-2 text-left group"
                          >
                            {isExpanded ? (
                              <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                            ) : (
                              <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                            )}
                            <div>
                              <p className="font-medium text-slate-900 dark:text-slate-100 group-hover:text-blue-700 dark:group-hover:text-blue-400">
                                {row.contactName || 'Unidentified External'}
                              </p>
                              <p className="font-mono tabular-nums text-[11px] text-slate-500 dark:text-slate-400">
                                {row.contactNumber} · {row.operators.join(', ')}
                              </p>
                            </div>
                          </button>
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                          {row.totalCalls}
                        </td>
                        <td className="py-2.5 px-3 min-w-[130px]">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                              <div
                                className="h-full bg-blue-600 dark:bg-blue-400"
                                style={{ width: `${outPct}%` }}
                              />
                            </div>
                            <span className="font-mono tabular-nums text-[11px] text-slate-600 dark:text-slate-400">
                              {row.outgoingCalls}/{row.incomingCalls}
                            </span>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-700 dark:text-slate-300">
                          {formatDuration(row.totalDurationSec)}
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums font-medium text-amber-700 dark:text-amber-400">
                          {row.nightCalls}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                          <div>{formatISTDisplay(row.firstContactIso)}</div>
                          <div>{formatISTDisplay(row.lastContactIso)}</div>
                        </td>
                        <td className="py-2.5 px-4 text-[11px] text-slate-600 dark:text-slate-300">
                          {row.anomalies.length === 0 ? 'Nominal' : row.anomalies.join(' · ')}
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-slate-50/70 dark:bg-slate-800/30">
                          <td colSpan={7} className="px-6 py-3">
                            <p className="text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-2">
                              Underlying Source CDR Rows ({row.records.length})
                            </p>
                            <div className="overflow-x-auto border border-slate-200 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-900">
                              <table className="w-full text-left text-[11px]">
                                <thead>
                                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                                    <th className="py-1.5 px-3">Source &amp; Row</th>
                                    <th className="py-1.5 px-3">Timestamp (IST)</th>
                                    <th className="py-1.5 px-3">Operator</th>
                                    <th className="py-1.5 px-3">Caller → Callee</th>
                                    <th className="py-1.5 px-3 text-right">Duration</th>
                                    <th className="py-1.5 px-3">Cell Tower</th>
                                    <th className="py-1.5 px-3 text-right">Verify</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                                  {row.records.map((rec) => (
                                    <tr key={rec.id}>
                                      <td className="py-1.5 px-3 font-mono text-slate-700 dark:text-slate-300">
                                        {rec.sourceFile} · R{rec.rowNumber}
                                      </td>
                                      <td className="py-1.5 px-3 font-mono tabular-nums">
                                        {formatISTDisplay(rec.timestampIso)}
                                      </td>
                                      <td className="py-1.5 px-3">{rec.operator}</td>
                                      <td className="py-1.5 px-3 font-mono tabular-nums">
                                        {rec.caller} → {rec.callee}
                                      </td>
                                      <td className="py-1.5 px-3 text-right font-mono tabular-nums">
                                        {rec.durationSec}s
                                      </td>
                                      <td className="py-1.5 px-3 font-mono">
                                        {rec.cellTowerId || '—'}
                                      </td>
                                      <td className="py-1.5 px-3 text-right">
                                        <button
                                          type="button"
                                          onClick={() => onInspectCitation(cdrToCitation(rec))}
                                          className="inline-flex items-center gap-1 font-medium text-blue-700 dark:text-blue-400 hover:underline"
                                        >
                                          <span>Inspect</span>
                                          <ExternalLink className="w-3 h-3" />
                                        </button>
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
