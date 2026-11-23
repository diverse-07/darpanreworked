import React, { useMemo } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ArrowRight, AlertTriangle, CheckCircle2, FileText } from 'lucide-react';
import type { CaseFile, EvidenceCitation } from '../types/forensics.ts';
import {
  analyzeContactPatterns,
  detectDeviceSimChanges,
  findCommonContacts,
  formatDuration,
  formatISTDisplay,
} from '../lib/forensics.ts';
import type { NavTab } from './Sidebar.tsx';

interface OverviewViewProps {
  caseFile: CaseFile;
  onNavigate: (tab: NavTab) => void;
  onInspectCitation: (citation: EvidenceCitation) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  caseFile,
  onNavigate,
  onInspectCitation,
}) => {
  const analysis = useMemo(
    () => analyzeContactPatterns(caseFile.cdrs, caseFile.suspects, 'ALL'),
    [caseFile]
  );

  const deviceAnalysis = useMemo(
    () => detectDeviceSimChanges(caseFile.cdrs, caseFile.suspects),
    [caseFile]
  );

  const crossCorrelation = useMemo(() => {
    const phones = caseFile.suspects.slice(0, 2).map((s) => s.phone);
    return findCommonContacts(caseFile.cdrs, caseFile.suspects, phones);
  }, [caseFile]);

  const operators = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of caseFile.cdrs) {
      counts.set(r.operator, (counts.get(r.operator) || 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [caseFile.cdrs]);

  const verifiedFindings = caseFile.findings.filter((f) => f.status === 'verified').length;
  const pendingFindings = caseFile.findings.filter((f) => f.status === 'pending_review').length;

  return (
    <div className="space-y-6">
      {/* Case Brief Header */}
      <section className="case-brief p-5 lg:p-6">
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
          <div className="space-y-2 max-w-3xl">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
              <span className="font-mono font-medium text-slate-700 dark:text-slate-300">
                {caseFile.caseNumber}
              </span>
              <span aria-hidden="true">·</span>
              <span>{caseFile.station}</span>
              <span aria-hidden="true">·</span>
              <span>Opened by {caseFile.createdBy}</span>
            </div>
            <h2 className="text-2xl lg:text-4xl font-semibold text-slate-900 dark:text-white tracking-tight">
              {caseFile.title}
            </h2>
            <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
              {caseFile.brief}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => onNavigate('ai')}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-700 hover:bg-blue-800 text-white transition-colors whitespace-nowrap"
            >
              Ask the assistant
            </button>
            <button
              type="button"
              onClick={() => onNavigate('reports')}
              className="px-4 py-2 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap"
            >
              Draft report
            </button>
          </div>
        </div>
      </section>

      {/* 4-Column KPI Strip */}
      <section aria-label="Case key metrics" className="case-metrics grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
        <div className="p-5">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Normalized Telecom Records
          </p>
          <p className="mt-2 font-mono tabular-nums text-3xl font-semibold text-slate-900 dark:text-white">
            {caseFile.cdrs.length + caseFile.ipdrs.length}
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {caseFile.cdrs.length} CDRs · {caseFile.ipdrs.length} IPDRs · {caseFile.sources.length} files
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Night-Time Activity (00:00–06:00 IST)
          </p>
          <p className="mt-2 font-mono tabular-nums text-3xl font-semibold text-slate-900 dark:text-white">
            {analysis.nightCalls}{' '}
            <span className="text-sm font-medium text-amber-700 dark:text-amber-400">
              ({analysis.nightRatioPct}%)
            </span>
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Total talk duration {formatDuration(analysis.totalDurationSec)}
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Device &amp; Cross-Suspect Alerts
          </p>
          <p className="mt-2 font-mono tabular-nums text-3xl font-semibold text-slate-900 dark:text-white">
            {deviceAnalysis.changes.length + deviceAnalysis.sharedDevices.length}
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {deviceAnalysis.sharedDevices.length} shared IMEI · {crossCorrelation.sharedContacts.length} shared contacts
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Officer Verification Queue
          </p>
          <p className="mt-2 font-mono tabular-nums text-3xl font-semibold text-slate-900 dark:text-white">
            {verifiedFindings}{' '}
            <span className="text-sm font-normal text-slate-500 dark:text-slate-400">
              / {caseFile.findings.length} verified
            </span>
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {pendingFindings} finding{pendingFindings === 1 ? '' : 's'} awaiting officer review
          </p>
        </div>
      </section>

      {/* Main Analytical Row: Hourly Activity Chart + Forensic Signals */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* 24-Hour IST Distribution */}
        <section className="xl:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <div>
              <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
                Calls by hour (IST)
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Amber marks calls between midnight and 06:00 IST
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('contacts')}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline whitespace-nowrap"
            >
              <span>Inspect contact breakdown</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {caseFile.cdrs.length === 0 ? (
            <div className="flex-1 min-h-[220px] flex flex-col items-center justify-center text-center p-6 border border-dashed border-slate-200 dark:border-slate-700 rounded-lg">
              <p className="text-sm font-medium text-slate-700 dark:text-slate-200">
                No CDR records imported in this case yet
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 mb-3">
                Upload Jio, Airtel, Vi, or BSNL files to visualize temporal activity.
              </p>
              <button
                type="button"
                onClick={() => onNavigate('import')}
                className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-blue-700 text-white hover:bg-blue-800"
              >
                Import First Evidence File
              </button>
            </div>
          ) : (
            <div className="h-[240px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={analysis.hourlyDistribution}
                  margin={{ top: 8, right: 8, left: -20, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" vertical={false} />
                  <XAxis
                    dataKey="label"
                    tick={{ fontSize: 11, fill: 'var(--chart-label)' }}
                    interval={2}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fontSize: 11, fill: 'var(--chart-label)' }}
                    allowDecimals={false}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontSize: '12px',
                    }}
                    formatter={(val: unknown) => [`${val} calls`, 'Volume']}
                  />
                  <Bar dataKey="total" radius={[4, 4, 0, 0]}>
                    {analysis.hourlyDistribution.map((entry) => (
                      <Cell
                        key={entry.hour}
                        fill={entry.night ? '#c99959' : '#727272'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Operator Breakdown Strip */}
          {operators.length > 0 && (
            <div className="mt-4 pt-3.5 border-t border-slate-100 dark:border-slate-800 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-slate-600 dark:text-slate-300">
              <span className="font-medium text-slate-500 dark:text-slate-400">
                Operator Mix:
              </span>
              {operators.map(([op, count]) => (
                <span key={op} className="inline-flex items-center gap-1.5">
                  <span className="font-medium text-slate-900 dark:text-slate-100">{op}</span>
                  <span className="font-mono tabular-nums text-slate-500 dark:text-slate-400">
                    ({count})
                  </span>
                </span>
              ))}
            </div>
          )}
        </section>

        {/* High-Priority Investigative Leads */}
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col">
          <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white mb-1">
            Review leads
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
            Open a source reference to check the row
          </p>

          <div className="space-y-3 flex-1">
            {deviceAnalysis.sharedDevices.map((sd) => (
              <div
                key={sd.imei}
                className="p-3 rounded-lg bg-red-50/70 dark:bg-red-950/30 border border-red-200/80 dark:border-red-900/60 space-y-1.5"
              >
                <div className="flex items-center gap-1.5 text-xs font-semibold text-red-800 dark:text-red-300">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>Shared Handset IMEI</span>
                </div>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-snug">
                  IMEI <span className="font-mono font-medium">{sd.imei}</span> used by{' '}
                  {sd.msisdns.map((m) => m.name || m.phone).join(' & ')}.
                </p>
                <div className="flex flex-wrap gap-2 pt-0.5">
                  {sd.citations.map((c) => (
                    <button
                      key={`${c.sourceFile}-${c.rowNumber}`}
                      type="button"
                      onClick={() => onInspectCitation(c)}
                      className="text-[11px] font-mono text-blue-700 dark:text-blue-400 hover:underline"
                    >
                      [{c.sourceFile} · Row {c.rowNumber}]
                    </button>
                  ))}
                </div>
              </div>
            ))}

            {deviceAnalysis.changes.slice(0, 2).map((ch) => (
              <div
                key={ch.id}
                className="p-3 rounded-lg bg-amber-50/70 dark:bg-amber-950/25 border border-amber-200/80 dark:border-amber-900/50 space-y-1.5"
              >
                <p className="text-xs font-semibold text-amber-900 dark:text-amber-300">
                  {ch.changeType === 'IMEI_CHANGE' ? 'IMEI Device Switch' : 'SIM Swap Detected'} ·{' '}
                  {ch.suspectName || ch.msisdn}
                </p>
                <p className="text-xs text-slate-700 dark:text-slate-300 font-mono">
                  ...{ch.previousValue.slice(-6)} → ...{ch.newValue.slice(-6)} at{' '}
                  {formatISTDisplay(ch.newTimestampIso)}
                </p>
                <button
                  type="button"
                  onClick={() => onInspectCitation(ch.newCitation)}
                  className="text-[11px] font-mono text-blue-700 dark:text-blue-400 hover:underline"
                >
                  [{ch.newCitation.sourceFile} · Row {ch.newCitation.rowNumber}]
                </button>
              </div>
            ))}

            {crossCorrelation.sharedContacts.length > 0 && (
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                    Common Contacts Across Primary Suspects
                  </p>
                  <button
                    type="button"
                    onClick={() => onNavigate('network')}
                    className="text-[11px] font-medium text-blue-700 dark:text-blue-400 hover:underline"
                  >
                    Open Graph
                  </button>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  {crossCorrelation.sharedContacts.length} shared numbers linked between{' '}
                  {caseFile.suspects[0]?.name} and {caseFile.suspects[1]?.name} (
                  {crossCorrelation.sharedContacts
                    .slice(0, 3)
                    .map((s) => s.contactName || s.contactNumber)
                    .join(', ')}
                  ).
                </p>
              </div>
            )}

            {caseFile.cdrs.length === 0 && (
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Signals appear automatically once multi-operator records are normalized.
              </p>
            )}
          </div>
        </section>
      </div>

      {/* Registered Suspects & Evidence Files Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        {/* Suspects Table */}
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
              Registered Suspect Profiles ({caseFile.suspects.length})
            </h3>
            <button
              type="button"
              onClick={() => onNavigate('map')}
              className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline"
            >
              View Tower Movement
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 bg-slate-50/70 dark:bg-slate-800/40">
                  <th className="py-2.5 px-4 font-medium">Suspect</th>
                  <th className="py-2.5 px-4 font-medium">MSISDN</th>
                  <th className="py-2.5 px-4 font-medium">Base Sector</th>
                  <th className="py-2.5 px-4 font-medium">Prior FIRs</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {caseFile.suspects.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-6 px-4 text-center text-slate-500">
                      No suspect profiles uploaded yet.
                    </td>
                  </tr>
                ) : (
                  caseFile.suspects.map((s) => (
                    <tr key={s.phone} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40">
                      <td className="py-2.5 px-4 font-medium text-slate-900 dark:text-slate-100">
                        {s.name}
                      </td>
                      <td className="py-2.5 px-4 font-mono tabular-nums text-slate-700 dark:text-slate-300">
                        {s.phone}
                      </td>
                      <td className="py-2.5 px-4 text-slate-600 dark:text-slate-400">
                        {s.baseLocation}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-600 dark:text-slate-400">
                        {s.priorFirs.length > 0 ? s.priorFirs.join(', ') : 'None'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* Source Custody Manifest */}
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
              Normalized Evidence Sources ({caseFile.sources.length})
            </h3>
            <button
              type="button"
              onClick={() => onNavigate('import')}
              className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline"
            >
              Manage Sources
            </button>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-[260px] overflow-y-auto">
            {caseFile.sources.length === 0 ? (
              <p className="py-6 px-4 text-center text-xs text-slate-500">
                No evidence files imported yet.
              </p>
            ) : (
              caseFile.sources.map((src) => (
                <div
                  key={src.id}
                  className="px-4 py-2.5 flex items-center justify-between gap-3 text-xs hover:bg-slate-50/70 dark:hover:bg-slate-800/40"
                >
                  <div className="min-w-0 flex items-center gap-2.5">
                    <FileText className="w-4 h-4 text-slate-400 shrink-0" />
                    <div className="min-w-0">
                      <p className="font-medium text-slate-900 dark:text-slate-100 truncate">
                        {src.fileName}
                      </p>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                        {src.operator} · {src.datasetType.toUpperCase()} ·{' '}
                        <span className="font-mono">SHA {src.sha256.slice(0, 12)}</span>
                      </p>
                    </div>
                  </div>
                  <div className="text-right shrink-0 font-mono tabular-nums">
                    <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400 font-medium">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      {src.validRowCount}
                    </span>
                    {src.rejectedRowCount > 0 && (
                      <span className="ml-2 text-red-600 dark:text-red-400">
                        ({src.rejectedRowCount} err)
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
};
