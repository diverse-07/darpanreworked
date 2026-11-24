import React, { useMemo, useRef, useState } from 'react';
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
import { ArrowRight, AlertTriangle, Bot, CheckCircle2, FileText, Aperture, Pause, Play, List, ChevronDown } from 'lucide-react';
import type { CaseFile, EvidenceCitation } from '../types/forensics.ts';
import {
  analyzeContactPatterns,
  cdrToCitation,
  detectDeviceSimChanges,
  findCommonContacts,
  formatDuration,
  formatISTDisplay,
  ipdrToCitation,
} from '../lib/forensics.ts';
import type { NavTab } from './Sidebar.tsx';
import { EvidenceLinks } from './EvidenceLab.tsx';
import { FaceScan } from './FaceScan.tsx';

interface OverviewViewProps {
  caseFile: CaseFile;
  onNavigate: (tab: NavTab) => void;
  onInspectCitation: (citation: EvidenceCitation) => void;
}

function EvidenceDock({ caseFile, onInspectCitation }: Pick<OverviewViewProps, 'caseFile' | 'onInspectCitation'>) {
  const [kind, setKind] = useState('all');
  const [day, setDay] = useState('');
  const [page, setPage] = useState(0);
  const records = useMemo(() => [
    ...caseFile.cdrs.map(cdrToCitation),
    ...caseFile.ipdrs.map(ipdrToCitation),
  ].sort((a, b) => Date.parse(b.timestamp ?? '') - Date.parse(a.timestamp ?? '')), [caseFile]);
  const matches = records.filter(record =>
    (kind === 'all' || record.recordType === kind) && (!day || record.timestamp?.slice(0, 10) === day)
  );
  const pageSize = 5;
  const current = Math.min(page, Math.max(0, Math.ceil(matches.length / pageSize) - 1));
  const start = current * pageSize;

  return (
    <details className="explorer-dock" open>
      <summary><List size={15} aria-hidden="true"/> <span>Evidence timeline</span><small>{matches.length} records</small><ChevronDown size={15} aria-hidden="true"/></summary>
      <div className="explorer-dock-controls">
        <label>Type <select value={kind} onChange={event => { setKind(event.target.value); setPage(0); }}>
          <option value="all">All records</option><option value="cdr">CDR</option><option value="ipdr">IPDR</option>
        </select></label>
        <label>Date (IST) <input type="date" value={day} onInput={event => { setDay(event.currentTarget.value); setPage(0); }}/></label>
        {day && <button type="button" onClick={() => { setDay(''); setPage(0); }}>Clear date</button>}
      </div>
      {matches.length ? <>
        <div className="explorer-table-scroll">
          <table>
            <thead><tr><th scope="col">Timestamp (IST)</th><th scope="col">Type</th><th scope="col">Observation</th><th scope="col">Source</th></tr></thead>
            <tbody>{matches.slice(start, start + pageSize).map(record => (
              <tr key={`${record.recordType}-${record.sourceFile}-${record.rowNumber}`}>
                <td>{record.timestamp ? formatISTDisplay(record.timestamp) : '—'}</td>
                <td className="explorer-record-kind">{record.recordType}</td>
                <td>{record.summary}</td>
                <td><button type="button" onClick={() => onInspectCitation(record)}>{record.sourceFile} · Row {record.rowNumber}</button></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        {matches.length > pageSize && <div className="explorer-pagination">
          <span>{start + 1}–{Math.min(start + pageSize, matches.length)} of {matches.length}</span>
          <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)}>Previous</button>
          <button type="button" disabled={start + pageSize >= matches.length} onClick={() => setPage(current + 1)}>Next</button>
        </div>}
      </> : <p className="explorer-dock-empty">{records.length ? 'No records match these filters.' : 'Import CDR or IPDR files to populate the timeline.'}</p>}
    </details>
  );
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  caseFile,
  onNavigate,
  onInspectCitation,
}) => {
  const [playing, setPlaying] = useState(() => !window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const scanAngle = useRef(0);
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
    <div className="case-explorer">
      <section className="case-summary" data-running={playing}>
        <div className="case-intro">
          <p className="case-reference">{caseFile.caseNumber} <span aria-hidden="true">/</span> {caseFile.status}</p>
          <h2>{caseFile.title}</h2>
          <details className="case-brief">
            <summary>Case brief</summary>
            <p className="case-description">{caseFile.brief || 'Import call or IP records to begin examining the case.'}</p>
            <p className="case-station">{caseFile.station}{caseFile.createdBy && ' · Opened by ' + caseFile.createdBy}</p>
          </details>
        </div>
        <div className="case-actions">
          <button type="button" onClick={() => onNavigate('ai')} className="station-action">
            <Bot size={16} aria-hidden="true"/> Ask the assistant
          </button>
          <button type="button" onClick={() => onNavigate('reports')} className="station-action station-secondary">
            <FileText size={16} aria-hidden="true"/> Draft report
          </button>
        </div>
        <div className="case-evidence-links">
          <EvidenceLinks key={caseFile.id} caseFile={caseFile} onInspectCitation={onInspectCitation} playing={playing}
            workspace={{
              motionControl: <button className="lab-control" type="button" onClick={() => setPlaying(current => !current)}>
                {playing ? <Pause size={14} aria-hidden="true"/> : <Play size={14} aria-hidden="true"/>}
                {playing ? 'Pause motion' : 'Play motion'}
              </button>,
              portrait: <section className="case-portrait" aria-labelledby="overview-face-title">
                <div className="lab-panel-head">
                  <Aperture size={15} aria-hidden="true"/>
                  <h4 id="overview-face-title">Face scan</h4>
                  <span>Synthetic portrait</span>
                </div>
                <div className="lab-face-stage">
                  <div className="lab-reticle" aria-hidden="true"/>
                  <FaceScan playing={playing} angle={0} scanAngle={scanAngle}/>
                </div>
                <button className="case-lab-link" type="button" onClick={() => onNavigate('lab')}>
                  Open Evidence Lab <ArrowRight size={14} aria-hidden="true"/>
                </button>
              </section>,
            }}/>
        </div>
      </section>
      <EvidenceDock key={caseFile.id} caseFile={caseFile} onInspectCitation={onInspectCitation}/>

      {/* 4-Column KPI Strip */}
      <section aria-label="Case key metrics" className="case-metrics">
        <div className="p-5">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Telecom records
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
            Night calls (00:00–06:00 IST)
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
            Device alerts
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
            Officer review
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
      <div className="overview-analysis grid grid-cols-1 [@media(min-width:1100px)]:grid-cols-3 gap-5">
        {/* 24-Hour IST Distribution */}
        <section className="[@media(min-width:1100px)]:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col">
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
                Records by operator
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
              Subject profiles ({caseFile.suspects.length})
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
