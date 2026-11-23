import React, { useMemo, useState } from 'react';
import { BookmarkPlus, CheckCircle2, Globe, Search } from 'lucide-react';
import type { CaseFile, EvidenceCitation, IpdrLookupMatch } from '../types/forensics.ts';
import {
  correlateIpdrCgnat,
  formatISTDisplay,
  ipdrToCitation,
} from '../lib/forensics.ts';

interface IpdrLookupViewProps {
  caseFile: CaseFile;
  onInspectCitation: (citation: EvidenceCitation) => void;
  onPinFinding: (title: string, summary: string, citations: EvidenceCitation[]) => void;
  onLogIpdrLookup: (detail: string) => void;
}

export const IpdrLookupView: React.FC<IpdrLookupViewProps> = ({
  caseFile,
  onInspectCitation,
  onPinFinding,
  onLogIpdrLookup,
}) => {
  const [publicIp, setPublicIp] = useState('157.34.12.89');
  const [sourcePort, setSourcePort] = useState('44120');
  const [observedTimeIso, setObservedTimeIso] = useState('2026-01-14T02:18:45+05:30');
  const [protocol, setProtocol] = useState('TCP');
  const [toleranceSec, setToleranceSec] = useState('5');
  const [hasSearched, setHasSearched] = useState(true);

  const result = useMemo(() => {
    if (!hasSearched) return null;
    const portNum = sourcePort.trim() ? Number(sourcePort) : undefined;
    const tolNum = toleranceSec.trim() ? Number(toleranceSec) : 5;
    return correlateIpdrCgnat(caseFile.ipdrs, caseFile.suspects, {
      publicIp,
      sourcePort: portNum,
      observedTimeIso,
      protocol,
      toleranceSec: Number.isNaN(tolNum) ? 5 : tolNum,
    });
  }, [caseFile.ipdrs, caseFile.suspects, publicIp, sourcePort, observedTimeIso, protocol, toleranceSec, hasSearched]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setHasSearched(true);
    const portNum = sourcePort.trim() ? Number(sourcePort) : undefined;
    const tolNum = toleranceSec.trim() ? Number(toleranceSec) : 5;
    const res = correlateIpdrCgnat(caseFile.ipdrs, caseFile.suspects, {
      publicIp,
      sourcePort: portNum,
      observedTimeIso,
      protocol,
      toleranceSec: Number.isNaN(tolNum) ? 5 : tolNum,
    });
    onLogIpdrLookup(
      `CGNAT lookup ${publicIp}:${sourcePort || 'ANY'} ${protocol} @ ${observedTimeIso} (±${tolNum}s) -> ${res.summaryVerdict}`
    );
  };

  const statusMeta = (status: IpdrLookupMatch['status']) => {
    switch (status) {
      case 'EXACT_MATCH':
        return { label: 'Exact Window Match', cls: 'text-emerald-700 dark:text-emerald-400 font-semibold' };
      case 'OVERLAP_AMBIGUOUS':
        return { label: 'Ambiguous Overlap', cls: 'text-red-700 dark:text-red-400 font-semibold' };
      case 'TOLERANCE_MATCH':
        return { label: 'Tolerance-Only (±s)', cls: 'text-amber-700 dark:text-amber-400 font-semibold' };
      default:
        return { label: 'Out of Window', cls: 'text-slate-500 dark:text-slate-400' };
    }
  };

  const suspectNameMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of caseFile.suspects) m.set(s.phone, s.name);
    return m;
  }, [caseFile.suspects]);

  return (
    <div className="space-y-6">
      {/* CGNAT Query Form */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5">
        <div className="mb-4">
          <h2 className="font-display text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-700 dark:text-blue-400" />
            <span>CGNAT Public IP &amp; Source-Port Subscriber Attribution</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Correlate observed public IPv4, translated source port, protocol, and IST timestamp against
            carrier CGNAT allocation logs. Distinctly classifies exact window hits, ambiguous overlaps,
            clock-drift tolerance matches, and out-of-window rows.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 items-end">
          <div>
            <label htmlFor="ipdr-ip" className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
              Public IPv4
            </label>
            <input
              id="ipdr-ip"
              type="text"
              required
              value={publicIp}
              onChange={(e) => setPublicIp(e.target.value)}
              placeholder="157.34.12.89"
              className="w-full font-mono text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
            />
          </div>

          <div>
            <label htmlFor="ipdr-port" className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
              Source Port
            </label>
            <input
              id="ipdr-port"
              type="number"
              min={0}
              max={65535}
              value={sourcePort}
              onChange={(e) => setSourcePort(e.target.value)}
              placeholder="44120"
              className="w-full font-mono text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
            />
          </div>

          <div className="lg:col-span-2">
            <label htmlFor="ipdr-ts" className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
              Observed Timestamp (IST ISO)
            </label>
            <input
              id="ipdr-ts"
              type="text"
              required
              value={observedTimeIso}
              onChange={(e) => setObservedTimeIso(e.target.value)}
              placeholder="2026-01-14T02:18:45+05:30"
              className="w-full font-mono text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
            />
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label htmlFor="ipdr-proto" className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
                Protocol
              </label>
              <select
                id="ipdr-proto"
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="w-full text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-2 py-2 text-slate-900 dark:text-slate-100"
              >
                <option value="ANY">ANY</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
              </select>
            </div>
            <div>
              <label htmlFor="ipdr-tol" className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
                Drift (±s)
              </label>
              <input
                id="ipdr-tol"
                type="number"
                min={0}
                max={300}
                value={toleranceSec}
                onChange={(e) => setToleranceSec(e.target.value)}
                className="w-full font-mono text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-2.5 py-2 text-slate-900 dark:text-slate-100"
              />
            </div>
          </div>

          <button
            type="submit"
            className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-blue-700 hover:bg-blue-800 text-white transition-colors whitespace-nowrap"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Run Attribution</span>
          </button>
        </form>

        {/* Verdict Banner */}
        {result && (
          <div
            className={`mt-4 p-3.5 rounded-lg border flex flex-wrap items-center justify-between gap-3 text-xs ${
              result.uniqueSubscriber
                ? 'bg-emerald-50/70 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900/60 text-emerald-900 dark:text-emerald-200'
                : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200'
            }`}
          >
            <div className="flex items-center gap-2">
              {result.uniqueSubscriber && <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-700 dark:text-emerald-400" />}
              <span className="font-medium">{result.summaryVerdict}</span>
            </div>
            {result.uniqueSubscriber && result.matches[0] && (
              <button
                type="button"
                onClick={() =>
                  onPinFinding(
                    `CGNAT Attribution: ${publicIp}:${sourcePort}`,
                    result.summaryVerdict,
                    [result.matches[0].citation]
                  )
                }
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-slate-900 dark:bg-blue-700 text-white hover:opacity-90 whitespace-nowrap"
              >
                <BookmarkPlus className="w-3.5 h-3.5" />
                <span>Pin Finding</span>
              </button>
            )}
          </div>
        )}
      </section>

      {/* Correlation Matches Table */}
      {result && result.matches.length > 0 && (
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800">
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
              Matched CGNAT Allocations ({result.matches.length})
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-4 font-medium">Match Classification</th>
                  <th className="py-2.5 px-3 font-medium">Subscriber</th>
                  <th className="py-2.5 px-3 font-medium">Session Window (IST)</th>
                  <th className="py-2.5 px-3 font-medium">Port / Block</th>
                  <th className="py-2.5 px-3 font-medium">Supplied App / Service</th>
                  <th className="py-2.5 px-4 font-medium text-right">Citation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {result.matches.map((m) => {
                  const st = statusMeta(m.status);
                  return (
                    <tr key={m.record.id} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40">
                      <td className="py-2.5 px-4">
                        <div className={st.cls}>{st.label}</div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400">
                          {m.explanation}
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-medium text-slate-900 dark:text-slate-100">
                          {m.suspectName || 'Unregistered Subscriber'}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500">
                          {m.record.msisdn} · {m.record.operator}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                        <div>{formatISTDisplay(m.record.sessionStartIso)}</div>
                        <div>
                          {m.record.sessionEndIso
                            ? formatISTDisplay(m.record.sessionEndIso)
                            : 'Point observation'}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px]">
                        <div>Src: {m.record.sourcePort ?? '—'} ({m.record.protocol})</div>
                        <div className="text-slate-500">
                          Alloc: {m.record.allocPortStart ?? '?'}–{m.record.allocPortEnd ?? '?'}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-700 dark:text-slate-300">
                        <div className="font-medium">{m.record.application || 'Not supplied'}</div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          {m.record.destinationHost || m.record.service || '—'}
                        </div>
                      </td>
                      <td className="py-2.5 px-4 text-right">
                        <button
                          type="button"
                          onClick={() => onInspectCitation(m.citation)}
                          className="font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                        >
                          [{m.record.sourceFile}:R{m.record.rowNumber}]
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Full Case IPDR & App/Service Indicators Inventory */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800">
          <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
            All Normalized IPDR Sessions &amp; Application Indicators ({caseFile.ipdrs.length})
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Service and application indicators are surfaced strictly from operator-supplied IPDR fields
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400">
                <th className="py-2.5 px-4 font-medium">Session ID</th>
                <th className="py-2.5 px-3 font-medium">Subscriber</th>
                <th className="py-2.5 px-3 font-medium">Public IP : Port</th>
                <th className="py-2.5 px-3 font-medium">Start (IST)</th>
                <th className="py-2.5 px-3 font-medium">App / Service Indicator</th>
                <th className="py-2.5 px-3 font-medium">Tower</th>
                <th className="py-2.5 px-4 font-medium text-right">Verify</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {caseFile.ipdrs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No IPDR logs imported in this case yet.
                  </td>
                </tr>
              ) : (
                caseFile.ipdrs.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40">
                    <td className="py-2.5 px-4 font-mono font-medium text-slate-900 dark:text-slate-100">
                      {r.id}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="font-medium text-slate-900 dark:text-slate-100">
                        {suspectNameMap.get(r.msisdn) || r.msisdn}
                      </span>{' '}
                      <span className="font-mono text-[11px] text-slate-500">({r.operator})</span>
                    </td>
                    <td className="py-2.5 px-3 font-mono tabular-nums text-slate-700 dark:text-slate-300">
                      {r.publicIp}:{r.sourcePort ?? '—'} ({r.protocol})
                    </td>
                    <td className="py-2.5 px-3 font-mono tabular-nums text-[11px]">
                      {formatISTDisplay(r.sessionStartIso)}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="font-medium text-slate-900 dark:text-slate-100">
                        {r.application || 'Not supplied'}
                      </span>
                      {r.service && (
                        <span className="text-slate-500 dark:text-slate-400"> · {r.service}</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      {r.cellTowerId || '—'}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        type="button"
                        onClick={() => onInspectCitation(ipdrToCitation(r))}
                        className="font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                      >
                        [{r.sourceFile}:R{r.rowNumber}]
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
