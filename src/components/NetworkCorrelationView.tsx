import React, { useMemo, useState } from 'react';
import { AlertTriangle, Play, ZoomIn, ZoomOut, RotateCcw } from 'lucide-react';
import type { CaseFile, EvidenceCitation, NetworkEdge, NetworkNode } from '../types/forensics.ts';
import {
  buildNetworkGraph,
  detectDeviceSimChanges,
  findCommonContacts,
  formatDuration,
} from '../lib/forensics.ts';

interface NetworkCorrelationViewProps {
  caseFile: CaseFile;
  onInspectCitation: (citation: EvidenceCitation) => void;
  onOpenLab: () => void;
}

export const NetworkCorrelationView: React.FC<NetworkCorrelationViewProps> = ({
  caseFile,
  onInspectCitation,
  onOpenLab,
}) => {
  const [selectedPhones, setSelectedPhones] = useState<string[]>(() =>
    caseFile.suspects.slice(0, 2).map((s) => s.phone)
  );
  const [nightOnly, setNightOnly] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<NetworkEdge | null>(null);
  const [motionRun, setMotionRun] = useState(0);
  const [replayRequested, setReplayRequested] = useState(false);
  const selectGraphItem = (nodeId: string | null, edge: NetworkEdge | null) => {
    setSelectedNodeId(nodeId);
    setSelectedEdge(edge);
    setReplayRequested(false);
    setMotionRun(run => run + 1);
  };
  const changeNightFilter = (night: boolean) => {
    if (night === nightOnly) return;
    setNightOnly(night);
    selectGraphItem(null, null);
  };

  const graph = useMemo(
    () => buildNetworkGraph(caseFile.cdrs, caseFile.suspects, { nightOnly }),
    [caseFile, nightOnly]
  );

  const correlation = useMemo(
    () => findCommonContacts(caseFile.cdrs, caseFile.suspects, selectedPhones, { nightOnly }),
    [caseFile, selectedPhones, nightOnly]
  );

  const { sharedDevices } = useMemo(
    () => detectDeviceSimChanges(caseFile.cdrs, caseFile.suspects),
    [caseFile]
  );

  const toggleSuspect = (phone: string) => {
    setSelectedPhones((prev) =>
      prev.includes(phone) ? prev.filter((p) => p !== phone) : [...prev, phone]
    );
  };

  // Deterministic spacious layout: suspects on wide outer ring, shared bridges centered with clear separation
  const nodePositions = useMemo(() => {
    const pos = new Map<string, { x: number; y: number }>();
    const cx = 410;
    const cy = 230;
    const suspectNodes = graph.nodes.filter((n) => n.isSuspect);
    const bridgeNodes = graph.nodes.filter((n) => !n.isSuspect && n.isSharedBridge);
    const externalNodes = graph.nodes.filter((n) => !n.isSuspect && !n.isSharedBridge);

    suspectNodes.forEach((n, i) => {
      const angle = (i / Math.max(1, suspectNodes.length)) * Math.PI * 2 - Math.PI / 2;
      const rx = suspectNodes.length <= 2 ? 175 : 220;
      const ry = suspectNodes.length <= 2 ? 120 : 165;
      pos.set(n.id, {
        x: cx + Math.cos(angle) * rx,
        y: cy + Math.sin(angle) * ry,
      });
    });

    bridgeNodes.forEach((n, i) => {
      if (bridgeNodes.length === 1) {
        pos.set(n.id, { x: cx, y: cy + 8 });
      } else {
        const angle = (i / bridgeNodes.length) * Math.PI * 2;
        pos.set(n.id, {
          x: cx + Math.cos(angle) * 65,
          y: cy + Math.sin(angle) * 55,
        });
      }
    });

    externalNodes.forEach((n, i) => {
      const angle = (i / Math.max(1, externalNodes.length)) * Math.PI * 2 + Math.PI / 5;
      pos.set(n.id, {
        x: cx + Math.cos(angle) * 310,
        y: cy + Math.sin(angle) * 190,
      });
    });

    return pos;
  }, [graph.nodes]);

  const activeNode: NetworkNode | undefined = graph.nodes.find((n) => n.id === selectedNodeId);
  const suspectNameMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of caseFile.suspects) m.set(s.phone, s.name);
    return m;
  }, [caseFile.suspects]);

  return (
    <div className="space-y-6">
      {/* Cross-Suspect Selection Bar */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1.5">
          <p className="text-xs font-semibold text-slate-900 dark:text-white">
            Select Suspects to Cross-Correlate ({selectedPhones.length} selected)
          </p>
          <div className="flex flex-wrap items-center gap-2">
            {caseFile.suspects.map((s) => {
              const checked = selectedPhones.includes(s.phone);
              return (
                <button
                  key={s.phone}
                  type="button"
                  onClick={() => toggleSuspect(s.phone)}
                  aria-pressed={checked}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors whitespace-nowrap ${
                    checked
                      ? 'bg-blue-50 dark:bg-blue-950/60 border-blue-600 text-blue-800 dark:text-blue-200'
                      : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800'
                  }`}
                >
                  {s.name}{' '}
                  <span className="font-mono text-[11px] opacity-75">
                    ({s.phone.slice(-4)})
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg">
          <button
            type="button"
            onClick={() => changeNightFilter(false)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md ${
              !nightOnly
                ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400'
            }`}
          >
            All Traffic
          </button>
          <button
            type="button"
            onClick={() => changeNightFilter(true)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md ${
              nightOnly
                ? 'bg-white dark:bg-slate-900 text-amber-800 dark:text-amber-300 shadow-sm'
                : 'text-slate-600 dark:text-slate-400'
            }`}
          >
            Night Links Only
          </button>
        </div>
      </section>

      {/* Interactive Network Graph + Inspector */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <section className="xl:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden flex flex-col">
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
                Communication links
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Select a person or link to trace connections and inspect the source records.
              </p>
            </div>
            <div className="flex items-center gap-1">
              <button type="button" onClick={onOpenLab}
                className="rounded-md border border-slate-200 px-2 py-1.5 text-xs hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800">
                Open evidence lab
              </button>
              <button
                type="button"
                onClick={() => {
                  setReplayRequested(true);
                  setMotionRun(run => run + 1);
                }}
                disabled={!graph.edges.length}
                className="inline-flex items-center gap-2 rounded-md border border-slate-200 px-2 py-1.5 text-xs hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
              >
                <Play className="h-3.5 w-3.5" aria-hidden="true" />
                Replay motion
              </button>
              <button
                type="button"
                onClick={() => setZoom((z) => Math.min(1.8, Number((z + 0.15).toFixed(2))))}
                aria-label="Zoom in network graph"
                className="p-1.5 rounded-md border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={() => setZoom((z) => Math.max(0.6, Number((z - 0.15).toFixed(2))))}
                aria-label="Zoom out network graph"
                className="p-1.5 rounded-md border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={() => {
                  setZoom(1);
                  selectGraphItem(null, null);
                }}
                aria-label="Reset graph view"
                className="p-1.5 rounded-md border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <div
            className="network-canvas relative flex-1 min-h-[450px] overflow-hidden"
            data-replay={replayRequested ? 'true' : undefined}
            data-testid="contact-network-graph"
          >
            {graph.nodes.length === 0 ? (
              <div className="h-[450px] flex items-center justify-center text-xs text-slate-500">
                No communication edges match the active filter.
              </div>
            ) : (
              <svg
                viewBox="0 0 820 460"
                className="w-full h-[450px]"
                role="group"
                aria-label="Suspect and contact communication network graph"
              >
                <g className="network-zoom" style={{ transform: `scale(${zoom})` }}>
                  {/* Edges */}
                  {graph.edges.map((edge, idx) => {
                    const p1 = nodePositions.get(edge.source);
                    const p2 = nodePositions.get(edge.target);
                    if (!p1 || !p2) return null;
                    const isHighlighted =
                      selectedEdge === edge ||
                      selectedNodeId === edge.source ||
                      selectedNodeId === edge.target;
                    const showTrace = selectedEdge || selectedNodeId ? isHighlighted : idx < 12;
                    const strokeWidth = Math.min(4.5, 1.3 + Math.log2(edge.callCount + 1));
                    // Stagger label position along edge so intersecting chords never stack badges
                    const t = idx % 2 === 0 ? 0.42 : 0.58;
                    const labelX = p1.x + (p2.x - p1.x) * t;
                    const labelY = p1.y + (p2.y - p1.y) * t;
                    return (
                      <g
                        key={`${edge.source}-${edge.target}`}
                        className="network-target cursor-pointer"
                        role="button"
                        tabIndex={0}
                        aria-label={edge.callCount + ' calls between ' + edge.source + ' and ' + edge.target}
                        aria-pressed={selectedEdge === edge}
                        onClick={() => selectGraphItem(null, edge)}
                        onKeyDown={event => {
                          if (event.key !== 'Enter' && event.key !== ' ') return;
                          event.preventDefault();
                          selectGraphItem(null, edge);
                        }}
                      >
                        <line
                          className="network-edge"
                          x1={p1.x}
                          y1={p1.y}
                          x2={p2.x}
                          y2={p2.y}
                          stroke={
                            isHighlighted
                              ? '#b98643'
                              : edge.nightCalls > 0
                                ? '#996b42'
                                : '#73736f'
                          }
                          strokeOpacity={isHighlighted ? 1 : selectedEdge || selectedNodeId ? 0.23 : 0.65}
                          strokeWidth={strokeWidth}
                        />
                        {showTrace && (
                          <g key={motionRun} aria-hidden="true" className="network-traces"
                            style={{ animationDelay: `${(idx % 8) * 85}ms` }}>
                            <line x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y} pathLength={1} />
                            <line x1={p2.x} y1={p2.y} x2={p1.x} y2={p1.y} pathLength={1} />
                          </g>
                        )}
                        <rect
                          x={labelX - 12}
                          y={labelY - 8.5}
                          width={24}
                          height={17}
                          rx={4}
                          className="fill-slate-100 dark:fill-slate-900"
                          stroke={isHighlighted ? '#b98643' : '#cbd5e1'}
                          strokeWidth={1}
                        />
                        <text
                          x={labelX}
                          y={labelY + 3.5}
                          textAnchor="middle"
                          fontSize={10}
                          fontWeight={600}
                          fontFamily="IBM Plex Mono, monospace"
                          className="fill-slate-900 dark:fill-slate-100"
                        >
                          {edge.callCount}
                        </text>
                      </g>
                    );
                  })}

                  {/* Nodes */}
                  {graph.nodes.map((node) => {
                    const p = nodePositions.get(node.id);
                    if (!p) return null;
                    const isSelected = selectedNodeId === node.id;
                    const isCorrelated = selectedPhones.includes(node.phone);
                    const radius = node.isSuspect ? 21 : node.isSharedBridge ? 18 : 14;
                    const fill = node.isSuspect
                      ? isCorrelated
                        ? '#b98643'
                        : '#43433f'
                      : node.isSharedBridge
                        ? '#996b42'
                        : '#64645f';
                    const isUnnamed = node.label === node.phone;
                    const primaryTitle = isUnnamed
                      ? node.isSharedBridge
                        ? 'Shared Bridge'
                        : 'External'
                      : node.label;
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${p.x}, ${p.y})`}
                        className="network-target cursor-pointer"
                        role="button"
                        tabIndex={0}
                        aria-label={'Inspect ' + node.label}
                        aria-pressed={isSelected}
                        onClick={() => selectGraphItem(node.id, null)}
                        onKeyDown={event => {
                          if (event.key !== 'Enter' && event.key !== ' ') return;
                          event.preventDefault();
                          selectGraphItem(node.id, null);
                        }}
                      >
                        {isSelected && <circle className="network-selection" r={radius + 6} />}
                        {isSelected && <circle key={motionRun} className="network-ripple" r={radius + 6} aria-hidden="true" />}
                        <circle
                          className="network-node-core"
                          r={radius}
                          fill={fill}
                          stroke="#ffffff"
                          strokeWidth={2.5}
                        />
                        <text
                          y={3.5}
                          textAnchor="middle"
                          fontSize={10.5}
                          fontWeight={600}
                          fontFamily="IBM Plex Mono, monospace"
                          fill="#ffffff"
                        >
                          {node.totalCalls}
                        </text>
                        <text
                          y={radius + 15}
                          textAnchor="middle"
                          fontSize={11.5}
                          fontWeight={600}
                          paintOrder="stroke"
                          strokeWidth={4}
                          className="fill-slate-900 dark:fill-slate-100 stroke-slate-50 dark:stroke-slate-950"
                        >
                          {primaryTitle}
                        </text>
                        <text
                          y={radius + 28}
                          textAnchor="middle"
                          fontSize={9.5}
                          fontFamily="IBM Plex Mono, monospace"
                          paintOrder="stroke"
                          strokeWidth={3.5}
                          className="fill-slate-500 dark:fill-slate-400 stroke-slate-50 dark:stroke-slate-950"
                        >
                          {node.phone}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
            )}
          </div>
        </section>

        {/* Selection Inspector & Shared IMEI Panel */}
        <section className="space-y-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-3">
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
              Connection details
            </h3>
            {activeNode ? (
              <div className="space-y-2 text-xs">
                <p className="font-semibold text-slate-900 dark:text-white">{activeNode.label}</p>
                <p className="font-mono text-slate-500 dark:text-slate-400">{activeNode.phone}</p>
                <p className="text-slate-600 dark:text-slate-300">
                  {activeNode.isSuspect
                    ? 'Registered Suspect'
                    : activeNode.isSharedBridge
                      ? 'Shared External Bridge Number'
                      : 'External Contact'}
                </p>
                <dl className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <div>
                    <dt className="text-slate-500">Total Calls</dt>
                    <dd className="font-mono font-semibold">{activeNode.totalCalls}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Night Calls</dt>
                    <dd className="font-mono font-semibold text-amber-700 dark:text-amber-400">
                      {activeNode.nightCalls}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Duration</dt>
                    <dd className="font-mono font-semibold">
                      {formatDuration(activeNode.totalDurationSec)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Connected Nodes</dt>
                    <dd className="font-mono font-semibold">{activeNode.degree}</dd>
                  </div>
                </dl>
              </div>
            ) : selectedEdge ? (
              <div className="space-y-2.5 text-xs">
                <p className="font-semibold text-slate-900 dark:text-white">
                  {suspectNameMap.get(selectedEdge.source) || selectedEdge.source} ↔{' '}
                  {suspectNameMap.get(selectedEdge.target) || selectedEdge.target}
                </p>
                <p className="font-mono text-slate-500 dark:text-slate-400">
                  {selectedEdge.callCount} calls · {formatDuration(selectedEdge.totalDurationSec)} ·{' '}
                  {selectedEdge.nightCalls} night calls
                </p>
                <p className="text-slate-600 dark:text-slate-300">
                  Operators: {selectedEdge.operators.join(', ')}
                </p>
                <div className="pt-2 border-t border-slate-100 dark:border-slate-800 space-y-1">
                  <p className="font-medium text-slate-700 dark:text-slate-300">
                    Evidence Citations:
                  </p>
                  {selectedEdge.sampleCitations.map((c) => (
                    <button
                      key={`${c.sourceFile}-${c.rowNumber}`}
                      type="button"
                      onClick={() => onInspectCitation(c)}
                      className="block text-left font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                    >
                      [{c.sourceFile} · Row {c.rowNumber}] {c.recordId}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Click any suspect node or link count label on the graph to view call volumes and
                jump directly to the source operator rows.
              </p>
            )}
          </div>

          {/* Cross-Suspect Shared IMEI Handsets */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-3">
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
              Shared Handset (IMEI) Overlap
            </h3>
            {sharedDevices.length === 0 ? (
              <p className="text-xs text-slate-500 dark:text-slate-400">
                No IMEI is shared across multiple MSISDNs in the current case.
              </p>
            ) : (
              sharedDevices.map((sd) => (
                <div
                  key={sd.imei}
                  className="p-3 rounded-lg bg-red-50/70 dark:bg-red-950/30 border border-red-200 dark:border-red-900/60 space-y-1.5 text-xs"
                >
                  <div className="flex items-center gap-1.5 font-semibold text-red-800 dark:text-red-300">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                    <span className="font-mono">IMEI {sd.imei}</span>
                  </div>
                  <ul className="space-y-1 text-slate-700 dark:text-slate-300">
                    {sd.msisdns.map((m) => (
                      <li key={m.phone} className="font-mono text-[11px]">
                        {m.name || m.phone} ({m.phone}) — {m.count} calls
                      </li>
                    ))}
                  </ul>
                  <div className="flex flex-wrap gap-2 pt-1">
                    {sd.citations.map((c) => (
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
              ))
            )}
          </div>
        </section>
      </div>

      {/* Common Contacts Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800">
          <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
            Common Numbers Across Selected Suspects ({correlation.sharedContacts.length})
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Third-party numbers communicating with two or more selected suspects across uploaded
            multi-operator CDRs
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400">
                <th className="py-2.5 px-4 font-medium">Shared Contact</th>
                <th className="py-2.5 px-4 font-medium">Connected Suspects (Calls)</th>
                <th className="py-2.5 px-3 font-medium text-right">Total Calls</th>
                <th className="py-2.5 px-3 font-medium text-right">Night Calls</th>
                <th className="py-2.5 px-3 font-medium text-right">Duration</th>
                <th className="py-2.5 px-4 font-medium">Source Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {selectedPhones.length < 2 ? (
                <tr>
                  <td colSpan={6} className="py-7 text-center text-slate-500">
                    Select at least 2 suspects above to compute shared contacts.
                  </td>
                </tr>
              ) : correlation.sharedContacts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-7 text-center text-slate-500">
                    No common third-party contacts found among the selected suspects.
                  </td>
                </tr>
              ) : (
                correlation.sharedContacts.map((sc) => (
                  <tr key={sc.contactNumber} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40">
                    <td className="py-2.5 px-4">
                      <p className="font-medium text-slate-900 dark:text-slate-100">
                        {sc.contactName || 'Unidentified Bridge Number'}
                      </p>
                      <p className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                        {sc.contactNumber}
                      </p>
                    </td>
                    <td className="py-2.5 px-4 text-slate-700 dark:text-slate-300">
                      {Object.entries(sc.perSuspectCounts)
                        .map(
                          ([phone, cnt]) =>
                            `${suspectNameMap.get(phone) || phone} (${cnt})`
                        )
                        .join(' · ')}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums font-semibold">
                      {sc.totalSharedCalls}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums text-amber-700 dark:text-amber-400">
                      {sc.nightCalls}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                      {formatDuration(sc.totalDurationSec)}
                    </td>
                    <td className="py-2.5 px-4">
                      <div className="flex flex-wrap gap-2">
                        {sc.citations.slice(0, 3).map((c) => (
                          <button
                            key={`${c.sourceFile}-${c.rowNumber}`}
                            type="button"
                            onClick={() => onInspectCitation(c)}
                            className="font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                          >
                            [{c.sourceFile}:R{c.rowNumber}]
                          </button>
                        ))}
                      </div>
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
