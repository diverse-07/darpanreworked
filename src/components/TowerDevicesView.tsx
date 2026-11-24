import React, { useEffect, useMemo, useRef, useState } from 'react';
import L from 'leaflet';
import { AlertTriangle, Pause, Play, Smartphone } from 'lucide-react';
import type { CaseFile, EvidenceCitation } from '../types/forensics.ts';
import {
  buildTowerTimeline,
  detectDeviceSimChanges,
  formatISTDisplay,
} from '../lib/forensics.ts';

interface TowerDevicesViewProps {
  caseFile: CaseFile;
  initialSuspectPhone?: string;
  onInspectCitation: (citation: EvidenceCitation) => void;
}

/**
 * Generates geographic polygon vertices for a cell-tower directional azimuth sector wedge.
 */
function buildSectorPolygon(
  lat: number,
  lon: number,
  azimuthDeg: number,
  radiusMeters = 900,
  beamWidthDeg = 60
): [number, number][] {
  const points: [number, number][] = [[lat, lon]];
  const R = 6378137;
  const startAngle = azimuthDeg - beamWidthDeg / 2;
  const endAngle = azimuthDeg + beamWidthDeg / 2;
  const steps = 12;
  for (let i = 0; i <= steps; i++) {
    const bearing = ((startAngle + ((endAngle - startAngle) * i) / steps) * Math.PI) / 180;
    const dLat = (radiusMeters * Math.cos(bearing)) / R;
    const dLon =
      (radiusMeters * Math.sin(bearing)) / (R * Math.cos((lat * Math.PI) / 180));
    points.push([lat + (dLat * 180) / Math.PI, lon + (dLon * 180) / Math.PI]);
  }
  points.push([lat, lon]);
  return points;
}

export const TowerDevicesView: React.FC<TowerDevicesViewProps> = ({
  caseFile,
  initialSuspectPhone,
  onInspectCitation,
}) => {
  const [targetPhone, setTargetPhone] = useState<string>(
    initialSuspectPhone || caseFile.suspects[0]?.phone || ''
  );
  const [nightOnly, setNightOnly] = useState(false);
  const [playbackIdx, setPlaybackIdx] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState(false);

  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const layerGroupRef = useRef<L.LayerGroup | null>(null);

  const timeline = useMemo(
    () => buildTowerTimeline(caseFile.cdrs, caseFile.towers, targetPhone, { nightOnly }, caseFile.ipdrs),
    [caseFile, targetPhone, nightOnly]
  );

  const deviceAnalysis = useMemo(
    () => detectDeviceSimChanges(caseFile.cdrs, caseFile.suspects, targetPhone),
    [caseFile, targetPhone]
  );

  const clampedIdx = Math.min(playbackIdx, Math.max(0, timeline.steps.length - 1));
  const activeStep = timeline.steps[clampedIdx];

  useEffect(() => {
    setPlaybackIdx(Math.max(0, timeline.steps.length - 1));
    setIsPlaying(false);
  }, [targetPhone, nightOnly, timeline.steps.length]);

  useEffect(() => {
    if (!isPlaying || timeline.steps.length <= 1) return;
    const timer = window.setInterval(() => {
      setPlaybackIdx((prev) => {
        if (prev >= timeline.steps.length - 1) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 900);
    return () => window.clearInterval(timer);
  }, [isPlaying, timeline.steps.length]);

  // Mount Leaflet map once
  useEffect(() => {
    if (!mapContainerRef.current || mapRef.current) return;
    const map = L.map(mapContainerRef.current, {
      center: [26.872, 75.788],
      zoom: 12,
      scrollWheelZoom: true,
    });
    layerGroupRef.current = L.layerGroup().addTo(map);
    mapRef.current = map;

    return () => {
      map.remove();
      mapRef.current = null;
      layerGroupRef.current = null;
    };
  }, []);

  // Render towers, azimuth wedges, movement polyline, and active observation ping
  useEffect(() => {
    const map = mapRef.current;
    const group = layerGroupRef.current;
    if (!map || !group) return;
    group.clearLayers();

    const boundsCoords: [number, number][] = [];

    // 1. Draw all mapped towers with directional sector coverage wedges
    for (const t of caseFile.towers) {
      const hitInfo = timeline.towerSummary.find((s) => s.towerId === t.towerId);
      const isUsed = Boolean(hitInfo);
      boundsCoords.push([t.lat, t.lon]);

      const wedge = buildSectorPolygon(t.lat, t.lon, t.azimuthDegrees, isUsed ? 950 : 650);
      L.polygon(wedge, {
        color: isUsed ? '#1d4ed8' : '#64748b',
        weight: 1,
        fillColor: isUsed ? '#3b82f6' : '#94a3b8',
        fillOpacity: isUsed ? 0.18 : 0.08,
      }).addTo(group);

      const marker = L.circleMarker([t.lat, t.lon], {
        radius: isUsed ? 8 : 5,
        fillColor: isUsed ? '#1d4ed8' : '#64748b',
        color: '#ffffff',
        weight: 2,
        fillOpacity: 0.95,
      });
      const popup = document.createElement('div');
      const title = document.createElement('strong');
      title.textContent = t.towerName;
      const detail = document.createElement('p');
      detail.textContent = t.towerId + ' · Azimuth ' + t.azimuthDegrees + '° · ' +
        (hitInfo ? hitInfo.hitCount + ' serving hits' : 'No hits for selected subject');
      popup.append(title, detail);
      marker.bindPopup(popup);
      marker.addTo(group);
    }

    // 2. Chronological movement path up to current playback step
    const visibleSteps = timeline.steps
      .slice(0, clampedIdx + 1)
      .filter((s) => s.lat !== undefined && s.lon !== undefined);

    if (visibleSteps.length >= 2) {
      const latlngs = visibleSteps.map((s) => [s.lat!, s.lon!] as [number, number]);
      L.polyline(latlngs, {
        color: '#d97706',
        weight: 3,
        dashArray: '6 6',
        opacity: 0.85,
      }).addTo(group);
    }

    // 3. Highlight active playback step
    if (activeStep && activeStep.lat !== undefined && activeStep.lon !== undefined) {
      const label = document.createElement('span');
      label.textContent = '#' + activeStep.index + ' · ' + activeStep.towerId + ' (' + formatISTDisplay(activeStep.timestampIso) + ')';
      L.circleMarker([activeStep.lat, activeStep.lon], {
        radius: 13,
        color: '#dc2626',
        weight: 2.5,
        fillColor: '#f59e0b',
        fillOpacity: 0.35,
      })
        .bindTooltip(
          label,
          { direction: 'top' }
        )
        .addTo(group);
    }

    if (boundsCoords.length > 0) {
      map.fitBounds(L.latLngBounds(boundsCoords), { padding: [36, 36], maxZoom: 13 });
    }
  }, [caseFile.towers, timeline, clampedIdx, activeStep]);

  return (
    <div className="space-y-6">
      {/* Controls */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[240px]">
            <label
              htmlFor="tower-subject-select"
              className="block text-[11px] font-medium text-slate-500 dark:text-slate-400 mb-1"
            >
              Subject MSISDN (Serving Cell Observations)
            </label>
            <select
              id="tower-subject-select"
              value={targetPhone}
              onChange={(e) => setTargetPhone(e.target.value)}
              className="w-full text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
            >
              {caseFile.suspects.map((s) => (
                <option key={s.phone} value={s.phone}>
                  {s.name} ({s.phone})
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg">
            <button
              type="button"
              onClick={() => setNightOnly(false)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md ${
                !nightOnly
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-400'
              }`}
            >
              Full Timeline
            </button>
            <button
              type="button"
              onClick={() => setNightOnly(true)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md ${
                nightOnly
                  ? 'bg-white dark:bg-slate-900 text-amber-800 dark:text-amber-300 shadow-sm'
                  : 'text-slate-600 dark:text-slate-400'
              }`}
            >
              Night 00–06 IST
            </button>
          </div>
        </div>

        <div className="flex items-center gap-5 text-xs">
          <div>
            <span className="text-slate-500 dark:text-slate-400 block">Observations</span>
            <span className="font-mono tabular-nums font-semibold text-slate-900 dark:text-white">
              {timeline.steps.length}
            </span>
          </div>
          <div>
            <span className="text-slate-500 dark:text-slate-400 block">Tower Transitions</span>
            <span className="font-mono tabular-nums font-semibold text-slate-900 dark:text-white">
              {timeline.transitions}
            </span>
          </div>
          <div>
            <span className="text-slate-500 dark:text-slate-400 block">Max Implied Speed</span>
            <span className="font-mono tabular-nums font-semibold text-slate-900 dark:text-white">
              {timeline.maxImpliedSpeedKmh} km/h
            </span>
          </div>
        </div>
      </section>

      {/* Map + Playback Scrubber + IMEI/SIM Sidebar */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 items-stretch">
        <section className="xl:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden flex flex-col">
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
                Serving Cell-Tower Geospatial Map &amp; Sector Azimuths
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Displays operator-supplied serving tower coordinates and directional wedges (not exact GPS route)
              </p>
            </div>
          </div>

          <div
            ref={mapContainerRef}
            data-testid="tower-leaflet-map"
            className="w-full flex-1 min-h-[410px]"
          />

          {/* Playback Controls */}
          {timeline.steps.length > 0 && (
            <div className="px-5 py-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => {
                  if (clampedIdx >= timeline.steps.length - 1) setPlaybackIdx(0);
                  setIsPlaying((p) => !p);
                }}
                aria-label={isPlaying ? 'Pause tower timeline playback' : 'Play tower timeline'}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-700 hover:bg-blue-800 text-white"
              >
                {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                <span>{isPlaying ? 'Pause' : 'Play Path'}</span>
              </button>

              <input
                type="range"
                aria-label="Tower sequence timeline scrubber"
                min={0}
                max={Math.max(0, timeline.steps.length - 1)}
                value={clampedIdx}
                onChange={(e) => {
                  setIsPlaying(false);
                  setPlaybackIdx(Number(e.target.value));
                }}
                className="flex-1 min-w-[140px] accent-blue-700"
              />

              {activeStep && (
                <span className="font-mono text-[11px] text-slate-700 dark:text-slate-300">
                  #{activeStep.index}/{timeline.steps.length} · {activeStep.towerId} ·{' '}
                  {formatISTDisplay(activeStep.timestampIso)}
                </span>
              )}
            </div>
          )}
        </section>

        {/* IMEI / SIM Swap & Shared Handset Panel */}
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col space-y-3">
          <div>
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <Smartphone className="w-4 h-4 text-blue-700 dark:text-blue-400" />
              <span>IMEI &amp; SIM Change Detection</span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Chronological handset switches and SIM (IMSI / ICCID) swaps with exact row citations
            </p>
          </div>

          <div className="space-y-2.5 flex-1 overflow-y-auto max-h-[450px] pr-1">
            {deviceAnalysis.changes.length === 0 ? (
              <p className="text-xs text-slate-500 dark:text-slate-400 py-4">
                No IMEI or SIM (IMSI/ICCID) changes observed for this subscriber.
              </p>
            ) : (
              deviceAnalysis.changes.map((ch) => (
                <div
                  key={ch.id}
                  className="p-3.5 rounded-lg bg-amber-50/70 dark:bg-amber-950/25 border border-amber-200 dark:border-amber-900/60 space-y-1.5 text-xs"
                >
                  <p className="font-semibold text-amber-900 dark:text-amber-300">
                    {ch.changeType === 'IMEI_CHANGE'
                      ? 'Handset IMEI Changed'
                      : ch.changeType === 'SIM_SWAP_IMSI'
                        ? 'SIM Swap (IMSI Changed)'
                        : 'SIM Card Replaced (ICCID Changed)'}
                  </p>
                  <div className="font-mono text-[11px] text-slate-800 dark:text-slate-200 space-y-0.5">
                    <div>Prev: {ch.previousValue}</div>
                    <div>New:  {ch.newValue}</div>
                  </div>
                  <p className="text-[11px] text-slate-600 dark:text-slate-400 font-mono">
                    Observed {formatISTDisplay(ch.newTimestampIso)}
                  </p>
                  <div className="flex flex-wrap gap-2 pt-0.5">
                    <button
                      type="button"
                      onClick={() => onInspectCitation(ch.previousCitation)}
                      className="font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                    >
                      Before [{ch.previousCitation.sourceFile}:R{ch.previousCitation.rowNumber}]
                    </button>
                    <button
                      type="button"
                      onClick={() => onInspectCitation(ch.newCitation)}
                      className="font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                    >
                      After [{ch.newCitation.sourceFile}:R{ch.newCitation.rowNumber}]
                    </button>
                  </div>
                </div>
              ))
            )}

            {deviceAnalysis.sharedDevices.map((sd) => (
              <div
                key={sd.imei}
                className="p-3.5 rounded-lg bg-red-50/70 dark:bg-red-950/30 border border-red-200 dark:border-red-900/60 space-y-1.5 text-xs"
              >
                <div className="flex items-center gap-1.5 font-semibold text-red-800 dark:text-red-300">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>Cross-Suspect Shared Handset</span>
                </div>
                <p className="font-mono text-[11px] text-slate-800 dark:text-slate-200">
                  IMEI {sd.imei} shared across{' '}
                  {sd.msisdns.map((m) => m.name || m.phone).join(' & ')}
                </p>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Serving Tower Sequence Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800">
          <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
            Chronological Serving Tower Sequence ({timeline.steps.length} records)
          </h3>
        </div>
        <div className="overflow-x-auto max-h-[340px]">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
              <tr>
                <th className="py-2 px-4 font-medium">#</th>
                <th className="py-2 px-3 font-medium">Timestamp (IST)</th>
                <th className="py-2 px-3 font-medium">Serving Tower</th>
                <th className="py-2 px-3 font-medium">Transition / Transit</th>
                <th className="py-2 px-3 font-medium">IMEI</th>
                <th className="py-2 px-3 font-medium">Operator</th>
                <th className="py-2 px-4 font-medium text-right">Source Ref</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {timeline.steps.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-7 text-center text-slate-500">
                    No serving tower observations available for this subject.
                  </td>
                </tr>
              ) : (
                timeline.steps.map((st, idx) => {
                  return (
                    <tr
                      key={`${st.sourceFile}-${st.rowNumber}`}
                      onClick={() => setPlaybackIdx(idx)}
                      className={`cursor-pointer ${
                        idx === clampedIdx
                          ? 'bg-blue-50/70 dark:bg-blue-950/40'
                          : 'hover:bg-slate-50/80 dark:hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-2 px-4 font-mono tabular-nums text-slate-500">
                        {st.index}
                      </td>
                      <td className="py-2 px-3 font-mono tabular-nums text-slate-900 dark:text-slate-100">
                        {formatISTDisplay(st.timestampIso)}
                      </td>
                      <td className="py-2 px-3">
                        <span className="font-medium text-slate-900 dark:text-slate-100">
                          {st.towerName}
                        </span>{' '}
                        <span className="font-mono text-[11px] text-slate-500">({st.towerId})</span>
                      </td>
                      <td className="py-2 px-3 text-[11px]">
                        {st.isTransition ? (
                          <span
                            className={
                              st.speedAnomaly
                                ? 'font-semibold text-red-700 dark:text-red-400'
                                : 'font-medium text-amber-800 dark:text-amber-300'
                            }
                          >
                            Hop ({st.distanceFromPrevKm ?? '?'} km · ~{st.impliedSpeedKmh ?? '?'} km/h)
                          </span>
                        ) : (
                          <span className="text-slate-400">Same sector</span>
                        )}
                      </td>
                      <td className="py-2 px-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                        {st.imei || '—'}
                      </td>
                      <td className="py-2 px-3 text-slate-600 dark:text-slate-300">{st.operator}</td>
                      <td className="py-2 px-4 text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onInspectCitation(st.citation);
                            }}
                            className="font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                          >
                            [{st.sourceFile}:R{st.rowNumber}]
                          </button>
                      </td>
                    </tr>
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
