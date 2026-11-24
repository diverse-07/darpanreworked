import { useId, useMemo, useRef, useState, type ReactNode } from 'react';
import { Aperture, AudioWaveform, Cable, FileSearch, MapPin, Minus, Pause, Play, Plus, RotateCcw, Smartphone, UserRound } from 'lucide-react';
import type { CaseFile, EvidenceCitation } from '../types/forensics.ts';
import { cdrToCitation, ipdrToCitation, isVoiceCall } from '../lib/forensics.ts';
import { FaceScan, scanViewCount } from './FaceScan.tsx';
import './evidence-lab.css';

type LabNode = {
  id: string;
  label: string;
  detail: string;
  kind: 'person' | 'call' | 'session' | 'tower' | 'device';
  count: number;
  cites: EvidenceCitation[];
};

const accent = { person: '#70e5ff', call: '#a89bff', session: '#ffbf81', tower: '#6ff3bc', device: '#f89cda' };
const icons = { person: UserRound, call: AudioWaveform, session: Cable, tower: MapPin, device: Smartphone };
const peoplePositions = [[159,86],[88,181],[116,286],[224,347]];
const evidencePositions = [[645,70],[711,155],[711,249],[624,337]];

function collectNodes(caseFile: CaseFile, subject: string): LabNode[] {
  const contacts = caseFile.cdrs.filter(row => row.caller === subject || row.callee === subject);
  const calls = contacts.filter(isVoiceCall);
  const peers = new Map<string, typeof calls>();
  for (const row of calls) {
    const peer = row.caller === subject ? row.callee : row.caller;
    const bucket = peers.get(peer) || [];
    bucket.push(row);
    peers.set(peer, bucket);
  }
  const people: LabNode[] = [...peers].sort((a,b) => b[1].length - a[1].length).slice(0,4).map(([phone, records]) => ({
    id: phone, label: caseFile.suspects.find(p => p.phone === phone)?.name || phone, detail: phone,
    kind: 'person', count: records.length, cites: records.slice(0,6).map(cdrToCitation),
  }));
  const sessions = caseFile.ipdrs.filter(row => row.msisdn === subject);
  const observations = contacts.filter(row => row.observedMsisdn === subject);
  const towers = observations.filter(row => row.cellTowerId);
  const sessionTowers = sessions.filter(row => row.cellTowerId);
  const hasDevice = (row: { imei?: string; imsi?: string; iccid?: string }) => Boolean(row.imei || row.imsi || row.iccid);
  const deviceCitations = [
    ...observations.filter(hasDevice).map(cdrToCitation),
    ...sessions.filter(hasDevice).map(ipdrToCitation),
  ].sort((a, b) => Date.parse(b.timestamp ?? '') - Date.parse(a.timestamp ?? ''));
  return people.concat([
    { id:'calls', label:'Call records', detail:'CDR', kind:'call', count:calls.length, cites:calls.slice(0,6).map(cdrToCitation) },
    { id:'sessions', label:'IP sessions', detail:'IPDR', kind:'session', count:sessions.length, cites:sessions.slice(0,6).map(ipdrToCitation) },
    { id:'towers', label:'Tower observations', detail:'Serving cell', kind:'tower', count:towers.length + sessionTowers.length,
      cites:[...towers.map(cdrToCitation), ...sessionTowers.map(ipdrToCitation)].slice(0,6) },
    { id:'devices', label:'Devices and SIMs', detail:'IMEI, IMSI or ICCID observations', kind:'device', count:deviceCitations.length,
      cites:deviceCitations.slice(0,6) },
  ]);
}

function EvidenceGraph({ nodes, subjectName, selected, onSelect, playing, zoom = 1, grid = false }: {
  nodes: LabNode[];
  subjectName: string;
  selected: string;
  onSelect: (id: string) => void;
  playing: boolean;
  zoom?: number;
  grid?: boolean;
}) {
  const id = useId();
  let people = 0;
  let evidence = 0;
  const positioned = nodes.map(node => ({
    ...node,
    at: node.kind === 'person' ? peoplePositions[people++] : evidencePositions[evidence++],
  }));
  const selectedNode = selected && positioned.find(node => node.id === selected);
  return (
    <svg className="lab-graph" viewBox={`${400 - 400 / zoom} ${205 - 205 / zoom} ${800 / zoom} ${410 / zoom}`} role="group" aria-label="Subject and case evidence links">
      <defs>
        <pattern id={id + '-dots'} width="24" height="24" patternUnits="userSpaceOnUse">
          {grid ? <path d="M24 0H0V24" fill="none" stroke="#a6bbc4" strokeOpacity=".18" strokeWidth="1"/>
            : <circle cx="1" cy="1" r=".75" fill="#83b0ca" opacity=".28"/>}
        </pattern>
        <radialGradient id={id + '-glow'}>
          <stop offset="0" stopColor="#5da6ff" stopOpacity=".32" />
          <stop offset="1" stopColor="#5da6ff" stopOpacity="0" />
        </radialGradient>
        <radialGradient id={id + '-glass'} cx=".34" cy=".25" r=".76">
          <stop stopColor="#234a74"/><stop offset=".55" stopColor="#101a41"/>
          <stop offset="1" stopColor="#142e64"/>
        </radialGradient>
        <linearGradient id={id + '-ribbon'} x1="0" y1=".2" x2=".9" y2="1">
          <stop stopColor="#53e0fb"/><stop offset=".4" stopColor="#7c7cff"/>
          <stop offset=".73" stopColor="#ed9efa"/><stop offset="1" stopColor="#72f4cc"/>
        </linearGradient>
        <filter id={id + '-soft'}><feGaussianBlur stdDeviation="4"/></filter>
        <clipPath id={id + '-clip'}><circle cx="400" cy="200" r="58"/></clipPath>
        {positioned.map((node,i) => (
          <linearGradient key={node.id} id={id + '-link-' + i} gradientUnits="userSpaceOnUse"
            x1="400" y1="200" x2={node.at[0]} y2={node.at[1]}>
            <stop stopColor="#757cff"/>
            <stop offset="1" stopColor={accent[node.kind]}/>
          </linearGradient>
        ))}
      </defs>
      <rect width="800" height="410" fill={`url(#${id}-dots)`}/>
      {grid && <path className="explorer-hull" d="M141 77C270 28 530 26 657 67C743 94 774 227 712 309C649 394 302 408 163 354C67 317 34 216 70 133C88 101 110 89 141 77Z"/>}
      <ellipse cx="400" cy="200" rx="277" ry="126" className="lab-orbit"/>
      <ellipse cx="400" cy="200" rx="156" ry="88" className="lab-orbit lab-orbit-inner"/>
      <circle cx="400" cy="200" r="125" fill={`url(#${id}-glow)`}/>
      {positioned.map((node,i) => {
        const [x,y] = node.at;
        const path = `M400 200 Q ${(400+x)/2} ${(200+y)/2 + (x<400 ? 42 : -42)} ${x} ${y}`;
        const visible = node.count > 0;
        const highlight = node.id === selected || !selectedNode;
        return (
          <g key={node.id} opacity={highlight ? 1 : .42} className="lab-graph-link" aria-hidden="true">
            {visible && <path d={path} stroke={accent[node.kind]} strokeWidth="7" opacity=".16" fill="none" filter={`url(#${id}-soft)`}/>}
            <path d={path} stroke={`url(#${id}-link-${i})`} strokeWidth={visible ? 1.8 : 1} opacity={visible ? .8 : .32} strokeDasharray={visible ? undefined : '3 7'} fill="none"/>
            {playing && visible && highlight && [0,1].map(n => (
              <circle key={n} r={n ? 2 : 3.4} fill={n ? accent[node.kind] : '#eeffff'} className="lab-particle"
                style={{ color:accent[node.kind] }}>
                <animateMotion path={path} dur={(2.35 + (i % 3) * .33) + 's'} begin={`-${i*.29+n*.43}s`} repeatCount="indefinite"/>
              </circle>
            ))}
          </g>
        );
      })}
      <g aria-hidden="true" className={playing ? 'lab-orb lab-orb-playing' : 'lab-orb'}>
        <circle cx="400" cy="200" r="72" className="lab-orb-ring"/>
        <circle cx="400" cy="200" r="59" fill={`url(#${id}-glass)`} stroke="#83b9ff" strokeWidth="1.4"/>
        <g clipPath={`url(#${id}-clip)`}>
          <g className="lab-orb-flow">
            <path d="M346 217C374 209 364 151 392 153C410 145 421 181 435 184C463 199 451 229 427 240C410 248 404 209 386 215C369 220 356 241 346 217Z"
              fill={`url(#${id}-ribbon)`} filter={`url(#${id}-soft)`} opacity=".95"/>
            <path d="M357 223C360 184 424 216 429 177C434 147 447 211 422 234C398 261 379 169 353 193"
              fill="none" stroke={`url(#${id}-ribbon)`} strokeWidth="2"/>
            <path d="M352 207C371 219 369 170 406 171C428 172 440 230 417 241C395 255 378 214 399 207"
              fill="none" stroke="#b8f6ff" strokeOpacity=".62" strokeWidth="1.25"/>
          </g>
        </g>
        <path d="M359 173A50 50 0 0 1 421 155" fill="none" stroke="#c2ebff" strokeOpacity=".5"/>
        <rect x="313" y="280" width="174" height="29" rx="5" fill="#101e30" stroke="#37506d"/>
        <text x="400" y="299" textAnchor="middle" className="lab-orb-label">{subjectName.length > 22 ? subjectName.slice(0,21) + '…' : subjectName}</text>
      </g>
      {positioned.map(node => {
        const [x,y] = node.at;
        const Icon = icons[node.kind];
        return (
          <g key={node.id} transform={`translate(${x} ${y})`} role="button" tabIndex={0}
            aria-label={`Inspect ${node.label}, ${node.count} records`} aria-pressed={selected === node.id}
            onClick={() => onSelect(node.id)} onKeyDown={event => {
              if (event.key !== 'Enter' && event.key !== ' ') return;
              event.preventDefault();
              onSelect(node.id);
            }} className="lab-node" style={{ color:accent[node.kind] }}>
            <circle className="lab-node-halo" r="37"/>
            <circle className="lab-node-outer" r="25"/>
            <circle className="lab-node-core" r="18"/>
            <Icon x={-8} y={-8} width={16} height={16} strokeWidth={1.65}/>
            <text y="42" textAnchor="middle" className="lab-node-title">{node.label.length > 24 ? node.label.slice(0,23) + '…' : node.label}</text>
            <text y="58" textAnchor="middle" className="lab-node-count">{node.count} {node.count === 1 ? 'record' : 'records'}</text>
          </g>
        );
      })}
    </svg>
  );
}

export function EvidenceLinks({ caseFile, onInspectCitation, playing, workspace }: {
  caseFile: CaseFile;
  onInspectCitation: (citation: EvidenceCitation) => void;
  playing: boolean;
  workspace?: { motionControl: ReactNode; portrait: ReactNode };
}) {
  const titleId = useId();
  const subjectId = useId();
  const [subject, setSubject] = useState(caseFile.suspects[0]?.phone || caseFile.cdrs[0]?.caller || caseFile.ipdrs[0]?.msisdn || '');
  const [selected, setSelected] = useState('');
  const [zoom, setZoom] = useState(1);
  const nodes = useMemo(() => collectNodes(caseFile, subject), [caseFile, subject]);
  const activeNode = nodes.find(n => n.id === selected);
  const people = useMemo(() => {
    const choices = new Map(caseFile.suspects.map(p => [p.phone,p.name]));
    for (const phone of [subject, ...caseFile.cdrs.flatMap(row => [row.caller,row.callee]), ...caseFile.ipdrs.map(row => row.msisdn)]) {
      if (phone && !choices.has(phone)) choices.set(phone,phone);
    }
    return choices;
  }, [caseFile, subject]);

  const subjectName = people.get(subject) || subject;
  return (
      <section aria-labelledby={titleId} className={workspace ? 'lab-panel explorer-links' : 'lab-panel'}>
        <div className="lab-panel-head"><Cable size={17} aria-hidden="true"/><h3 id={titleId}>{workspace ? 'Graph explorer' : 'Evidence links'}</h3><span>{workspace ? `${nodes.filter(node => node.count > 0).length} linked nodes` : 'Case records'}</span></div>
        <div className="lab-links-toolbar">
          <label htmlFor={subjectId}>Case subject</label>
          <select id={subjectId} value={subject} disabled={!people.size} onChange={event => { setSubject(event.target.value); setSelected(''); setZoom(1); }}>
            {!people.size && <option value="">No subjects in this case</option>}
            {[...people].map(([phone,name]) => <option key={phone} value={phone}>{name}</option>)}
          </select>
          {workspace && <div className="explorer-zoom" role="group" aria-label="Graph view controls">
            {workspace.motionControl}
            <button type="button" className="lab-control" aria-label="Zoom out" title="Zoom out" disabled={!subject || zoom <= 1} onClick={() => setZoom(zoom - .1)}><Minus size={14} aria-hidden="true"/></button>
            <output aria-label="Graph zoom">{Math.round(zoom * 100)}%</output>
            <button type="button" className="lab-control" aria-label="Zoom in" title="Zoom in" disabled={!subject || zoom >= 1.19} onClick={() => setZoom(zoom + .1)}><Plus size={14} aria-hidden="true"/></button>
            <button type="button" className="lab-control" aria-label="Reset graph view" title="Reset graph view" disabled={!subject || zoom <= 1} onClick={() => setZoom(1)}><RotateCcw size={14} aria-hidden="true"/></button>
          </div>}
        </div>
        {subject || workspace ? (
          <div className="lab-links-body">
            {subject ? <div className="lab-graph-scroll">
              <EvidenceGraph nodes={nodes} subjectName={subjectName} selected={selected}
                onSelect={id => setSelected(current => current === id ? '' : id)} playing={playing} zoom={zoom} grid={Boolean(workspace)}/>
              {workspace && <div className="explorer-legend">
                <span><i/> Recorded link</span><span><i/> No matching records</span>
              </div>}
            </div> : <p className="lab-empty">Import case records to populate the evidence links.</p>}
            <aside className="lab-link-details">
              {workspace && <div className="explorer-dossier">
                <p>Entity dossier</p>
                <h4>{activeNode?.label || subjectName || 'No subject selected'}</h4>
                <small>{activeNode ? activeNode.detail : subject}</small>
              </div>}
              {workspace?.portrait}
              <div className="explorer-citations">
              <h4>{workspace || !activeNode ? 'Source records' : activeNode.label}</h4>
              {activeNode ? <>
                <p>{!workspace && activeNode.detail + ' · '}{activeNode.count} {activeNode.count === 1 ? 'record' : 'records'}</p>
                {activeNode.cites.map((cite, i) => (
                  <button className="lab-citation" type="button" key={cite.recordId + '-' + i} onClick={() => onInspectCitation(cite)}>
                    <FileSearch size={15} aria-hidden="true"/> <span>{cite.sourceFile}<small>Row {cite.rowNumber}</small></span>
                  </button>
                ))}
                {!activeNode.cites.length && <p>No records of this type for the selected subject.</p>}
              </> : <p>Select a person or evidence node to open its cited records.</p>}
              </div>
            </aside>
          </div>
        ) : <p className="lab-empty">Import case records to populate the evidence links.</p>}
      </section>
  );
}

export function EvidenceLab({ caseFile, onInspectCitation }: {
  caseFile: CaseFile;
  onInspectCitation: (citation: EvidenceCitation) => void;
}) {
  const [playing, setPlaying] = useState(() => !window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const [angle, setAngle] = useState(0);
  const scanAngle = useRef(0);

  const changeAngle = (value: number) => {
    scanAngle.current = value;
    setAngle(value);
    setPlaying(false);
  };

  return (
    <div className="evidence-lab" data-running={playing}>
      <header className="lab-header">
        <div><span className="lab-case">PS03 / {caseFile.caseNumber}</span>
          <h2>Evidence lab</h2>
          <p>Inspect a synthetic portrait scan and trace the records connected to a case subject.</p>
        </div>
        <button type="button" className="lab-control" onClick={() => {
          setAngle(Math.round(scanAngle.current));
          setPlaying(!playing);
        }}>
          {playing ? <Pause size={16} aria-hidden="true"/> : <Play size={16} aria-hidden="true"/>}
          {playing ? 'Pause motion' : 'Play motion'}
        </button>
      </header>

      <section aria-labelledby="lab-face-title" className="lab-panel lab-face-panel">
        <div className="lab-panel-head"><Aperture size={17} aria-hidden="true"/><h3 id="lab-face-title">Face scan</h3><span>Synthetic portrait</span></div>
        <div className="lab-face-body">
          <div className="lab-face-stage">
            <div className="lab-reticle" aria-hidden="true"/>
            <span className="lab-stage-caption">Scan stage / 360°</span>
            <FaceScan playing={playing} angle={angle} scanAngle={scanAngle}/>
          </div>
          <div className="lab-scan-info">
            <h4>Portrait inspection</h4>
            <p>Rotate the fictional subject and follow the scan beam across sample landmarks.</p>
            <dl><div><dt>Viewing range</dt><dd>360°</dd></div>
              <div><dt>Portrait views</dt><dd>{scanViewCount}</dd></div></dl>
            <label htmlFor="lab-angle">Rotation angle</label>
            <input id="lab-angle" type="range" min="0" max="360" value={angle} onChange={event => changeAngle(Number(event.target.value))}/>
            <button className="lab-control" type="button" onClick={() => changeAngle(0)}><RotateCcw size={15} aria-hidden="true"/> Reset view</button>
          </div>
        </div>
      </section>

      <EvidenceLinks caseFile={caseFile} onInspectCitation={onInspectCitation} playing={playing}/>
    </div>
  );
}
