import type { ComponentType } from 'react';
import { useEffect, useId, useRef } from 'react';
import {
  Activity, Aperture, Bot, FileSpreadsheet, FolderPlus, Globe, LayoutDashboard,
  MapPin, Network, ScanLine, ShieldCheck, Upload, X,
} from 'lucide-react';
import type { CaseFile, OfficerSession } from '../types/forensics.ts';

export type NavTab = 'overview' | 'import' | 'contacts' | 'network' | 'lab' | 'map' | 'ipdr' | 'ai' | 'reports' | 'audit';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  cases: CaseFile[];
  activeCaseId: string;
  onSelectCase: (caseId: string) => void;
  onOpenNewCase: () => void;
  officer: OfficerSession | null;
  pendingReviewCount: number;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

type NavEntry = [NavTab, string, ComponentType<{ className?: string }>];
const groups: Array<[string, NavEntry[]]> = [
  ['Casework', [['overview', 'Case overview', LayoutDashboard], ['import', 'Import evidence', Upload]]],
  ['Investigation', [
    ['contacts', 'Contact patterns', Activity], ['network', 'Contact network', Network],
    ['lab', 'Evidence lab', Aperture], ['map', 'Towers and devices', MapPin],
    ['ipdr', 'IPDR lookup', Globe], ['ai', 'Evidence assistant', Bot],
  ]],
  ['Review', [['reports', 'Reports and review', FileSpreadsheet], ['audit', 'Access and audit', ShieldCheck]]],
];

function RailContent({
  activeTab, onSelectTab, cases, activeCaseId, onSelectCase, onOpenNewCase,
  officer, pendingReviewCount, onCloseMobile,
}: SidebarProps) {
  const canCreate = officer?.role === 'investigator' || officer?.role === 'admin';
  const sources = cases.find(item => item.id === activeCaseId)?.sources ?? [];
  const caseSelectorId = useId();
  const navigate = (tab: NavTab) => { onSelectTab(tab); onCloseMobile(); };
  const initials = officer?.displayName.trim().split(/\s+/).slice(-2).map(word => word[0]).join('').toUpperCase();
  return (
    <div className="station-rail">
      <div className="rail-brand">
        <button type="button" onClick={() => navigate('overview')} className="rail-home">
          <span className="rail-mark"><ScanLine aria-hidden="true" size={19}/></span>
          <span><strong>Darpan</strong><small>Telecom forensics</small></span>
        </button>
        <button type="button" onClick={onCloseMobile} aria-label="Close navigation menu" className="station-icon rail-close">
          <X size={17} aria-hidden="true"/>
        </button>
      </div>
      <div className="rail-case">
        <label htmlFor={caseSelectorId}>Active case</label>
        <div>
          <select id={caseSelectorId} value={activeCaseId} onChange={event => onSelectCase(event.target.value)}>
            {cases.map(item => <option key={item.id} value={item.id}>{item.caseNumber} · {item.title}</option>)}
          </select>
          <button type="button" onClick={() => { onCloseMobile(); onOpenNewCase(); }} disabled={!canCreate} className="station-icon"
            aria-label="Create new case" title={canCreate ? 'Create new case' : 'Only investigators can create cases'}>
            <FolderPlus size={17} aria-hidden="true"/>
          </button>
        </div>
      </div>
      <nav aria-label="Investigation sections" className="rail-nav">
        {groups.map(([label, entries]) => (
          <div className="rail-group" key={label}>
            <p>{label}</p>
            {entries.map(([tab, name, Icon]) => (
              <button key={tab} type="button" className="rail-link" aria-current={activeTab === tab ? 'page' : undefined}
                onClick={() => navigate(tab)}>
                <Icon className="rail-icon"/>
                <span>{name}</span>
                {tab === 'reports' && pendingReviewCount > 0 && <small>{pendingReviewCount}</small>}
              </button>
            ))}
          </div>
        ))}
        {activeTab === 'overview' && <details className="rail-datasets" open>
          <summary>Datasets <span>{sources.length}</span></summary>
          <ul>{sources.map(source => (
            <li key={source.id} title={source.fileName}>
              <FileSpreadsheet size={13} aria-hidden="true"/>
              <span>{source.fileName}</span>
              <small>{source.validRowCount}</small>
            </li>
          ))}</ul>
          {!sources.length && <p>No datasets imported.</p>}
        </details>}
      </nav>
      {officer && (
        <button type="button" className="rail-account" onClick={() => navigate('audit')}>
          <span className="rail-avatar" aria-hidden="true">{initials}</span>
          <span><strong>{officer.displayName}</strong><small>{officer.role}{officer.badgeNumber ? ' · ' + officer.badgeNumber : ''}</small></span>
          <ShieldCheck size={16} aria-hidden="true"/>
        </button>
      )}
    </div>
  );
}

export function Sidebar(props: SidebarProps) {
  const drawer = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = drawer.current;
    if (!element) return;
    if (props.mobileOpen && !element.open) element.showModal();
    if (!props.mobileOpen && element.open) element.close();
  }, [props.mobileOpen]);
  useEffect(() => {
    if (!props.mobileOpen) return;
    const desktop = window.matchMedia('(min-width: 1024px)');
    const closeOnDesktop = () => { if (desktop.matches) drawer.current?.close(); };
    desktop.addEventListener('change', closeOnDesktop);
    closeOnDesktop();
    return () => desktop.removeEventListener('change', closeOnDesktop);
  }, [props.mobileOpen]);
  return (
    <>
      <aside className="hidden lg:block shrink-0 sticky top-0 h-dvh"><RailContent {...props}/></aside>
      <dialog ref={drawer} className="station-drawer lg:hidden" aria-label="Navigation"
        onClose={props.onCloseMobile} onClick={event => { if (event.target === event.currentTarget) props.onCloseMobile(); }}>
        <div className="station-drawer-body"><RailContent {...props}/></div>
      </dialog>
    </>
  );
}
