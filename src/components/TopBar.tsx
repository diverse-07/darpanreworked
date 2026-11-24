import { Menu, Moon, Sun, Upload } from 'lucide-react';
import type { CaseFile, OfficerSession } from '../types/forensics.ts';
import type { NavTab } from './Sidebar.tsx';

interface TopBarProps {
  activeTab: NavTab;
  activeCase: CaseFile | null;
  officer: OfficerSession | null;
  demo: boolean;
  darkMode: boolean;
  mobileNavOpen: boolean;
  onToggleDarkMode: () => void;
  onOpenMobileNav: () => void;
  onNavigateImport: () => void;
}

const TAB_LABELS: Record<NavTab, string> = {
  overview: 'Case overview',
  import: 'Import evidence',
  contacts: 'Contact patterns',
  network: 'Contact network',
  lab: 'Evidence lab',
  map: 'Tower timeline',
  ipdr: 'IPDR lookup',
  ai: 'Evidence assistant',
  reports: 'Reports and review',
  audit: 'Access and audit',
};

export function TopBar({
  activeTab, activeCase, officer, demo, darkMode, mobileNavOpen, onToggleDarkMode, onOpenMobileNav, onNavigateImport,
}: TopBarProps) {
  const canImport = officer?.role === 'investigator' || officer?.role === 'admin';
  return (
    <header className="station-topbar">
      <div className="station-crumb">
        <button type="button" onClick={onOpenMobileNav} aria-label="Open navigation menu" aria-haspopup="dialog"
          aria-expanded={mobileNavOpen} className="station-icon rail-open">
          <Menu size={18} aria-hidden="true"/>
        </button>
        <nav aria-label="Breadcrumb">
          {activeCase && <><span>{activeCase.caseNumber}</span><i aria-hidden="true">/</i></>}
          <h1>{TAB_LABELS[activeTab]}</h1>
        </nav>
      </div>
      <div className="station-tools">
        <span className="station-mode"><i aria-hidden="true"/>{demo ? 'Synthetic case' : 'Local station'}</span>
        <button type="button" onClick={onToggleDarkMode} className="station-icon"
          aria-label={darkMode ? 'Switch to light theme' : 'Switch to dark theme'}>
          {darkMode ? <Sun size={16} aria-hidden="true"/> : <Moon size={16} aria-hidden="true"/>}
        </button>
        {activeTab !== 'import' && (
          <button type="button" className="station-action station-import" onClick={onNavigateImport} disabled={!canImport}
            aria-label="Import evidence" title={canImport ? 'Import evidence' : 'Only investigators can import evidence'}>
            <Upload size={16} aria-hidden="true"/><span>Import evidence</span>
          </button>
        )}
      </div>
    </header>
  );
}
