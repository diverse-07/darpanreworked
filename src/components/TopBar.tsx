import React from 'react';
import { Menu, Moon, Sun, Upload } from 'lucide-react';
import type { CaseFile, OfficerSession } from '../types/forensics.ts';
import type { NavTab } from './Sidebar.tsx';

interface TopBarProps {
  activeTab: NavTab;
  activeCase: CaseFile | null;
  officer: OfficerSession | null;
  darkMode: boolean;
  onToggleDarkMode: () => void;
  onOpenMobileNav: () => void;
  onNavigateImport: () => void;
}

const TAB_LABELS: Record<NavTab, string> = {
  overview: 'Case overview',
  import: 'Import evidence',
  contacts: 'Contact patterns',
  network: 'Contact network',
  map: 'Tower timeline',
  ipdr: 'IPDR lookup',
  ai: 'Evidence assistant',
  reports: 'Draft reports and review',
  audit: 'Role Access and audit Log',
};

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  activeCase,
  officer,
  darkMode,
  onToggleDarkMode,
  onOpenMobileNav,
  onNavigateImport,
}) => {
  const canImport = officer?.role === 'investigator' || officer?.role === 'admin';

  return (
    <header className="h-14 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-4 lg:px-6 flex items-center justify-between gap-4 sticky top-0 z-20">
      <div className="flex items-center gap-3 min-w-0">
        <button
          type="button"
          onClick={onOpenMobileNav}
          aria-label="Open navigation menu"
          className="lg:hidden p-2 -ml-1 rounded-md text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <Menu className="w-5 h-5" />
        </button>

        <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-sm min-w-0">
          <span className="font-mono text-xs text-slate-500 dark:text-slate-400 truncate hidden sm:inline">
            {activeCase?.caseNumber || 'No Case'}
          </span>
          <span aria-hidden="true" className="text-slate-300 dark:text-slate-700 hidden sm:inline">
            /
          </span>
          <h1 className="font-display font-semibold text-sm sm:text-base text-slate-900 dark:text-slate-100 truncate">
            {TAB_LABELS[activeTab]}
          </h1>
        </nav>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        <button
          type="button"
          onClick={onToggleDarkMode}
          aria-label={darkMode ? 'Switch to light theme' : 'Switch to dark theme'}
          className="p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
        >
          {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        {activeTab !== 'import' && (
          <button
            type="button"
            onClick={onNavigateImport}
            disabled={!canImport}
            title={
              canImport
                ? 'Import operator CDR, IPDR, or tower dump files'
                : 'Reviewer role is read-only for evidence import'
            }
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-blue-700 hover:bg-blue-800 text-white disabled:opacity-45 disabled:cursor-not-allowed transition-colors whitespace-nowrap shrink-0"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Import evidence</span>
          </button>
        )}
      </div>
    </header>
  );
};
