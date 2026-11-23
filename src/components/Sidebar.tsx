import React from 'react';
import {
  Activity,
  Bot,
  FileSpreadsheet,
  FolderPlus,
  Globe,
  LayoutDashboard,
  MapPin,
  Network,
  ShieldCheck,
  Upload,
  X,
} from 'lucide-react';
import type { CaseFile, OfficerSession } from '../types/forensics.ts';

export type NavTab =
  | 'overview'
  | 'import'
  | 'contacts'
  | 'network'
  | 'map'
  | 'ipdr'
  | 'ai'
  | 'reports'
  | 'audit';

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

const NAV_ITEMS: Array<{
  id: NavTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  group: 'workspace' | 'analysis' | 'governance';
}> = [
  { id: 'overview', label: 'Case overview', icon: LayoutDashboard, group: 'workspace' },
  { id: 'import', label: 'Import evidence', icon: Upload, group: 'workspace' },
  { id: 'contacts', label: 'Contact patterns', icon: Activity, group: 'analysis' },
  { id: 'network', label: 'Contact network', icon: Network, group: 'analysis' },
  { id: 'map', label: 'Towers and devices', icon: MapPin, group: 'analysis' },
  { id: 'ipdr', label: 'IPDR & CGNAT', icon: Globe, group: 'analysis' },
  { id: 'ai', label: 'Evidence assistant', icon: Bot, group: 'analysis' },
  { id: 'reports', label: 'Reports and review', icon: FileSpreadsheet, group: 'governance' },
  { id: 'audit', label: 'Access and audit', icon: ShieldCheck, group: 'governance' },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  cases,
  activeCaseId,
  onSelectCase,
  onOpenNewCase,
  officer,
  pendingReviewCount,
  mobileOpen,
  onCloseMobile,
}) => {
  const canCreateCase = officer?.role === 'investigator' || officer?.role === 'admin';

  const renderGroup = (title: string, group: 'workspace' | 'analysis' | 'governance') => {
    const items = NAV_ITEMS.filter((i) => i.group === group);
    return (
      <div className="space-y-0.5">
        <p className="px-3 pb-1.5 pt-3 text-[11px] font-medium text-slate-400 dark:text-slate-500">
          {title}
        </p>
        {items.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                onSelectTab(item.id);
                onCloseMobile();
              }}
              aria-current={isActive ? 'page' : undefined}
              className={`w-full flex items-center justify-between gap-2 min-h-9 px-3 py-1 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
                isActive
                  ? 'bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-slate-100 dark:hover:bg-slate-800/60'
              }`}
            >
              <span className="flex items-center gap-2 truncate">
                <Icon
                  className={`w-4 h-4 shrink-0 ${
                    isActive
                      ? 'text-blue-700 dark:text-blue-300'
                      : 'text-slate-400 dark:text-slate-500'
                  }`}
                />
                <span className="truncate">{item.label}</span>
              </span>
              {item.id === 'reports' && pendingReviewCount > 0 && (
                <span className="font-mono tabular-nums text-xs font-semibold text-amber-700 dark:text-amber-400">
                  {pendingReviewCount}
                </span>
              )}
            </button>
          );
        })}
      </div>
    );
  };

  const sidebarContent = (
    <div className="flex flex-col h-full bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 w-[252px]">
      {/* Brand Wordmark */}
      <div className="h-14 px-4 flex items-center justify-between border-b border-slate-200 dark:border-slate-800 shrink-0">
        <button
          type="button"
          onClick={() => onSelectTab('overview')}
          className="flex items-center gap-2 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 rounded"
        >
          <span className="w-7 h-7 rounded-md bg-slate-900 dark:bg-blue-600 text-white flex items-center justify-center font-display font-bold text-sm">
            D
          </span>
          <span className="font-display font-bold text-base tracking-tight text-slate-900 dark:text-white whitespace-nowrap">
            Darpan
          </span>
        </button>
        <button
          type="button"
          onClick={onCloseMobile}
          aria-label="Close navigation menu"
          className="lg:hidden p-1.5 rounded-md text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Case Switcher */}
      <div className="p-3 border-b border-slate-200 dark:border-slate-800">
        <label
          htmlFor="case-selector"
          className="block text-[11px] font-medium text-slate-500 dark:text-slate-400 mb-1.5"
        >
          Active case
        </label>
        <div className="flex items-center gap-1.5">
          <select
            id="case-selector"
            value={activeCaseId}
            onChange={(e) => onSelectCase(e.target.value)}
            className="flex-1 min-w-0 text-xs font-medium bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md px-2.5 py-2 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
          >
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.caseNumber} — {c.title}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={onOpenNewCase}
            disabled={!canCreateCase}
            title={canCreateCase ? 'Create new case' : 'Reviewer role cannot create cases'}
            aria-label="Create new case"
            className="p-2 rounded-md border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
          >
            <FolderPlus className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Primary Navigation */}
      <nav aria-label="Investigation sections" className="flex-1 overflow-y-auto px-2.5 pb-4">
        {renderGroup('Case & Evidence', 'workspace')}
        {renderGroup('Forensic Analysis', 'analysis')}
        {renderGroup('Governance', 'governance')}
      </nav>

      {/* Active Officer Identity Footer */}
      {officer && (
        <div className="p-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900/80">
          <button
            type="button"
            onClick={() => {
              onSelectTab('audit');
              onCloseMobile();
            }}
            className="w-full flex items-center gap-2 text-left rounded-md p-1 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <span className="w-8 h-8 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-100 font-display font-semibold text-xs flex items-center justify-center shrink-0">
              {officer.displayName
                .split(' ')
                .slice(-2)
                .map((p) => p[0])
                .join('')
                .toUpperCase()}
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
                {officer.displayName}
              </p>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                {officer.role === 'investigator'
                  ? 'Investigator'
                  : officer.role === 'reviewer'
                    ? 'Senior Reviewer'
                    : 'Administrator'}{' '}
                · <span className="font-mono">{officer.badgeNumber}</span>
              </p>
            </div>
          </button>
        </div>
      )}
    </div>
  );

  return (
    <>
      {/* Desktop rail */}
      <aside className="hidden lg:block shrink-0 h-screen sticky top-0">{sidebarContent}</aside>

      {/* Mobile slide-over drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-slate-950/50 backdrop-blur-[1px]"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <div className="relative z-10 h-full">{sidebarContent}</div>
        </div>
      )}
    </>
  );
};
