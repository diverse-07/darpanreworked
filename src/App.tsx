import { useCallback, useEffect, useMemo, useState } from 'react';
import type {
  AuditLogEntry,
  CaseFile,
  EvidenceCitation,
  OfficerSession,
  VerifiedFinding,
} from './types/forensics.ts';
import type { ImportRequest } from './components/ImportView.tsx';
import { Sidebar, type NavTab } from './components/Sidebar.tsx';
import { TopBar } from './components/TopBar.tsx';
import { OverviewView } from './components/OverviewView.tsx';
import { ImportView } from './components/ImportView.tsx';
import { ContactAnalysisView } from './components/ContactAnalysisView.tsx';
import { NetworkCorrelationView } from './components/NetworkCorrelationView.tsx';
import { TowerDevicesView } from './components/TowerDevicesView.tsx';
import { IpdrLookupView } from './components/IpdrLookupView.tsx';
import { AiAssistantView } from './components/AiAssistantView.tsx';
import { ReportsView } from './components/ReportsView.tsx';
import { AccessAuditView } from './components/AccessAuditView.tsx';
import { EvidenceDrawer } from './components/EvidenceDrawer.tsx';
import { NewCaseModal } from './components/NewCaseModal.tsx';

export default function App() {
  const [authToken, setAuthToken] = useState<string>('');
  const [officer, setOfficer] = useState<OfficerSession | null>(null);
  const [demo, setDemo] = useState(false);
  const [loginError, setLoginError] = useState('');
  const [cases, setCases] = useState<CaseFile[]>([]);
  const [activeCaseId, setActiveCaseId] = useState<string>('');
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [darkMode, setDarkMode] = useState(true);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [newCaseOpen, setNewCaseOpen] = useState(false);
  const [inspectedCitation, setInspectedCitation] = useState<EvidenceCitation | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  // Deep-link filter state from AI Assistant suggested actions
  const [viewPreset, setViewPreset] = useState<{
    suspectPhone?: string;
    nightOnly?: boolean;
  }>({});

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    window.setTimeout(() => {
      setToast((prev) => (prev === msg ? null : prev));
    }, 3600);
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    if (darkMode) root.classList.add('dark');
    else root.classList.remove('dark');
  }, [darkMode]);

  const fetchWorkspace = useCallback(async (token: string) => {
    const response = await fetch('/api/cases', { headers: { Authorization: 'Bearer ' + token } });
    if (!response.ok) throw new Error('Unable to open the case workspace.');
    const casesJson = (await response.json()) as { cases: CaseFile[]; auditLogs: AuditLogEntry[] };
    setCases(casesJson.cases);
    setAuditLogs(casesJson.auditLogs);
    setActiveCaseId((prev) =>
      prev && casesJson.cases.some((c) => c.id === prev)
        ? prev
        : casesJson.cases[0]?.id || ''
    );
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const mode = await fetch('/api/mode');
        if (!mode.ok) throw new Error('Unable to connect to the workstation.');
        const settings = await mode.json();
        if (!settings.demo || cancelled) return;
        setDemo(true);
        const res = await fetch('/api/auth/bootstrap-demo', { method: 'POST' });
        if (!res.ok) throw new Error('Unable to initialize workstation session.');
        const data = (await res.json()) as { token: string; officer: OfficerSession };
        if (cancelled) return;
        setAuthToken(data.token);
        setOfficer(data.officer);
        await fetchWorkspace(data.token);
      } catch (err) {
        if (!cancelled) {
          setLoadError(err instanceof Error ? err.message : 'Failed to connect to Darpan server.');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [fetchWorkspace]);

  const activeCase = useMemo(
    () => cases.find((c) => c.id === activeCaseId) || cases[0] || null,
    [cases, activeCaseId]
  );

  const pendingReviewCount = useMemo(
    () => activeCase?.findings.filter((f) => f.status === 'pending_review').length || 0,
    [activeCase]
  );

  const handleCommitImport = async (output: ImportRequest) => {
    if (!activeCase) return;
    const res = await fetch(`/api/cases/${activeCase.id}/import`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify(output),
    });
    const data = (await res.json()) as {
      caseFile?: CaseFile;
      auditLog?: AuditLogEntry;
      error?: string;
    };
    if (!res.ok || !data.caseFile) {
      throw new Error(data.error || 'Import rejected by server.');
    }
    setCases((prev) => prev.map((c) => (c.id === data.caseFile!.id ? data.caseFile! : c)));
    if (data.auditLog) setAuditLogs((prev) => [data.auditLog!, ...prev]);
    showToast(`Imported ${output.fileName}`);
  };

  const handleCreateCase = async (payload: {
    caseNumber: string;
    title: string;
    station: string;
    brief: string;
  }) => {
    const res = await fetch('/api/cases', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify(payload),
    });
    const data = (await res.json()) as {
      caseFile?: CaseFile;
      auditLog?: AuditLogEntry;
      error?: string;
    };
    if (!res.ok || !data.caseFile) {
      throw new Error(data.error || 'Failed to create case.');
    }
    setCases((prev) => [data.caseFile!, ...prev]);
    setActiveCaseId(data.caseFile.id);
    if (data.auditLog) setAuditLogs((prev) => [data.auditLog!, ...prev]);
    setActiveTab('import');
    showToast(`Created case ${data.caseFile.caseNumber}`);
  };

  const handlePinFinding = async (
    title: string,
    summary: string,
    citations: EvidenceCitation[],
    source: 'ai_assistant' | 'manual_pin' = 'manual_pin'
  ) => {
    if (!activeCase) return;
    const res = await fetch(`/api/cases/${activeCase.id}/findings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ title, summary, source, citations }),
    });
    const data = (await res.json()) as {
      finding?: VerifiedFinding;
      auditLog?: AuditLogEntry;
      error?: string;
    };
    if (!res.ok || !data.finding) {
      showToast(data.error || 'Unable to pin finding.');
      return;
    }
    setCases((prev) =>
      prev.map((c) =>
        c.id === activeCase.id
          ? { ...c, findings: [data.finding!, ...c.findings] }
          : c
      )
    );
    if (data.auditLog) setAuditLogs((prev) => [data.auditLog!, ...prev]);
    showToast('Finding added to Officer Verification Queue.');
  };

  const handleReviewFinding = async (
    findingId: string,
    status: 'verified' | 'rejected',
    reviewerNote: string
  ) => {
    if (!activeCase) return;
    const res = await fetch(`/api/cases/${activeCase.id}/findings/${findingId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ status, reviewerNote }),
    });
    const data = (await res.json()) as {
      finding?: VerifiedFinding;
      auditLog?: AuditLogEntry;
      error?: string;
    };
    if (!res.ok || !data.finding) {
      showToast(data.error || 'Verification update failed.');
      return;
    }
    setCases((prev) =>
      prev.map((c) =>
        c.id === activeCase.id
          ? {
              ...c,
              findings: c.findings.map((f) => (f.id === findingId ? data.finding! : f)),
            }
          : c
      )
    );
    if (data.auditLog) setAuditLogs((prev) => [data.auditLog!, ...prev]);
    showToast(`Finding marked ${status.toUpperCase()}.`);
  };

  const handleLogClientAction = async (
    action: 'IPDR_LOOKUP' | 'REPORT_EXPORT' | 'EVIDENCE_VIEW',
    detail: string
  ) => {
    if (!activeCase || !authToken) return;
    try {
      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({ caseId: activeCase.id, action, detail }),
      });
      if (res.ok) {
        const data = (await res.json()) as { auditLog?: AuditLogEntry };
        if (data.auditLog) setAuditLogs((prev) => [data.auditLog!, ...prev]);
      }
    } catch {
      // Non-blocking audit ping
    }
  };

  const handleLogin = async (username: string, password: string) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = (await res.json()) as {
      token?: string;
      officer?: OfficerSession;
      error?: string;
    };
    if (!res.ok || !data.token || !data.officer) {
      throw new Error(data.error || 'Authentication failed.');
    }
    setAuthToken(data.token);
    setOfficer(data.officer);
    await fetchWorkspace(data.token);
  };

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST', headers: { Authorization: 'Bearer ' + authToken } });
    setAuthToken('');
    setOfficer(null);
    setCases([]);
    setInspectedCitation(null);
    setActiveTab('overview');
    if (demo) window.location.reload();
  };

  const inspectEvidence = (cite: EvidenceCitation | null) => {
    setInspectedCitation(cite);
    if (cite) void handleLogClientAction('EVIDENCE_VIEW', cite.sourceFile + ' / row ' + cite.rowNumber);
  };
  const downloadOriginal = async (id: string, name: string) => {
    if (!activeCase) return;
    const url = '/api/cases/' + encodeURIComponent(activeCase.id) + '/sources/' + encodeURIComponent(id) + '/original';
    const response = await fetch(url, { headers: { Authorization: 'Bearer ' + authToken } });
    if (!response.ok) { showToast('Original file unavailable.'); return; }
    const temporaryUrl = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    link.href = temporaryUrl;
    link.download = name;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(temporaryUrl), 1000);
    await fetchWorkspace(authToken);
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 text-sm text-slate-600 dark:text-slate-300">
        Loading Darpan Forensics workstation…
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 p-6">
        <div className="max-w-md w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 space-y-3 text-center">
          <h1 className="font-display text-lg font-bold text-slate-900 dark:text-white">
            Darpan Forensics
          </h1>
          <p className="text-xs text-red-700 dark:text-red-400">
            {loadError}
          </p>
        </div>
      </div>
    );
  }

  if (!officer) return (
    <div className="station-entry">
      <form className="station-form" onSubmit={async event => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        setLoginError('');
        try { await handleLogin(String(data.get('username')), String(data.get('password'))); }
        catch (error) { setLoginError(error instanceof Error ? error.message : 'Sign-in failed.'); }
      }}>
        <h1>Darpan</h1><p>Telecom evidence workstation</p>
        <label>Station account<input name="username" autoComplete="username" required /></label>
        <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
        <button type="submit">Sign in</button>
        {loginError && <p role="alert">{loginError}</p>}
      </form>
    </div>
  );

  if (!activeCase) return (
    <div className="station-entry">
      <section className="station-form">
        <h1>Your case workspace</h1><p>Cases created on this station appear here.</p>
        {officer.role === 'investigator' && <button onClick={() => setNewCaseOpen(true)}>Create a case</button>}
        <button onClick={handleLogout}>Sign out</button>
      </section>
      <NewCaseModal open={newCaseOpen} onClose={() => setNewCaseOpen(false)} onCreate={handleCreateCase} />
    </div>
  );

  return (
    <div className="workstation min-h-screen flex bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        cases={cases}
        activeCaseId={activeCase.id}
        onSelectCase={(id) => {
          setActiveCaseId(id);
          setViewPreset({});
        }}
        onOpenNewCase={() => setNewCaseOpen(true)}
        officer={officer}
        pendingReviewCount={pendingReviewCount}
        mobileOpen={mobileNavOpen}
        onCloseMobile={() => setMobileNavOpen(false)}
      />

      <div className="flex-1 min-w-0 flex flex-col">
        <TopBar
          activeTab={activeTab}
          activeCase={activeCase}
          officer={officer}
          darkMode={darkMode}
          onToggleDarkMode={() => setDarkMode((d) => !d)}
          onOpenMobileNav={() => setMobileNavOpen(true)}
          onNavigateImport={() => setActiveTab('import')}
        />

        <main key={activeTab} className="workspace-view flex-1 p-4 lg:p-8 max-w-[1520px] w-full mx-auto">
          {activeTab === 'overview' && (
            <OverviewView
              caseFile={activeCase}
              onNavigate={setActiveTab}
              onInspectCitation={inspectEvidence}
            />
          )}

          {activeTab === 'import' && (
            <ImportView
              key={activeCase.id}
              caseFile={activeCase}
              officer={officer}
              onCommitImport={handleCommitImport}
            />
          )}

          {activeTab === 'contacts' && (
            <ContactAnalysisView
              key={`${activeCase.id}-${viewPreset.suspectPhone || ''}-${String(viewPreset.nightOnly)}`}
              caseFile={activeCase}
              initialSuspectPhone={viewPreset.suspectPhone}
              initialNightOnly={viewPreset.nightOnly}
              onInspectCitation={inspectEvidence}
            />
          )}

          {activeTab === 'network' && (
            <NetworkCorrelationView
              key={activeCase.id}
              caseFile={activeCase}
              onInspectCitation={inspectEvidence}
            />
          )}

          {activeTab === 'map' && (
            <TowerDevicesView
              key={`${activeCase.id}-${viewPreset.suspectPhone || ''}`}
              caseFile={activeCase}
              initialSuspectPhone={viewPreset.suspectPhone}
              onInspectCitation={inspectEvidence}
            />
          )}

          {activeTab === 'ipdr' && (
            <IpdrLookupView
              caseFile={activeCase}
              onInspectCitation={inspectEvidence}
              onPinFinding={(title, summary, citations) =>
                handlePinFinding(title, summary, citations, 'manual_pin')
              }
              onLogIpdrLookup={(detail) => handleLogClientAction('IPDR_LOOKUP', detail)}
            />
          )}

          {activeTab === 'ai' && (
            <AiAssistantView
              key={activeCase.id}
              caseFile={activeCase}
              authToken={authToken}
              onInspectCitation={inspectEvidence}
              onPinFinding={handlePinFinding}
              onApplySuggestedFilter={(f) => {
                setViewPreset({ suspectPhone: f.suspectPhone, nightOnly: f.nightOnly });
                setActiveTab(f.targetView);
              }}
              onAuditAppended={(log) =>
                setAuditLogs((prev) => [log as AuditLogEntry, ...prev])
              }
            />
          )}

          {activeTab === 'reports' && (
            <ReportsView
              caseFile={activeCase}
              officer={officer}
              auditLogs={auditLogs}
              onInspectCitation={inspectEvidence}
              onReviewFinding={handleReviewFinding}
              onLogReportExport={(detail) => handleLogClientAction('REPORT_EXPORT', detail)}
            />
          )}

          {activeTab === 'audit' && (
            <AccessAuditView
              officer={officer}
              demo={demo}
              auditLogs={auditLogs}
              onLogout={handleLogout}
            />
          )}
        </main>
      </div>

      {/* Primary Evidence Inspector Drawer */}
      <EvidenceDrawer
        citation={inspectedCitation}
        activeCase={activeCase}
        onClose={() => setInspectedCitation(null)}
        onDownloadOriginal={downloadOriginal}
        onPinFinding={(title, summary, citations) =>
          handlePinFinding(title, summary, citations, 'manual_pin')
        }
      />

      {/* New Case Dialog */}
      <NewCaseModal
        open={newCaseOpen}
        onClose={() => setNewCaseOpen(false)}
        onCreate={handleCreateCase}
      />

      {/* Subtle Feedback Toast */}
      {toast && (
        <div
          role="status"
          aria-live="polite"
          className="fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 text-xs font-medium shadow-lg"
        >
          {toast}
        </div>
      )}
    </div>
  );
}
