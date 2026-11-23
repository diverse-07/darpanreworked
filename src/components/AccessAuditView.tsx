import type { AuditLogEntry, OfficerSession } from '../types/forensics.ts';

const format = new Intl.DateTimeFormat('en-IN', {
  timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'short',
});

export function AccessAuditView({ officer, auditLogs, demo, onLogout }: {
  officer: OfficerSession | null;
  auditLogs: AuditLogEntry[];
  demo: boolean;
  onLogout: () => Promise<void>;
}) {
  return (
    <div className="space-y-6">
      <section className="case-brief p-6">
        <h2 className="text-2xl">Station access</h2>
        <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
          {officer?.displayName} · {officer?.role} · {demo ? 'Synthetic session' : 'Protected local station'}
        </p>
        {!demo && <button type="button" onClick={() => void onLogout()} className="mt-4 rounded-lg border border-slate-600 px-4 py-2 text-sm">Sign out</button>}
      </section>
      <section className="rounded-lg border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
        <h2 className="text-lg mb-4">Activity log</h2>
        {auditLogs.length === 0 ? <p className="text-sm text-slate-500">No activity recorded yet</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead><tr><th scope="col">Time (IST)</th><th scope="col">Account</th><th scope="col">Activity</th><th scope="col">Details</th></tr></thead>
              <tbody>{auditLogs.map(entry => (
                <tr key={entry.id}>
                  <td className="whitespace-nowrap font-mono">{format.format(new Date(entry.timestamp))}</td>
                  <td>{entry.actor}</td>
                  <td>{entry.action.toLowerCase().replaceAll('_', ' ')}</td>
                  <td className="break-words">{entry.detail}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
