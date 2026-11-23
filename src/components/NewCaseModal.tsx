import React, { useState } from 'react';
import { X } from 'lucide-react';

interface NewCaseModalProps {
  open: boolean;
  onClose: () => void;
  onCreate: (payload: {
    caseNumber: string;
    title: string;
    station: string;
    brief: string;
  }) => Promise<void>;
}

export const NewCaseModal: React.FC<NewCaseModalProps> = ({ open, onClose, onCreate }) => {
  const [caseNumber, setCaseNumber] = useState('');
  const [title, setTitle] = useState('');
  const [station, setStation] = useState('Cyber Crime Police Station, Jaipur');
  const [brief, setBrief] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  if (!open) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseNumber.trim() || !title.trim()) {
      setError('Case number and title are required.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onCreate({ caseNumber, title, station, brief });
      setCaseNumber('');
      setTitle('');
      setBrief('');
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to create case.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Create new investigation case"
    >
      <div
        className="fixed inset-0 bg-slate-950/50 backdrop-blur-[1px]"
        onClick={onClose}
        aria-hidden="true"
      />
      <div className="relative z-10 w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <h2 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
            Create New Investigation Case
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close modal"
            className="p-1.5 rounded-md text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-3.5 text-xs">
          {error && (
            <div className="p-2.5 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 text-red-800 dark:text-red-300">
              {error}
            </div>
          )}

          <div>
            <label htmlFor="new-case-num" className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
              Case / FIR Number <span className="text-red-600">*</span>
            </label>
            <input
              id="new-case-num"
              type="text"
              required
              value={caseNumber}
              onChange={(e) => setCaseNumber(e.target.value)}
              placeholder="e.g. FIR-2026-089"
              className="w-full font-mono bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
            />
          </div>

          <div>
            <label htmlFor="new-case-title" className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
              Case Title <span className="text-red-600">*</span>
            </label>
            <input
              id="new-case-title"
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. UPI Phishing & Mule SIM Network"
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
            />
          </div>

          <div>
            <label htmlFor="new-case-station" className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
              Police Station / Unit
            </label>
            <input
              id="new-case-station"
              type="text"
              value={station}
              onChange={(e) => setStation(e.target.value)}
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
            />
          </div>

          <div>
            <label htmlFor="new-case-brief" className="block font-medium text-slate-700 dark:text-slate-300 mb-1">
              Investigation Brief
            </label>
            <textarea
              id="new-case-brief"
              rows={3}
              value={brief}
              onChange={(e) => setBrief(e.target.value)}
              placeholder="Primary suspect numbers, timeframe, and initial investigative objective..."
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-2 rounded-lg font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 rounded-lg font-semibold bg-blue-700 hover:bg-blue-800 text-white disabled:opacity-50"
            >
              {saving ? 'Creating...' : 'Create Case'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
