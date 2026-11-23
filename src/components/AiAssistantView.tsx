import React, { useState } from 'react';
import {
  AlertCircle,
  BookmarkPlus,
  Bot,
  ExternalLink,
  Filter,
  Send,
  ShieldAlert,
} from 'lucide-react';
import type {
  AiQueryResponse,
  CaseFile,
  EvidenceCitation,
} from '../types/forensics.ts';

interface AiMessage {
  id: string;
  role: 'user' | 'assistant';
  text: string;
  timestamp: string;
  structured?: AiQueryResponse;
  error?: string;
}

interface AiAssistantViewProps {
  caseFile: CaseFile;
  authToken: string;
  onInspectCitation: (citation: EvidenceCitation) => void;
  onPinFinding: (
    title: string,
    summary: string,
    citations: EvidenceCitation[],
    source?: 'ai_assistant' | 'manual_pin'
  ) => void;
  onApplySuggestedFilter: (filter: {
    targetView: 'contacts' | 'network' | 'map' | 'ipdr';
    suspectPhone?: string;
    nightOnly?: boolean;
  }) => void;
  onAuditAppended: (log: unknown) => void;
}

const SAMPLE_PROMPTS = [
  'Show IMEI and SIM changes for Rohan Mehta with exact source rows.',
  'Show common contacts for Rohan Mehta and Aman Verma.',
  'रोहन मेहता की रात की कॉल दिखाएं।',
  'Who did Rohan Mehta call last?',
];

export const AiAssistantView: React.FC<AiAssistantViewProps> = ({
  caseFile,
  authToken,
  onInspectCitation,
  onPinFinding,
  onApplySuggestedFilter,
  onAuditAppended,
}) => {
  const [messages, setMessages] = useState<AiMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      text: `Ask about contacts, device changes or tower observations in ${caseFile.caseNumber}. Include a name or phone number to select a subject. Open a cited row to check the result.`,
      timestamp: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const sendQuestion = async (questionText: string) => {
    const trimmed = questionText.trim();
    if (!trimmed || loading) return;

    const userMsg: AiMessage = {
      id: `u-${Date.now()}`,
      role: 'user',
      text: trimmed,
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await fetch('/api/ai/query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          caseId: caseFile.id,
          question: trimmed,
        }),
      });

      const data = (await res.json()) as {
        result?: AiQueryResponse;
        auditLog?: unknown;
        error?: string;
      };

      if (!res.ok || !data.result) {
        setMessages((prev) => [
          ...prev,
          {
            id: `err-${Date.now()}`,
            role: 'assistant',
            text: trimmed,
            error: data.error || `Request failed with status ${res.status}`,
            timestamp: new Date().toISOString(),
          },
        ]);
      } else {
        if (data.auditLog) onAuditAppended(data.auditLog);
        setMessages((prev) => [
          ...prev,
          {
            id: `a-${Date.now()}`,
            role: 'assistant',
            text: data.result!.answer,
            structured: data.result,
            timestamp: new Date().toISOString(),
          },
        ]);
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          role: 'assistant',
          text: trimmed,
          error:
            err instanceof Error ? err.message : 'Could not reach the local assistant.',
          timestamp: new Date().toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">
      {/* Conversational Thread */}
      <section className="xl:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl flex flex-col min-h-[600px] max-h-[760px]">
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
          <div>
            <h2 className="font-display text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <Bot className="w-4 h-4 text-blue-700 dark:text-blue-400" />
              <span>Evidence assistant</span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Local analysis · Supported questions in English, Hindi and Hinglish
            </p>
          </div>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
            Officer verification required
          </span>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[92%] rounded-xl px-4 py-3 text-xs leading-relaxed space-y-3 ${
                  msg.role === 'user'
                    ? 'bg-blue-700 text-white'
                    : 'bg-slate-50 dark:bg-slate-800/70 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-100'
                }`}
              >
                {msg.error ? (
                  <div className="flex items-start gap-2 text-red-700 dark:text-red-300">
                    <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
                    <div className="space-y-2">
                      <div>
                        <p className="font-semibold">Unable to complete AI analysis</p>
                        <p className="mt-0.5">{msg.error}</p>
                      </div>
                      {msg.text && (
                        <button
                          type="button"
                          disabled={loading}
                          onClick={() => sendQuestion(msg.text)}
                          className="px-2.5 py-1 rounded-md text-[11px] font-semibold bg-white dark:bg-slate-900 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-200 hover:bg-red-50 dark:hover:bg-red-950/40 disabled:opacity-50"
                        >
                          Retry Query
                        </button>
                      )}
                    </div>
                  </div>
                ) : (
                  <>
                    {msg.structured && !msg.structured.dataSupported && (
                      <div className="p-2.5 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900/60 flex items-start gap-2 text-amber-900 dark:text-amber-200">
                        <ShieldAlert className="w-4 h-4 mt-0.5 shrink-0" />
                        <span>
                          <strong>Insufficient Evidence Scope:</strong> Uploaded records do not
                          contain the data required to confirm this claim.
                        </span>
                      </div>
                    )}

                    <div className="whitespace-pre-wrap">{msg.text}</div>

                    {msg.structured?.limitationsNote && (
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 border-t border-slate-200 dark:border-slate-700 pt-2">
                        Scope note: {msg.structured.limitationsNote}
                      </p>
                    )}

                    {/* Clickable Source Citations */}
                    {msg.structured && msg.structured.evidenceCitations.length > 0 && (
                      <div className="border-t border-slate-200 dark:border-slate-700 pt-2.5 space-y-1.5">
                        <p className="text-[11px] font-semibold text-slate-600 dark:text-slate-300">
                          Linked Primary Records ({msg.structured.evidenceCitations.length}) — click
                          to inspect:
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {msg.structured.evidenceCitations.map((c, idx) => (
                            <button
                              key={`${c.sourceFile}-${c.rowNumber}-${idx}`}
                              type="button"
                              onClick={() => onInspectCitation(c)}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 font-mono text-[11px] text-blue-700 dark:text-blue-400 hover:border-blue-500 transition-colors"
                            >
                              <span>
                                {c.sourceFile} · Row {c.rowNumber}
                              </span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Suggested View Filters + Pin for Officer Verification */}
                    {msg.structured && (
                      <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-200 dark:border-slate-700">
                        <div className="flex flex-wrap gap-1.5">
                          {msg.structured.suggestedFilters.map((f, idx) => (
                            <button
                              key={idx}
                              type="button"
                              onClick={() => onApplySuggestedFilter(f)}
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
                            >
                              <Filter className="w-3 h-3" />
                              <span>{f.label}</span>
                            </button>
                          ))}
                        </div>

                        {msg.structured.dataSupported && (
                          <button
                            type="button"
                            onClick={() =>
                              onPinFinding(
                                `AI Observation (${caseFile.caseNumber})`,
                                msg.structured!.answer.slice(0, 320),
                                msg.structured!.evidenceCitations,
                                'ai_assistant'
                              )
                            }
                            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-semibold bg-slate-900 dark:bg-blue-700 text-white hover:opacity-90"
                          >
                            <BookmarkPlus className="w-3 h-3" />
                            <span>Send to Officer Review</span>
                          </button>
                        )}
                      </div>
                    )}

                    {/* Follow-Up Suggestions */}
                    {msg.structured && msg.structured.followUpQuestions.length > 0 && (
                      <div className="pt-1 space-y-1">
                        <p className="text-[11px] text-slate-500 dark:text-slate-400">
                          Suggested follow-up questions:
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {msg.structured.followUpQuestions.map((fq, idx) => (
                            <button
                              key={idx}
                              type="button"
                              onClick={() => sendQuestion(fq)}
                              className="text-left text-[11px] text-blue-700 dark:text-blue-400 hover:underline"
                            >
                              “{fq}”
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex justify-start">
              <div className="px-4 py-3 rounded-xl bg-slate-50 dark:bg-slate-800/70 border border-slate-200 dark:border-slate-700 text-xs text-slate-500 dark:text-slate-400">
                Cross-referencing normalized CDR, IPDR, and cell-tower rows…
              </div>
            </div>
          )}
        </div>

        {/* Input Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            sendQuestion(input);
          }}
          className="p-3.5 border-t border-slate-200 dark:border-slate-800 flex items-center gap-2"
        >
          <label htmlFor="ai-question-input" className="sr-only">
            Ask an investigative question in English, Hindi, or Hinglish
          </label>
          <input
            id="ai-question-input"
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask in English, Hindi (हिन्दी), or Hinglish — e.g. Show Rohan Mehta's IMEI swaps..."
            disabled={loading}
            className="flex-1 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3.5 py-2.5 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-lg text-xs font-semibold bg-blue-700 hover:bg-blue-800 text-white disabled:opacity-50 transition-colors whitespace-nowrap"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Ask</span>
          </button>
        </form>
      </section>

      {/* Right Rail: Sample Prompts & Evidential Guardrails */}
      <aside className="space-y-4">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-3">
          <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
            Suggested Investigative Queries
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Includes English, Hindi, and an out-of-scope test query to verify hallucination guards
          </p>
          <div className="space-y-2">
            {SAMPLE_PROMPTS.map((q, idx) => (
              <button
                key={idx}
                type="button"
                disabled={loading}
                onClick={() => sendQuestion(q)}
                className="w-full text-left p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors disabled:opacity-50"
              >
                {q}
              </button>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2 text-xs">
          <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
            Evidential Accountability Rules
          </h3>
          <ul className="space-y-1.5 text-slate-600 dark:text-slate-300 list-disc pl-4">
            <li>Every claim is cross-validated against loaded source files and row numbers.</li>
            <li>AI observations cannot enter final conclusions until verified by a Senior Reviewer.</li>
            <li>Every natural-language prompt and citation count is recorded in the case Audit Log.</li>
          </ul>
        </div>
      </aside>
    </div>
  );
};
