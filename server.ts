import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import * as XLSX from 'xlsx';
import type { AiQueryResponse, AuditLogEntry, CaseFile, EvidenceCitation, OfficerSession, VerifiedFinding } from './src/types/forensics.ts';
import { cdrToCitation, ipdrToCitation } from './src/lib/forensics.ts';
import { normalizeDatasetRows, parseDelimitedText } from './src/lib/parser.ts';
import { buildDefaultCasePS03, DOWNLOADABLE_SAMPLES } from './src/lib/sampleData.ts';

const root = path.dirname(fileURLToPath(import.meta.url));
const demo = process.argv.includes('--demo');
const production = process.argv.includes('--production');
const python = process.env.DARPAN_PYTHON || 'python';
const bridge = path.join(root, 'backend/local_engine.py');
const port = Number(process.env.PORT || 3000);
const app = express();

type Workspace = { cases: CaseFile[]; auditLogs: AuditLogEntry[]; originals: Record<string, Record<string, string>> };
type Envelope = { key: string; revision: number; value: Workspace };
type Identity = { username: string; role: 'investigator' | 'reviewer' };
type Finding = { title: string; summary: string; rows: object[]; evidence: object[] };

function unwrap<T>(stdout: string): T {
  const result = JSON.parse(stdout) as { value: T; error?: string };
  if (result.error) throw new Error(result.error);
  return result.value;
}
function station<T>(command: string, data: unknown): T {
  const process = spawnSync(python, ['-B', bridge, command], {
    input: JSON.stringify(data), encoding: 'utf8', timeout: 15000, maxBuffer: 64 * 1024 * 1024,
  });
  if (process.status !== 0) throw new Error('Local station service failed. Check the Python environment.');
  return unwrap<T>(process.stdout);
}
function answerLocally(payload: unknown): Promise<Finding | null> {
  return new Promise((resolve, reject) => {
    const child = spawn(python, ['-B', bridge, 'answer'], { timeout: 30000, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
    let output = '';
    child.on('error', reject);
    child.stdin.on('error', reject);
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => { output += chunk; });
    child.on('close', (code) => {
      if (code !== 0) { reject(new Error('The local assistant did not complete. Verify the Python dependencies.')); return; }
      try { resolve(unwrap<Finding | null>(output)); } catch (error) { reject(error); }
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

const initial: Workspace = { cases: [], auditLogs: [], originals: {} };
if (demo) {
  const sample = buildDefaultCasePS03();
  initial.cases.push(sample);
  initial.originals[sample.id] = {};
  for (const source of sample.sources) {
    const input = DOWNLOADABLE_SAMPLES.find(item => item.fileName === source.fileName);
    if (!input) continue;
    const raw = Buffer.from(input.content, 'utf8');
    source.sha256 = crypto.createHash('sha256').update(raw).digest('hex');
    initial.originals[sample.id][source.id] = raw.toString('base64');
  }
}
let workspace = initial;
let vault: Envelope | undefined;
if (!demo) {
  vault = station<Envelope>('open', initial);
  workspace = vault.value;
}
const sessions = new Map<string, { officer: OfficerSession; expires: number }>();
const viewer = (res: express.Response) => res.locals.officer as OfficerSession;
function session(res: express.Response, identity: Identity) {
  const officer: OfficerSession = { id: identity.username, username: identity.username, displayName: identity.username,
    role: identity.role, badgeNumber: '', unit: demo ? 'Synthetic case' : 'Local station' };
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  for (const [key, value] of sessions) if (value.expires <= now) sessions.delete(key);
  sessions.set(token, { officer, expires: now + 8 * 60 * 60 * 1000 });
  res.json({ token, officer });
}
function auth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const token = req.header('Authorization')?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1] || '';
  const current = sessions.get(token);
  if (!current || current.expires <= Date.now()) { sessions.delete(token); res.status(401).json({ error: 'Sign in to continue.' }); return; }
  res.locals.officer = current.officer;
  res.locals.token = token;
  next();
}
function requireRole(role: Identity['role']) {
  return (_req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (viewer(res).role === role) next();
    else res.status(403).json({ error: 'Your role cannot perform this action.' });
  };
}
function findCase(state: Workspace, id: string): CaseFile {
  const result = state.cases.find(item => item.id === id);
  if (!result) throw Object.assign(new Error('Case not found.'), { status: 404 });
  return result;
}
function commit(actor: OfficerSession, caseId: string, action: AuditLogEntry['action'], detail: string, update?: (state: Workspace) => void) {
  const state = structuredClone(workspace);
  update?.(state);
  const auditLog: AuditLogEntry = { id: crypto.randomUUID(), caseId, action, detail, actor: actor.username,
    role: actor.role, timestamp: new Date().toISOString() };
  state.auditLogs.unshift(auditLog);
  if (vault) {
    try {
      const revision = station<number>('save', { key: vault.key, revision: vault.revision, value: state });
      vault = { ...vault, revision, value: state };
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes('Another session updated')) throw error;
      vault = station<Envelope>('open', initial);
      workspace = vault.value;
      throw Object.assign(new Error('Another station process updated the workspace. Reload and retry.'), { status: 409 });
    }
  }
  workspace = state;
  return auditLog;
}
function citations(c: CaseFile) {
  return [...c.cdrs.map(cdrToCitation), ...c.ipdrs.map(ipdrToCitation)];
}

app.disable('x-powered-by');
app.use('/api', (_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
app.use(express.json({ limit: '24mb' }));
app.get('/api/mode', (_req, res) => { res.json({ demo }); });
app.post('/api/auth/bootstrap-demo', (_req, res) => {
  if (!demo) { res.status(404).end(); return; }
  session(res, { username: 'Sample investigator', role: 'investigator' });
});
app.post('/api/auth/login', (req, res) => {
  if (demo) { res.status(403).json({ error: 'Run the protected workstation to use station accounts.' }); return; }
  const { username, password } = req.body;
  if (typeof username !== 'string' || typeof password !== 'string') { res.status(400).json({ error: 'Enter your account name and password.' }); return; }
  const identity = station<Identity | null>('authenticate', { username, password });
  if (!identity) { res.status(401).json({ error: 'Credentials rejected or sign-in temporarily locked.' }); return; }
  session(res, identity);
});
app.post('/api/auth/logout', auth, (_req, res) => { sessions.delete(res.locals.token); res.status(204).end(); });
app.get('/api/cases', auth, (_req, res) => {
  const actor = viewer(res);
  res.json({ cases: workspace.cases, auditLogs: workspace.auditLogs.filter(row => actor.role === 'reviewer' || row.actor === actor.username) });
});
app.post('/api/cases', auth, requireRole('investigator'), (req, res) => {
  const actor = viewer(res);
  const { caseNumber, title, station: unit, brief } = req.body;
  if (typeof caseNumber !== 'string' || typeof title !== 'string' || !caseNumber.trim() || !title.trim()) {
    res.status(400).json({ error: 'Case number and title are required.' }); return;
  }
  const newCase: CaseFile = { id: crypto.randomUUID(), caseNumber: caseNumber.trim().slice(0, 90), title: title.trim().slice(0, 160),
    station: typeof unit === 'string' ? unit.slice(0, 160) : actor.unit, brief: typeof brief === 'string' ? brief.slice(0, 8000) : '',
    createdAt: new Date().toISOString(), createdBy: actor.username, status: 'Active', sources: [], suspects: [],
    towers: [], cdrs: [], ipdrs: [], findings: [] };
  const auditLog = commit(actor, newCase.id, 'CASE_CREATE', 'Created case ' + newCase.caseNumber, state => state.cases.unshift(newCase));
  res.status(201).json({ caseFile: newCase, auditLog });
});
app.post('/api/cases/:id/import', auth, requireRole('investigator'), (req, res) => {
  const actor = viewer(res);
  const c = findCase(workspace, req.params.id as string);
  const { fileName, original, datasetType, operator, columnMapping, observedRole } = req.body;
  if (typeof original !== 'string' || typeof fileName !== 'string' || !fileName || /[\\/]/.test(fileName) ||
      !['cdr', 'ipdr', 'towers', 'suspects'].includes(datasetType) || typeof operator !== 'string' ||
      !columnMapping || typeof columnMapping !== 'object' || !Object.values(columnMapping).every(x => typeof x === 'string')) {
    res.status(400).json({ error: 'A source file and its mapping are required.' }); return;
  }
  const bytes = Buffer.from(original, 'base64');
  if (!bytes.length || bytes.length > 10 * 1024 * 1024) { res.status(400).json({ error: 'Use a source file up to 10 MB.' }); return; }
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  if (c.sources.some(item => item.sha256 === sha256 || item.fileName === fileName)) {
    res.status(409).json({ error: 'This file or file name is already registered in the case.' }); return;
  }
  let rows: Record<string, string>[];
  try {
    if (/\.xlsx?$/i.test(fileName)) {
      const workbook = XLSX.read(bytes);
      const sheet = workbook.Sheets[workbook.SheetNames[0]];
      rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: '', blankrows: true }).map(row =>
        Object.fromEntries(Object.entries(row).map(([key, value]) => [key.trim(), String(value ?? '').trim()])));
    } else {
      rows = parseDelimitedText(bytes.toString('utf8')).rows;
    }
  } catch {
    res.status(400).json({ error: 'The source could not be parsed.' }); return;
  }
  const result = normalizeDatasetRows({ sourceId: crypto.randomUUID(), fileName, datasetType, operator,
    uploadedBy: actor.username, sha256, rows, columnMapping, observedFallbackRole: observedRole === 'callee' ? 'callee' : 'caller' });
  if (!result.sourceMeta.validRowCount) { res.status(422).json({ error: 'No rows passed the selected mapping.' }); return; }
  const auditLog = commit(actor, c.id, 'EVIDENCE_IMPORT', fileName + ' · SHA-256 ' + sha256, state => {
    const item = findCase(state, c.id);
    item.sources.unshift(result.sourceMeta);
    item.cdrs.push(...result.cdrs); item.ipdrs.push(...result.ipdrs);
    item.towers = [...new Map([...item.towers, ...result.towers].map(t => [t.towerId, t])).values()];
    item.suspects = [...new Map([...item.suspects, ...result.suspects].map(s => [s.phone, s])).values()];
    (state.originals[c.id] ||= {})[result.sourceMeta.id] = original;
  });
  res.json({ caseFile: findCase(workspace, c.id), auditLog });
});
app.get('/api/cases/:id/sources/:sourceId/original', auth, (req, res) => {
  const c = findCase(workspace, req.params.id as string);
  const source = c.sources.find(item => item.id === req.params.sourceId);
  const content = source && workspace.originals[c.id]?.[source.id];
  if (!source || !content) { res.status(404).json({ error: 'Original bytes are unavailable.' }); return; }
  commit(viewer(res), c.id, 'EVIDENCE_VIEW', 'Downloaded original ' + source.fileName);
  res.attachment(source.fileName).type('application/octet-stream').send(Buffer.from(content, 'base64'));
});
app.post('/api/cases/:id/findings', auth, (req, res) => {
  const actor = viewer(res);
  const c = findCase(workspace, req.params.id as string);
  const { title, summary, citations: proposed, source } = req.body;
  if (typeof title !== 'string' || typeof summary !== 'string' || !title.trim() || !summary.trim()) {
    res.status(400).json({ error: 'A title and summary are required.' }); return;
  }
  const keys = new Set<string>(Array.isArray(proposed) ? proposed.map((cite: EvidenceCitation) => cite.recordId) : []);
  const finding: VerifiedFinding = { id: crypto.randomUUID(), caseId: c.id, title: title.slice(0, 200), summary: summary.slice(0, 8000),
    source: source === 'ai_assistant' ? source : 'manual_pin', status: 'pending_review', createdBy: actor.username,
    createdAt: new Date().toISOString(), citations: citations(c).filter(cite => keys.has(cite.recordId)) };
  const auditLog = commit(actor, c.id, 'FINDING_PIN', finding.title, state => findCase(state, c.id).findings.unshift(finding));
  res.status(201).json({ finding, auditLog });
});
app.patch('/api/cases/:id/findings/:findingId', auth, requireRole('reviewer'), (req, res) => {
  const actor = viewer(res);
  const c = findCase(workspace, req.params.id as string);
  const previous = c.findings.find(f => f.id === req.params.findingId);
  if (!previous) { res.status(404).json({ error: 'Finding not found.' }); return; }
  const { status, reviewerNote } = req.body;
  if (status !== 'verified' && status !== 'rejected') { res.status(400).json({ error: 'Select a verification decision.' }); return; }
  const finding = { ...previous, status, reviewerNote: typeof reviewerNote === 'string' ? reviewerNote.slice(0, 1000) : '',
    reviewedBy: actor.username, reviewedAt: new Date().toISOString() };
  const auditLog = commit(actor, c.id, 'FINDING_VERIFY', finding.title + ' · ' + status, state => {
    const item = findCase(state, c.id);
    item.findings = item.findings.map(f => f.id === finding.id ? finding : f);
  });
  res.json({ finding, auditLog });
});
app.post('/api/audit', auth, (req, res) => {
  const { caseId, action, detail } = req.body;
  findCase(workspace, caseId);
  if (!['IPDR_LOOKUP', 'REPORT_EXPORT', 'EVIDENCE_VIEW'].includes(action) || typeof detail !== 'string') {
    res.status(400).json({ error: 'Invalid audit action.' }); return;
  }
  res.json({ auditLog: commit(viewer(res), caseId, action, detail.slice(0, 1200)) });
});
app.post('/api/ai/query', auth, async (req, res, next) => {
  try {
    const { caseId, question, active, compare } = req.body;
    if (typeof question !== 'string' || !question.trim() || question.length > 550) { res.status(400).json({ error: 'Enter a question up to 550 characters.' }); return; }
    const c = findCase(workspace, caseId);
    const finding = await answerLocally({ caseFile: c, question: question.trim(), demo, active, compare });
    const supportText = finding ? [finding.summary, ...finding.evidence.flatMap(row => Object.values(row)), ...finding.rows.flatMap(row => Object.values(row))].join('\n') : '';
    const matching = citations(c).filter(cite => supportText.includes(cite.sourceFile + ' Row #' + cite.rowNumber + ' · SHA-256'));
    const result: AiQueryResponse = { answer: matching.length ? finding!.summary : finding ? finding.summary : 'The supplied records do not support that question. Try a contact, a time window, tower visits or device changes.',
      dataSupported: matching.length > 0, language: /[\u0900-\u097f]/.test(question) ? 'hi' : 'en', evidenceCitations: matching.slice(0, 30),
      suggestedFilters: [], followUpQuestions: [], modelUsed: 'Local intent model + evidence rules' };
    const auditLog = commit(viewer(res), c.id, 'AI_QUERY', question.trim() + ' · ' + matching.length + ' source rows');
    res.json({ result, auditLog });
  } catch (error) { next(error); }
});
app.use('/api', (_req, res) => { res.status(404).json({ error: 'Unknown endpoint.' }); });

if (production) {
  const dist = path.join(root, 'dist');
  app.use(express.static(dist));
  app.get('*', (_req, res) => { res.sendFile(path.join(dist, 'index.html')); });
} else {
  const vite = await createViteServer({ root, server: { middlewareMode: true, hmr: false }, appType: 'spa' });
  app.use(vite.middlewares);
}
app.use((error: Error & { status?: number }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  res.status(error.status || 500).json({ error: error.status ? error.message : 'The local workstation could not complete the request.' });
});
app.listen(port, '127.0.0.1', () => console.log('Darpan at http://127.0.0.1:' + port + (demo ? ' (synthetic mode)' : '')));
