import React, { useRef, useState } from 'react';
import * as XLSX from 'xlsx';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  FileSpreadsheet,
  Lock,
  Upload,
} from 'lucide-react';
import type {
  CaseFile,
  DatasetType,
  OfficerSession,
  OperatorPreset,
} from '../types/forensics.ts';
import {
  CDR_CANONICAL_FIELDS,
  computeSha256Hex,
  detectOperatorSchema,
  IPDR_CANONICAL_FIELDS,
  normalizeDatasetRows,
  parseDelimitedText,
  SUSPECT_CANONICAL_FIELDS,
  TOWER_CANONICAL_FIELDS,
  type NormalizationOutput,
} from '../lib/parser.ts';
import { DOWNLOADABLE_SAMPLES } from '../lib/sampleData.ts';

export interface ImportRequest {
  fileName: string;
  original: string;
  datasetType: DatasetType;
  operator: string;
  columnMapping: Record<string, string>;
  observedRole: 'caller' | 'callee';
}

interface ImportViewProps {
  caseFile: CaseFile;
  officer: OfficerSession | null;
  onCommitImport: (request: ImportRequest) => Promise<void>;
}

const OPERATORS: OperatorPreset[] = [
  'Jio 5G',
  'Airtel',
  'Vi',
  'BSNL',
  'Carrier IPDR',
  'Cell Tower Dump',
  'Suspect Registry',
  'Custom',
];

export const ImportView: React.FC<ImportViewProps> = ({
  caseFile,
  officer,
  onCommitImport,
}) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const canImport = officer?.role === 'investigator' || officer?.role === 'admin';

  const [original, setOriginal] = useState<Uint8Array<ArrayBuffer>>(new Uint8Array());
  const [fileName, setFileName] = useState<string>('');
  const [rawContentHash, setRawContentHash] = useState<string>('');
  const [headers, setHeaders] = useState<string[]>([]);
  const [rows, setRows] = useState<Record<string, string>[]>([]);
  const [datasetType, setDatasetType] = useState<DatasetType>('cdr');
  const [operator, setOperator] = useState<string>('Jio 5G');
  const [observedRole, setObservedRole] = useState<'caller' | 'callee'>('caller');
  const [columnMapping, setColumnMapping] = useState<Record<string, string>>({});
  const [previewResult, setPreviewResult] = useState<NormalizationOutput | null>(null);
  const [statusMessage, setStatusMessage] = useState<{
    type: 'success' | 'error';
    text: string;
  } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const activeFields =
    datasetType === 'cdr'
      ? CDR_CANONICAL_FIELDS
      : datasetType === 'ipdr'
        ? IPDR_CANONICAL_FIELDS
        : datasetType === 'towers'
          ? TOWER_CANONICAL_FIELDS
          : SUSPECT_CANONICAL_FIELDS;

  const stageParsedTable = async (
    name: string,
    originalBytes: Uint8Array<ArrayBuffer>,
    parsedHeaders: string[],
    parsedRows: Record<string, string>[]
  ) => {
    setStatusMessage(null);
    const hash = await computeSha256Hex(originalBytes);
    const detected = detectOperatorSchema(parsedHeaders, parsedRows, name);
    setFileName(name);
    setOriginal(originalBytes);
    setRawContentHash(hash);
    setHeaders(parsedHeaders);
    setRows(parsedRows);
    setDatasetType(detected.datasetType);
    setOperator(detected.operator);
    setColumnMapping(detected.suggestedMapping);

    const preview = normalizeDatasetRows({
      sourceId: `src-${Date.now()}`,
      fileName: name,
      datasetType: detected.datasetType,
      operator: detected.operator,
      uploadedBy: officer?.displayName || 'Officer',
      sha256: hash,
      rows: parsedRows,
      columnMapping: detected.suggestedMapping,
      observedFallbackRole: observedRole,
    });
    setPreviewResult(preview);
  };

  const handleFileSelected = async (file: File) => {
    setPreviewResult(null);
    setFileName('');
    setOriginal(new Uint8Array());
    try {
      if (file.size > 10 * 1024 * 1024) throw new Error('Use a source file up to 10 MB.');
      const buffer = await file.arrayBuffer();
      const raw = new Uint8Array(buffer);
      const lower = file.name.toLowerCase();
      if (lower.endsWith('.xlsx') || lower.endsWith('.xls')) {
        const wb = XLSX.read(buffer, { type: 'array' });
        const firstSheet = wb.Sheets[wb.SheetNames[0]];
        const jsonRows = XLSX.utils.sheet_to_json<Record<string, unknown>>(firstSheet, {
          defval: '', blankrows: true,
        });
        const parsedHeaders = jsonRows.length > 0 ? Object.keys(jsonRows[0]).map((h) => h.trim()) : [];
        const stringRows = jsonRows.map((r) => {
          const out: Record<string, string> = {};
          for (const h of parsedHeaders) {
            out[h] = String(Object.entries(r).find(([key]) => key.trim() === h)?.[1] ?? '').trim();
          }
          return out;
        });
        await stageParsedTable(file.name, raw, parsedHeaders, stringRows);
      } else {
        const text = await file.text();
        const parsed = parseDelimitedText(text);
        if (parsed.headers.length === 0) {
          setStatusMessage({ type: 'error', text: 'Selected file appears empty or missing headers.' });
          return;
        }
        await stageParsedTable(file.name, raw, parsed.headers, parsed.rows);
      }
    } catch (err) {
      setStatusMessage({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to read uploaded file.',
      });
    }
  };

  const recomputePreview = (
    nextType: DatasetType,
    nextOp: string,
    nextMap: Record<string, string>,
    nextObs: 'caller' | 'callee'
  ) => {
    if (!fileName || rows.length === 0) return;
    const preview = normalizeDatasetRows({
      sourceId: `src-${Date.now()}`,
      fileName,
      datasetType: nextType,
      operator: nextOp,
      uploadedBy: officer?.displayName || 'Officer',
      sha256: rawContentHash,
      rows,
      columnMapping: nextMap,
      observedFallbackRole: nextObs,
    });
    setPreviewResult(preview);
  };

  const handleCommit = async () => {
    if (!previewResult || !canImport) return;
    if (previewResult.sourceMeta.validRowCount === 0) {
      setStatusMessage({
        type: 'error',
        text: 'Cannot commit import: zero valid rows passed validation. Adjust the column mapping below.',
      });
      return;
    }
    setSubmitting(true);
    setStatusMessage(null);
    try {
      const chunks: string[] = [];
      for (let i = 0; i < original.length; i += 8192) chunks.push(String.fromCharCode(...original.subarray(i, i + 8192)));
      await onCommitImport({ fileName, original: btoa(chunks.join('')), datasetType, operator, columnMapping, observedRole });
      setStatusMessage({
        type: 'success',
        text: `Imported ${previewResult.sourceMeta.fileName}: ${previewResult.sourceMeta.validRowCount} normalized rows added to ${caseFile.caseNumber}.`,
      });
      setFileName('');
      setOriginal(new Uint8Array());
      setHeaders([]);
      setRows([]);
      setPreviewResult(null);
    } catch (err) {
      setStatusMessage({
        type: 'error',
        text: err instanceof Error ? err.message : 'Server rejected evidence import.',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const downloadSample = (sample: (typeof DOWNLOADABLE_SAMPLES)[number]) => {
    const blob = new Blob([sample.content], { type: sample.mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = sample.fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  const stageSampleDirectly = async (sample: (typeof DOWNLOADABLE_SAMPLES)[number]) => {
    const parsed = parseDelimitedText(sample.content);
    await stageParsedTable(sample.fileName, new TextEncoder().encode(sample.content), parsed.headers, parsed.rows);
  };

  return (
    <div className="space-y-6">
      {!canImport && (
        <div
          role="alert"
          className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/60 flex items-start gap-3 text-xs text-amber-900 dark:text-amber-200"
        >
          <Lock className="w-4 h-4 mt-0.5 shrink-0" />
          <div>
            <p className="font-semibold">Evidence Import Restricted for Reviewer Role</p>
            <p className="mt-0.5">
              You are signed in as {officer?.displayName} ({officer?.role}). Only Investigators and
              Administrators can ingest new telecom files into the case vault. Switch role in Access
              &amp; Audit to test uploads.
            </p>
          </div>
        </div>
      )}

      {statusMessage && (
        <div
          role="status"
          className={`p-3.5 rounded-xl border text-xs flex items-center gap-2.5 ${
            statusMessage.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900/60 text-emerald-900 dark:text-emerald-200'
              : 'bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-900/60 text-red-900 dark:text-red-200'
          }`}
        >
          {statusMessage.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 shrink-0" />
          )}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Upload Dropzone & Sample Formats */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <section className="xl:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5">
          <h2 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
            Format-Agnostic CDR / IPDR Ingestion
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 mb-4">
            Upload CSV, TSV, or Excel (.xlsx) records from Jio, Airtel, Vi, BSNL, or carrier CGNAT
            logs. Operator columns and IST date formats are auto-detected and validated row-by-row.
          </p>

          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              if (!canImport) return;
              const f = e.dataTransfer.files?.[0];
              if (f) handleFileSelected(f);
            }}
            className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors ${
              canImport
                ? 'border-slate-300 dark:border-slate-700 hover:border-blue-500 dark:hover:border-blue-500 bg-slate-50/50 dark:bg-slate-800/30'
                : 'border-slate-200 dark:border-slate-800 bg-slate-50/30 opacity-60'
            }`}
          >
            <Upload className="w-7 h-7 mx-auto text-slate-400 mb-2.5" />
            <p className="text-sm font-medium text-slate-800 dark:text-slate-200">
              Drop operator CDR, IPDR, Cell Dump, or Suspect file here
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 mb-4">
              Supports .csv, .tsv, .txt, .xlsx · Computes SHA-256 chain-of-custody digest locally
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,.tsv,.txt,.xlsx,.xls"
              disabled={!canImport}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFileSelected(f);
                e.target.value = '';
              }}
              className="hidden"
            />
            <button
              type="button"
              disabled={!canImport}
              onClick={() => fileInputRef.current?.click()}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-700 hover:bg-blue-800 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Choose Evidence File
            </button>
          </div>
        </section>

        {/* Synthetic Operator Templates */}
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col">
          <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
            Synthetic Operator Test Files
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 mb-3">
            Stage directly into the column mapper or download for offline inspection
          </p>
          <div className="divide-y divide-slate-100 dark:divide-slate-800 flex-1">
            {DOWNLOADABLE_SAMPLES.map((sample) => (
              <div key={sample.fileName} className="py-2.5 flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-xs font-medium text-slate-900 dark:text-slate-100 truncate">
                    {sample.label}
                  </p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                    {sample.description}
                  </p>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    disabled={!canImport}
                    onClick={() => stageSampleDirectly(sample)}
                    className="px-2.5 py-1 rounded-md text-[11px] font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40"
                  >
                    Inspect
                  </button>
                  <button
                    type="button"
                    onClick={() => downloadSample(sample)}
                    aria-label={`Download ${sample.fileName}`}
                    className="p-1.5 rounded-md text-slate-500 hover:text-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Interactive Column Mapping & Validation Stage */}
      {fileName && previewResult && (
        <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-5">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 pb-4 border-b border-slate-200 dark:border-slate-800">
            <div>
              <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
                Column Mapping &amp; Validation — {fileName}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                {rows.length} raw rows · SHA-256 {rawContentHash.slice(0, 20)}...
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  setFileName('');
      setOriginal(new Uint8Array());
                  setPreviewResult(null);
                }}
                className="px-3 py-2 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                Discard
              </button>
              <button
                type="button"
                disabled={submitting || !canImport || previewResult.sourceMeta.validRowCount === 0}
                onClick={handleCommit}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-700 hover:bg-blue-800 text-white disabled:opacity-50"
              >
                {submitting
                  ? 'Normalizing...'
                  : `Commit ${previewResult.sourceMeta.validRowCount} Valid Rows to Case`}
              </button>
            </div>
          </div>

          {/* Schema & Operator Controls */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label
                htmlFor="import-schema-type"
                className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
              >
                Dataset Schema
              </label>
              <select
                id="import-schema-type"
                value={datasetType}
                onChange={(e) => {
                  const nextType = e.target.value as DatasetType;
                  setDatasetType(nextType);
                  const detected = detectOperatorSchema(headers, rows, fileName);
                  const nextMap =
                    nextType === detected.datasetType ? detected.suggestedMapping : {};
                  setColumnMapping(nextMap);
                  recomputePreview(nextType, operator, nextMap, observedRole);
                }}
                className="w-full text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
              >
                <option value="cdr">CDR (Call Detail Records)</option>
                <option value="ipdr">IPDR (CGNAT / IP Session Logs)</option>
                <option value="towers">Cell Tower Location Dump</option>
                <option value="suspects">Suspect Registry (CCTNS)</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="import-operator"
                className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
              >
                Operator / Source Format
              </label>
              <select
                id="import-operator"
                value={operator}
                onChange={(e) => {
                  setOperator(e.target.value);
                  recomputePreview(datasetType, e.target.value, columnMapping, observedRole);
                }}
                className="w-full text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
              >
                {OPERATORS.map((op) => (
                  <option key={op} value={op}>
                    {op}
                  </option>
                ))}
              </select>
            </div>

            {datasetType === 'cdr' && (
              <div>
                <label
                  htmlFor="import-observed-role"
                  className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                >
                  Attach Tower/IMEI Fallback To
                </label>
                <select
                  id="import-observed-role"
                  value={observedRole}
                  onChange={(e) => {
                    const nextObs = e.target.value as 'caller' | 'callee';
                    setObservedRole(nextObs);
                    recomputePreview(datasetType, operator, columnMapping, nextObs);
                  }}
                  className="w-full text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-slate-100"
                >
                  <option value="caller">Caller (A-Number) unless column supplied</option>
                  <option value="callee">Callee (B-Number) unless column supplied</option>
                </select>
              </div>
            )}
          </div>

          {/* Validation Summary */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 text-xs">
            <div>
              <span className="text-slate-500 dark:text-slate-400 block">Valid Normalized</span>
              <span className="font-mono tabular-nums text-base font-semibold text-emerald-700 dark:text-emerald-400">
                {previewResult.sourceMeta.validRowCount}
              </span>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400 block">Rejected Rows</span>
              <span className="font-mono tabular-nums text-base font-semibold text-red-600 dark:text-red-400">
                {previewResult.sourceMeta.rejectedRowCount}
              </span>
            </div>
            <div className="col-span-2">
              <span className="text-slate-500 dark:text-slate-400 block">
                Missing Optional Fields Reported
              </span>
              <span className="font-mono text-xs text-slate-800 dark:text-slate-200">
                {Object.keys(previewResult.sourceMeta.missingFieldCounts).length === 0
                  ? 'None — all key fields populated'
                  : Object.entries(previewResult.sourceMeta.missingFieldCounts)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join(' · ')}
              </span>
            </div>
          </div>

          {/* Column Mapper Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {activeFields.map((field) => (
              <div key={field.key}>
                <label
                  htmlFor={`map-${field.key}`}
                  className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1"
                >
                  {field.label}
                  {field.required && <span className="text-red-600 ml-0.5">*</span>}
                </label>
                <select
                  id={`map-${field.key}`}
                  value={columnMapping[field.key] || ''}
                  onChange={(e) => {
                    const nextMap = { ...columnMapping, [field.key]: e.target.value };
                    if (!e.target.value) delete nextMap[field.key];
                    setColumnMapping(nextMap);
                    recomputePreview(datasetType, operator, nextMap, observedRole);
                  }}
                  className="w-full text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-md px-2.5 py-1.5 text-slate-900 dark:text-slate-100"
                >
                  <option value="">— Unmapped —</option>
                  {headers.map((h) => (
                    <option key={h} value={h}>
                      {h}
                    </option>
                  ))}
                </select>
              </div>
            ))}
          </div>

          {/* Row Diagnostics */}
          {previewResult.issues.length > 0 && (
            <div className="border border-red-200 dark:border-red-900/60 rounded-lg p-3.5 bg-red-50/50 dark:bg-red-950/20">
              <p className="text-xs font-semibold text-red-800 dark:text-red-300 mb-2">
                Validation Issues ({previewResult.issues.length} flagged)
              </p>
              <ul className="space-y-1 text-xs text-red-700 dark:text-red-300 max-h-32 overflow-y-auto font-mono">
                {previewResult.issues.slice(0, 15).map((iss, i) => (
                  <li key={i}>
                    Row {iss.rowNumber} [{iss.field}]: {iss.message}
                    {iss.rawValue ? ` (value="${iss.rawValue}")` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {/* Registered Case Sources Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-white">
              Imported Sources &amp; Chain-of-Custody Manifest
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Every uploaded telecom file is hashed with SHA-256 and tracked with row-level counts
            </p>
          </div>
          <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
            {caseFile.sources.length} files
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400">
                <th className="py-2.5 px-4 font-medium">File Name</th>
                <th className="py-2.5 px-4 font-medium">Type / Operator</th>
                <th className="py-2.5 px-4 font-medium text-right">Valid</th>
                <th className="py-2.5 px-4 font-medium text-right">Rejected</th>
                <th className="py-2.5 px-4 font-medium">Missing Fields</th>
                <th className="py-2.5 px-4 font-medium">SHA-256 Digest</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {caseFile.sources.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No sources imported yet. Upload a file or click Inspect on a synthetic operator file above.
                  </td>
                </tr>
              ) : (
                caseFile.sources.map((src) => (
                  <tr key={src.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40">
                    <td className="py-2.5 px-4 font-medium text-slate-900 dark:text-slate-100">
                      <span className="inline-flex items-center gap-2">
                        <FileSpreadsheet className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        {src.fileName}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-600 dark:text-slate-300">
                      {src.datasetType.toUpperCase()} · {src.operator}
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-emerald-700 dark:text-emerald-400 font-medium">
                      {src.validRowCount}
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-600 dark:text-slate-400">
                      {src.rejectedRowCount}
                    </td>
                    <td className="py-2.5 px-4 text-slate-500 dark:text-slate-400 font-mono text-[11px]">
                      {Object.keys(src.missingFieldCounts).length === 0
                        ? 'None'
                        : Object.entries(src.missingFieldCounts)
                            .map(([k, v]) => `${k}:${v}`)
                            .join(', ')}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      {src.sha256.slice(0, 18)}…
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
