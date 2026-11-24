# Darpan Reworked

An offline CDR/IPDR investigation workstation for PS03. The React case workspace connects to Darpan's Python/DuckDB evidence engine, local PyTorch intent model, and Fernet-encrypted SQLite station storage.

## Run the synthetic case

Prerequisites are Node.js 24, Bun, and Python with the dependencies below. Run these commands from the repository root.

```sh
bun install --frozen-lockfile
python -m pip install -r backend/requirements.txt
npm run dev
```

Open http://127.0.0.1:3000. The synthetic case runs in memory. Uploaded data in demo mode is cleared on restart. Use only synthetic fixtures for hackathon rehearsal. The assistant runs locally without a cloud API key. Set `DARPAN_PYTHON` to the Python executable if the server needs to use a particular virtual environment.

Try choosing a case subject in Graph explorer, opening a linked source row, and filtering the evidence timeline. In Evidence assistant, ask “Show common contacts for Rohan Mehta and Aman Verma.” The answer cites the original files and rows. The animated portrait is synthetic.

For a production asset build, run `npm run build`. Run `npm run start -- --demo` to serve the built synthetic workspace.

## Run a protected station

Set `DARPAN_REWORKED_HOME` to an OS-restricted vault directory. The default is `.darpan-reworked` in the current home directory. Use the same directory for both account commands and the server. Set `DARPAN_KEY_FILE` before provisioning if you keep the encryption key outside the vault directory. Back up both files separately.

```sh
python backend/app.py --create-account --station PATH_TO_VAULT --username investigator --role investigator
python backend/app.py --create-account --station PATH_TO_VAULT --username reviewer --role reviewer
npm run build
npm run start
```

Omitting `--demo` requires station accounts. Investigators create cases and import evidence. Reviewers can record a verification decision. Both can inspect evidence and export draft reports. The server binds to loopback. Station accounts are local workstation roles and can see the cases in that station.

Imports preserve original bytes and compute SHA-256 on the server. Case records, source originals, findings and audit records are encrypted in the station vault. The tower view uses local coordinates and a local grid. Serving-tower observations are approximate. The browser exports drafts with source references for officer review.

The included Python workstation remains available at `python -m streamlit run backend/app.py --server.address 127.0.0.1 --browser.gatherUsageStats false`. Its case payload format differs from the React workspace. Its bank ledger and evidence-package workflows remain available there. For training the local model checkpoint, run `python backend/app.py --train-models`.

## Source layout

- `src/` contains the React interface, SVG evidence graph, and synthetic portrait asset.
- `server.ts` serves the app and bridges authenticated case work to Python.
- `backend/local_engine.py` exposes local analysis and encrypted case storage to the server.
- `backend/darpan_models.py` contains the PyTorch model definitions and training logic. `backend/darpan-models.json` contains the bundled checkpoint.
- `backend/sample_data/` contains synthetic import fixtures, including separate Jio and Airtel CDR formats and a carrier IPDR sample.

The bundled case data is synthetic. The official R4C dataset is required for operator-format acceptance testing.

## PS03 demo walkthrough

1. **Import and validate.** Start in a new synthetic case. Import the Jio CSV, Airtel TSV and carrier IPDR CSV from `backend/sample_data/`. Review the proposed mapping and check normalized counts and validation issues. Import the tower and suspect CSVs to add map coordinates and named subjects.
2. **Explore the evidence.** In Contact patterns, select a subject to compare call direction, duration, first and last contact, and night activity. In Contact network, select two subjects to compare shared numbers and open a source citation. In Towers and devices, verify the sequence of serving observations and handset or SIM changes. In IPDR lookup, use the supplied IP, port and timestamp to compare sessions and check the supplied service fields.
3. **Question the case.** In the built-in case, try “Which numbers did both suspects contact after midnight?”, “Which number did Rohan Mehta call last?”, “Summarize the case”, and “रोहन मेहता की रात की कॉल दिखाएं।” Open citations, apply suggested filters, and try an out-of-scope question to see the insufficient-evidence response. Hindi input is supported for documented intents. The analytical text may include English and original operator values.
4. **Review and export.** Send a cited observation to officer review. Use protected station mode with an investigator and reviewer account to demonstrate separate permissions and audit records. Export a draft PDF and Excel workbook. The Excel Night Activity sheet contains the complete 00:00–06:00 IST call list with source rows.

## Checks

```sh
npm run lint
npm test
(cd backend && python -B -m unittest discover -s tests -v)
npm run build
```

Design direction follows [unslop by Damir Sokolovsky](https://heydamir.design/unslop), CC BY 4.0.
