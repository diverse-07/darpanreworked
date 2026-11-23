# Darpan Reworked

An offline PS03 telecom evidence workstation. This edition combines the React investigation interface from darpan2 with Darpan’s Python/DuckDB evidence engine, local PyTorch intent model, and Fernet-encrypted SQLite station storage. The UI uses a graphite palette with amber emphasis on case selection and audit evidence.

## Run the synthetic case

Prerequisites are Node.js 24, Bun, and a Python environment with the dependencies below.

```sh
bun install --frozen-lockfile
python -m pip install -r backend/requirements.txt
npm run dev
```

Open http://127.0.0.1:3000. The synthetic case runs in memory. Uploaded data in demo mode is cleared on restart. Use only synthetic fixtures for hackathon rehearsal. The assistant runs locally and no cloud API key is needed.

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

The bundled case data is synthetic. The official R4C dataset is required for operator-format acceptance testing.

## Checks

```sh
npm run lint
npm test
(cd backend && python -B -m unittest discover -s tests -v)
npm run build
```

Design direction follows [unslop by Damir Sokolovsky](https://heydamir.design/unslop), CC BY 4.0.
