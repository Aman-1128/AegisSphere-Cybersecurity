# AegisSphere (AG Spare)

AegisSphere is an existing React/Vite and FastAPI security analysis project. It applies the included scikit-learn Random Forest model to CICIDS2017-style flow CSVs, runs four analysis agents, and tracks incidents and analyst response decisions in SQLite.

## Audit of the supplied project

- **Already present:** React 19/Vite dashboard; FastAPI upload and prediction APIs; CICIDS2017 datasets; saved Random Forest artifact and feature list; log analysis, threat detection, threat intelligence, and response recommendation modules.
- **Partly complete:** the four-agent pipeline and dashboard result views existed, as did a response proposal UI. Those response controls only changed in-memory UI state, the dashboard had no real operations APIs, and the API returned “executed” for simulated actions.
- **Missing:** persisted incidents, action decisions and audit history; incident status management; dashboard summary API; install/run instructions at the project root; upload limits and consistent validation.
- **Fixed/completed:** added SQLite-backed incidents and response actions, audit events, dashboard statistics, incident form/status controls, persisted action history, guarded CSV inputs, explicit simulation-only response approvals, input validation, logging, requirements, and documentation. Preserved the existing model and API routes, including a compatibility `/response-action` route.
- **Remaining improvements:** authentication and role-based access, external threat-intelligence feeds, live packet capture, real containment integrations, and deployment hardening are outside this local demo scope. No real response control is connected.

## Requirements

- Windows, macOS, or Linux
- Python 3.13 (the supplied model environment was Python 3.13)
- Node.js 20.19+ or 22.12+ (Vite 8 requirement)
- Network access for dependency installation

## Install

From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cd frontend
npm ci
```

If PowerShell blocks activation, run the interpreter directly as `..\.venv\Scripts\python.exe` from `frontend`, or use the equivalent `bin/activate` path on macOS/Linux.

## Run locally

Terminal 1, from the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Terminal 2:

```powershell
cd frontend
npm run dev
```

Open <http://localhost:5173>. API documentation is available at <http://127.0.0.1:8000/docs>; health is at `/health`. SQLite state is created at `data/aegisphere.db` on first API startup. Keep this file to retain incidents and history. Set `AEGISPHERE_DB_PATH` before starting the API to store the database elsewhere.

## Use

1. Upload a CSV. `/agent-analysis` requires every feature listed in `ml/models/feature_names.txt`, using the CICIDS2017 flow feature names and numeric values. `datasets/test_prediction.csv` is a ready-to-use sample.
2. Review model classifications, severity, agent findings, and proposed actions.
3. Each detected attack creates an `OPEN` incident and a `PENDING` response proposal. The API caps automatic incident creation at 500 per analysis and reports any omitted count.
4. Choose **Investigate**, **Approve**, or **Reject**. Decisions and status changes are written to the audit log. Approval records `APPROVED_SIMULATED` only; it does not block, isolate, or modify any real system.
5. Create manual incidents in the Incident Management section and update their lifecycle status there.

## API overview

- `GET /health`, `GET /dashboard/stats`
- `POST /upload-log`, `POST /predict`, `POST /threat-intelligence`, `POST /agent-analysis` (multipart field `file`)
- `POST /incidents`, `GET /incidents`, `GET /incidents/{id}`, `PATCH /incidents/{id}/status`
- `POST /incidents/{id}/actions/{action_id}/decision`, `GET /action-history`
- `POST /response-action` remains as a compatibility route and only resolves a persisted proposal.

Uploads are limited to 50 MiB and 100,000 rows. A `400` response describes invalid CSVs or missing model features; `413` means an upload limit was exceeded. The service does not connect to external intelligence feeds or perform live network collection.

## Verification

The checked-in project was reviewed against its routes, feature list, model artifact, agents, data files, and frontend. Runtime verification results and any environment constraints are recorded in `documentation/TESTING_REPORT.md` after the implementation checks.
