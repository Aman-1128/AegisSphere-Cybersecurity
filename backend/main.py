"""AegisSphere API: ML analysis, incident tracking, and approval-gated simulation."""

from __future__ import annotations

import io
import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ml.agents.orchestrator import run_security_pipeline
from ml.agents.threat_intelligence import analyze_threats

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "ml" / "models" / "threat_detector.pkl"
FEATURES_PATH = BASE_DIR / "ml" / "models" / "feature_names.txt"
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("AEGISPHERE_DB_PATH", DATA_DIR / "aegisphere.db")).resolve()
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_ROWS = 100_000
MAX_INCIDENTS_PER_ANALYSIS = 500
logger = logging.getLogger("aegisphere")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

if not MODEL_PATH.is_file() or not FEATURES_PATH.is_file():
    raise RuntimeError(f"Model assets not found: expected {MODEL_PATH} and {FEATURES_PATH}")
model = joblib.load(MODEL_PATH)
with FEATURES_PATH.open("r", encoding="utf-8") as feature_file:
    FEATURE_NAMES = [line.strip() for line in feature_file if line.strip()]
if not FEATURE_NAMES:
    raise RuntimeError("The model feature list is empty")

app = FastAPI(
    title="AegisSphere",
    description="Machine learning network analysis, security incidents, and analyst-approved response simulations.",
    version="2.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def database():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_database() -> None:
    with database() as connection:
        connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'LOW',
                status TEXT NOT NULL DEFAULT 'OPEN',
                source TEXT NOT NULL DEFAULT 'analyst',
                log_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                log_id INTEGER,
                action TEXT NOT NULL,
                recommendation TEXT NOT NULL DEFAULT '',
                priority TEXT NOT NULL DEFAULT 'NORMAL',
                status TEXT NOT NULL DEFAULT 'PENDING',
                decision TEXT NOT NULL DEFAULT 'PENDING',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                action_id INTEGER,
                event TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                total_logs INTEGER NOT NULL,
                attack_count INTEGER NOT NULL,
                benign_count INTEGER NOT NULL,
                overall_severity TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


@app.on_event("startup")
def startup() -> None:
    init_database()


def audit(connection: sqlite3.Connection, event: str, details: dict[str, Any], incident_id: int | None = None, action_id: int | None = None) -> None:
    connection.execute(
        "INSERT INTO audit_logs(incident_id, action_id, event, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (incident_id, action_id, event, json.dumps(details, ensure_ascii=False), now_iso()),
    )


def row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


def read_csv_upload(contents: bytes, filename: str | None) -> pd.DataFrame:
    if not contents:
        raise HTTPException(status_code=400, detail="The uploaded CSV is empty.")
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="CSV uploads are limited to 50 MB.")
    if filename and Path(filename).suffix.lower() != ".csv":
        raise HTTPException(status_code=400, detail="Upload a .csv file.")
    try:
        frame = pd.read_csv(io.BytesIO(contents), low_memory=False)
    except (UnicodeDecodeError, pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="The file could not be parsed as a CSV.") from exc
    frame.columns = frame.columns.astype(str).str.strip()
    if frame.empty:
        raise HTTPException(status_code=400, detail="The CSV contains no data rows.")
    if len(frame) > MAX_ROWS:
        raise HTTPException(status_code=413, detail=f"CSV uploads are limited to {MAX_ROWS:,} rows.")
    if frame.columns.duplicated().any():
        raise HTTPException(status_code=400, detail="The CSV contains duplicate column names after trimming spaces.")
    return frame


def generate_response_action(response_data: dict[str, Any] | None) -> dict[str, Any]:
    """Turn recommendations into simulation proposals; never execute host controls."""
    responses = (response_data or {}).get("responses", [])
    actions = []
    for response in responses:
        recommendation = str(response.get("recommended_action", "")).lower()
        if "block" in recommendation or "restrict" in recommendation:
            action = "BLOCK_SOURCE"
        elif "isolate" in recommendation:
            action = "ISOLATE_HOST"
        elif "monitor" in recommendation:
            action = "MONITOR_ACTIVITY"
        elif "alert" in recommendation:
            action = "GENERATE_ALERT"
        else:
            action = "INVESTIGATE_THREAT"
        actions.append({
            "log_id": response.get("log_id"),
            "threat_type": response.get("threat_type", "Unknown"),
            "severity": str(response.get("severity", "LOW")).upper(),
            "priority": str(response.get("priority", "NORMAL")).upper(),
            "recommended_action": response.get("recommended_action", ""),
            "action": action,
            "status": "PENDING_APPROVAL",
            "execution_message": "No security control has been changed. Analyst review is required.",
        })
    return {"status": "success", "execution_mode": "SIMULATION_ONLY", "total_actions": len(actions), "actions": actions}


def summarize_logs(frame: pd.DataFrame) -> dict[str, Any]:
    def find_column(names: set[str]) -> str | None:
        return next((column for column in frame.columns if column.lower() in names), None)

    source = find_column({"source ip", "src ip", "source_ip", "src_ip"})
    protocol = find_column({"protocol"})
    port = find_column({"destination port", "dest port", "dst port", "destination_port"})
    decision = find_column({"action", "status", "decision"})
    decisions = frame[decision].astype(str).str.upper().value_counts() if decision else pd.Series(dtype="int64")
    return {
        "total_logs": int(len(frame)),
        "unique_source_ips": int(frame[source].nunique()) if source else 0,
        "repeated_source_ips": {str(key): int(value) for key, value in frame[source].value_counts().loc[lambda counts: counts > 1].head(10).items()} if source else {},
        "protocol_distribution": {str(key): int(value) for key, value in frame[protocol].value_counts().items()} if protocol else {},
        "top_destination_ports": {str(key): int(value) for key, value in frame[port].value_counts().head(10).items()} if port else {},
        "allowed_requests": int(sum(int(decisions.get(key, 0)) for key in ("ALLOW", "ALLOWED"))),
        "denied_requests": int(sum(int(decisions.get(key, 0)) for key in ("DENY", "DENIED", "BLOCK", "BLOCKED"))),
    }


def require_incident(connection: sqlite3.Connection, incident_id: int) -> sqlite3.Row:
    incident = connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    description: str = Field(default="", max_length=4000)
    severity: str = Field(default="MEDIUM", pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    log_id: int | None = Field(default=None, ge=1)


class IncidentStatusUpdate(BaseModel):
    status: str = Field(pattern="^(OPEN|INVESTIGATING|RESOLVED|CLOSED)$")


class ActionDecision(BaseModel):
    decision: str = Field(pattern="^(APPROVED|INVESTIGATING|REJECTED|PENDING)$")


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "AegisSphere backend is running", "status": "success", "docs": "/docs"}


@app.get("/health")
def health_check() -> dict[str, Any]:
    return {"status": "healthy", "service": "AegisSphere API", "model_loaded": model is not None, "model_features": len(FEATURE_NAMES)}


@app.get("/dashboard/stats")
def dashboard_stats() -> dict[str, Any]:
    with database() as connection:
        latest = connection.execute("SELECT * FROM analysis_runs ORDER BY id DESC LIMIT 1").fetchone()
        incidents = connection.execute("SELECT status, COUNT(*) count FROM incidents GROUP BY status").fetchall()
        actions = connection.execute("SELECT status, COUNT(*) count FROM response_actions GROUP BY status").fetchall()
        severity = connection.execute("SELECT severity, COUNT(*) count FROM incidents WHERE status NOT IN ('RESOLVED','CLOSED') GROUP BY severity").fetchall()
        return {
            "latest_analysis": row_dict(latest) if latest else None,
            "incident_counts": {row["status"].lower(): row["count"] for row in incidents},
            "action_counts": {row["status"].lower(): row["count"] for row in actions},
            "open_incidents": sum(row["count"] for row in incidents if row["status"] not in ("RESOLVED", "CLOSED")),
            "severity_counts": {row["severity"].lower(): row["count"] for row in severity},
            "model_loaded": model is not None,
        }


@app.post("/upload-log")
async def upload_log(file: UploadFile = File(...)) -> dict[str, Any]:
    try:
        contents = await file.read(MAX_UPLOAD_BYTES + 1)
        frame = read_csv_upload(contents, file.filename)
        return {"status": "success", "filename": file.filename, **summarize_logs(frame)}
    finally:
        await file.close()


@app.post("/predict")
async def predict(file: UploadFile = File(...)) -> dict[str, Any]:
    try:
        frame = read_csv_upload(await file.read(MAX_UPLOAD_BYTES + 1), file.filename)
        missing = [feature for feature in FEATURE_NAMES if feature not in frame.columns]
        if missing:
            raise HTTPException(status_code=400, detail={"message": "Required CICIDS2017 features are missing", "missing_features": missing})
        features = frame[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce").fillna(0)
        predictions = model.predict(features)
        probabilities = model.predict_proba(features)
        classes = list(model.classes_)
        attack_index = classes.index(1) if 1 in classes else (classes.index("ATTACK") if "ATTACK" in classes else -1)
        results = []
        for prediction, probability in zip(predictions, probabilities):
            is_attack = prediction == 1 or str(prediction).upper() == "ATTACK"
            confidence = float(probability[attack_index] if is_attack and attack_index >= 0 else max(probability))
            results.append({"prediction": "ATTACK" if is_attack else "BENIGN", "confidence": round(confidence, 4)})
        attack_count = sum(result["prediction"] == "ATTACK" for result in results)
        return {"status": "success", "total_logs": len(results), "attack_count": attack_count, "benign_count": len(results) - attack_count, "results": results}
    finally:
        await file.close()


@app.post("/threat-intelligence")
async def threat_intelligence(file: UploadFile = File(...)) -> dict[str, Any]:
    try:
        frame = read_csv_upload(await file.read(MAX_UPLOAD_BYTES + 1), file.filename)
        missing = [feature for feature in FEATURE_NAMES if feature not in frame.columns]
        if missing:
            raise HTTPException(status_code=400, detail={"message": "Required CICIDS2017 features are missing", "missing_features": missing})
        features = frame[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce").fillna(0)
        predictions, probabilities = model.predict(features), model.predict_proba(features)
        classes = list(model.classes_)
        attack_idx = classes.index(1) if 1 in classes else -1
        detected = [{"prediction": "ATTACK" if value == 1 or str(value).upper() == "ATTACK" else "BENIGN", "confidence": round(float(prob[attack_idx] if (value == 1 or str(value).upper() == "ATTACK") and attack_idx >= 0 else max(prob)), 4)} for value, prob in zip(predictions, probabilities)]
        return {"status": "success", "filename": file.filename, "threat_intelligence": analyze_threats(detected)}
    finally:
        await file.close()


@app.post("/agent-analysis")
async def agent_analysis(file: UploadFile = File(...)) -> dict[str, Any]:
    try:
        frame = read_csv_upload(await file.read(MAX_UPLOAD_BYTES + 1), file.filename)
        result = run_security_pipeline(model, FEATURE_NAMES, frame.copy())
        if result.get("status") != "success":
            raise HTTPException(status_code=400, detail={"message": result.get("message", "Analysis could not process these features."), "missing_features": result.get("missing_features", [])})
        actions = generate_response_action(result.get("response"))
        created_incidents: list[dict[str, Any]] = []
        with database() as connection:
            ti = result["threat_intelligence"]
            cursor = connection.execute(
                "INSERT INTO analysis_runs(filename,total_logs,attack_count,benign_count,overall_severity,created_at) VALUES(?,?,?,?,?,?)",
                (file.filename or "upload.csv", ti["total_logs"], ti["attack_count"], ti["benign_count"], ti["overall_severity"], now_iso()),
            )
            run_id = int(cursor.lastrowid)
            for item in actions["actions"][:MAX_INCIDENTS_PER_ANALYSIS]:
                created_at = now_iso()
                title = f"{item['threat_type']} — log #{item['log_id']}"
                cursor = connection.execute(
                    "INSERT INTO incidents(title,description,severity,status,source,log_id,created_at,updated_at) VALUES(?,?,?,'OPEN','ml-analysis',?,?,?)",
                    (title, item["recommended_action"], item["severity"], item["log_id"], created_at, created_at),
                )
                incident_id = int(cursor.lastrowid)
                cursor = connection.execute(
                    "INSERT INTO response_actions(incident_id,log_id,action,recommendation,priority,status,decision,created_at,updated_at) VALUES(?,?,?,?,?,'PENDING','PENDING',?,?)",
                    (incident_id, item["log_id"], item["action"], item["recommended_action"], item["priority"], created_at, created_at),
                )
                action_id = int(cursor.lastrowid)
                audit(connection, "INCIDENT_CREATED_FROM_ANALYSIS", {"run_id": run_id, "severity": item["severity"]}, incident_id, action_id)
                created_incidents.append({"incident_id": incident_id, "action_id": action_id})
        for index, item in enumerate(actions["actions"][:len(created_incidents)]):
            item.update(created_incidents[index])
        actions["omitted_incident_count"] = max(0, actions["total_actions"] - len(created_incidents))
        actions["actions"] = actions["actions"][:MAX_INCIDENTS_PER_ANALYSIS]
        result["response_actions"] = actions
        result["analysis_run_id"] = run_id
        return {"status": "success", "filename": file.filename, "analysis": result}
    finally:
        await file.close()


@app.post("/incidents", status_code=201)
def create_incident(payload: IncidentCreate) -> dict[str, Any]:
    created_at = now_iso()
    with database() as connection:
        cursor = connection.execute(
            "INSERT INTO incidents(title,description,severity,status,source,log_id,created_at,updated_at) VALUES(?,?,?,'OPEN','analyst',?,?,?)",
            (payload.title.strip(), payload.description.strip(), payload.severity, payload.log_id, created_at, created_at),
        )
        incident_id = int(cursor.lastrowid)
        audit(connection, "INCIDENT_CREATED", payload.model_dump(), incident_id)
        return row_dict(require_incident(connection, incident_id))


@app.get("/incidents")
def list_incidents(status: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    if status and status not in {"OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"}:
        raise HTTPException(status_code=400, detail="Invalid incident status.")
    limit = min(max(limit, 1), 500)
    with database() as connection:
        where, parameters = ("WHERE status = ?", [status]) if status else ("", [])
        rows = connection.execute(f"SELECT * FROM incidents {where} ORDER BY id DESC LIMIT ? OFFSET ?", (*parameters, limit, offset)).fetchall()
        return {"items": [row_dict(row) for row in rows], "limit": limit, "offset": offset}


@app.get("/incidents/{incident_id}")
def incident_detail(incident_id: int) -> dict[str, Any]:
    with database() as connection:
        incident = row_dict(require_incident(connection, incident_id))
        incident["response_actions"] = [row_dict(row) for row in connection.execute("SELECT * FROM response_actions WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()]
        incident["audit_history"] = [row_dict(row) | {"details": json.loads(row["details"])} for row in connection.execute("SELECT * FROM audit_logs WHERE incident_id = ? ORDER BY id DESC", (incident_id,)).fetchall()]
        return incident


@app.patch("/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, payload: IncidentStatusUpdate) -> dict[str, Any]:
    with database() as connection:
        incident = require_incident(connection, incident_id)
        updated_at = now_iso()
        connection.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?", (payload.status, updated_at, incident_id))
        audit(connection, "INCIDENT_STATUS_CHANGED", {"from": incident["status"], "to": payload.status}, incident_id)
        return row_dict(require_incident(connection, incident_id))


@app.post("/incidents/{incident_id}/actions/{action_id}/decision")
def decide_response_action(incident_id: int, action_id: int, payload: ActionDecision) -> dict[str, Any]:
    with database() as connection:
        require_incident(connection, incident_id)
        action = connection.execute("SELECT * FROM response_actions WHERE id = ? AND incident_id = ?", (action_id, incident_id)).fetchone()
        if not action:
            raise HTTPException(status_code=404, detail="Response action not found for this incident.")
        if action["status"] in {"APPROVED_SIMULATED", "REJECTED"} and payload.decision != action["decision"]:
            raise HTTPException(status_code=409, detail="This response action already has a final decision.")
        status_map = {"APPROVED": "APPROVED_SIMULATED", "INVESTIGATING": "INVESTIGATING", "REJECTED": "REJECTED", "PENDING": "PENDING"}
        updated_at = now_iso()
        next_status = status_map[payload.decision]
        connection.execute("UPDATE response_actions SET decision = ?, status = ?, updated_at = ? WHERE id = ?", (payload.decision, next_status, updated_at, action_id))
        if payload.decision == "INVESTIGATING":
            connection.execute("UPDATE incidents SET status = 'INVESTIGATING', updated_at = ? WHERE id = ?", (updated_at, incident_id))
        audit(connection, "RESPONSE_DECISION_RECORDED", {"decision": payload.decision, "status": next_status, "simulation_only": True}, incident_id, action_id)
        updated = connection.execute("SELECT * FROM response_actions WHERE id = ?", (action_id,)).fetchone()
        return {"status": "success", "incident_id": incident_id, "action": row_dict(updated), "execution": "SIMULATION_ONLY", "message": "Approval recorded. No firewall, host, or network control was changed." if payload.decision == "APPROVED" else f"Decision recorded: {payload.decision}."}


@app.post("/response-action")
def legacy_response_action(data: dict[str, Any]) -> dict[str, Any]:
    """Compatibility route for the original UI; resolves only persisted proposals."""
    log_id, action_name, decision = data.get("log_id"), data.get("action"), data.get("decision")
    if not isinstance(log_id, int) or isinstance(log_id, bool) or log_id < 1:
        raise HTTPException(status_code=400, detail="log_id must be a positive integer.")
    if not isinstance(action_name, str) or action_name not in {"BLOCK_IP", "BLOCK_SOURCE", "ISOLATE_HOST", "MONITOR_ACTIVITY", "INVESTIGATE_THREAT", "GENERATE_ALERT"}:
        raise HTTPException(status_code=400, detail="Invalid response action.")
    if decision not in {"APPROVED", "INVESTIGATING", "REJECTED", "PENDING"}:
        raise HTTPException(status_code=400, detail="Invalid analyst decision.")
    with database() as connection:
        action = connection.execute("SELECT * FROM response_actions WHERE log_id = ? AND action = ? ORDER BY id DESC LIMIT 1", (log_id, action_name)).fetchone()
    if not action:
        raise HTTPException(status_code=404, detail="No persisted response proposal matches this log and action.")
    result = decide_response_action(action["incident_id"], action["id"], ActionDecision(decision=decision))
    return {"status": "success", "log_id": log_id, "action": action_name, "decision": decision, "execution": "SIMULATION_ONLY", "execution_status": result["action"]["status"], "message": result["message"]}


@app.get("/action-history")
def action_history(limit: int = 200) -> dict[str, Any]:
    limit = min(max(limit, 1), 1000)
    with database() as connection:
        rows = connection.execute("SELECT a.*, i.title AS incident_title FROM audit_logs a LEFT JOIN incidents i ON i.id = a.incident_id ORDER BY a.id DESC LIMIT ?", (limit,)).fetchall()
        return {"items": [row_dict(row) | {"details": json.loads(row["details"])} for row in rows]}


@app.get("/openapi.json", include_in_schema=False)
def openapi_json() -> dict[str, Any]:
    return app.openapi()
