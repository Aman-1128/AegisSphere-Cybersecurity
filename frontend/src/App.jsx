import { useEffect, useState } from "react";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

function App() {
  const [backendStatus, setBackendStatus] = useState("Checking...");
  const [selectedFile, setSelectedFile] = useState(null);
  const [predictionResult, setPredictionResult] = useState(null);
  const [agentAnalysis, setAgentAnalysis] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [actionStatuses, setActionStatuses] = useState({});
  const [actionHistory, setActionHistory] = useState([]);
  const [workspaceStats, setWorkspaceStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [incidentError, setIncidentError] = useState("");
  const [incidentDraft, setIncidentDraft] = useState({ title: "", severity: "MEDIUM", description: "" });
  const [savingIncident, setSavingIncident] = useState(false);

  // =========================================================
  // BACKEND HEALTH CHECK
  // =========================================================

  const loadWorkspace = async () => {
    try {
      const [statsResponse, incidentsResponse, historyResponse] = await Promise.all([
        fetch(`${API_BASE}/dashboard/stats`),
        fetch(`${API_BASE}/incidents?limit=100`),
        fetch(`${API_BASE}/action-history?limit=200`),
      ]);
      if (!statsResponse.ok || !incidentsResponse.ok || !historyResponse.ok) throw new Error("Workspace data could not be loaded.");
      const [stats, incidentData, historyData] = await Promise.all([
        statsResponse.json(), incidentsResponse.json(), historyResponse.json(),
      ]);
      setWorkspaceStats(stats);
      setIncidents(incidentData.items || []);
      setActionHistory(historyData.items || []);
      setIncidentError("");
    } catch (error) {
      setIncidentError(error.message || "Backend unavailable.");
    }
  };

  const checkBackend = async () => {
    setBackendStatus("Checking...");

    try {
      const response = await fetch(`${API_BASE}/health`);

      if (!response.ok) {
        throw new Error("Backend unavailable");
      }

      const data = await response.json();

      setBackendStatus(
        data.status === "healthy" ? "healthy" : "Offline"
      );
      loadWorkspace();
    } catch (error) {
      console.error("Health check error:", error);
      setBackendStatus("Offline");
    }
  };

  useEffect(() => {
    let active = true;
    fetch(`${API_BASE}/health`)
      .then((response) => {
        if (!response.ok) throw new Error("Backend unavailable");
        return response.json();
      })
      .then((data) => {
        if (!active) return;
        setBackendStatus(data.status === "healthy" ? "healthy" : "Offline");
        loadWorkspace();
      })
      .catch((error) => {
        if (!active) return;
        console.error("Health check error:", error);
        setBackendStatus("Offline");
      });
    return () => { active = false; };
  }, []);

  // =========================================================
  // FILE SELECTION
  // =========================================================

  const handleFileChange = (event) => {
    const file = event.target.files[0];

    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".csv")) {
      alert("Please select a CSV file.");
      event.target.value = "";
      return;
    }

    setSelectedFile(file);
    setPredictionResult(null);
    setAgentAnalysis(null);
  };

  // =========================================================
  // AI AGENT ANALYSIS
  // =========================================================

  const analyzeFile = async () => {
    if (!selectedFile) {
      alert("Please select a CSV file first.");
      return;
    }

    setAnalyzing(true);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch(
        `${API_BASE}/agent-analysis`,
        {
          method: "POST",
          body: formData,
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Analysis failed"
        );
      }

      if (data.status === "error") {
        throw new Error(
          data.message || "Analysis failed"
        );
      }

      console.log(
        "Complete AegisSphere Analysis:",
        data
      );

      // Store complete multi-agent result
      setAgentAnalysis(data.analysis || null);

      // Store threat detection result
      setPredictionResult(
        data.analysis?.threat_detection || null
      );
      await loadWorkspace();
    } catch (error) {
      console.error("Analysis error:", error);

      alert(
        error.message ||
          "Could not analyze the file. Make sure the backend is running."
      );
    } finally {
      setAnalyzing(false);
    }
  };

  // =========================================================
  // CLEAR ANALYSIS
  // =========================================================

  const clearAnalysis = () => {
    setSelectedFile(null);
    setPredictionResult(null);
    setAgentAnalysis(null);
    setActionStatuses({});

    const fileInput =
      document.getElementById("log-file");

    if (fileInput) {
      fileInput.value = "";
    }
  };

  // =========================================================
  // THREAT DETECTION DATA
  // =========================================================

  const totalLogs =
    predictionResult?.total_logs ?? workspaceStats?.latest_analysis?.total_logs ?? 0;

  const attacks =
    predictionResult?.attack_count ?? workspaceStats?.latest_analysis?.attack_count ?? 0;

  const benign =
    predictionResult?.benign_count ?? workspaceStats?.latest_analysis?.benign_count ?? 0;

  const threatRate =
    totalLogs > 0
      ? ((attacks / totalLogs) * 100).toFixed(2)
      : "0.00";

  const results =
    predictionResult?.results || [];

  // =========================================================
  // AGENT DATA
  // =========================================================

  const logAnalysis =
    agentAnalysis?.log_analysis || null;

  const threatIntelligence =
    agentAnalysis?.threat_intelligence || null;

  const responseAgent =
    agentAnalysis?.response || null;
  const responseActions =
    agentAnalysis?.response_actions || null;
  const actionCounts = workspaceStats?.action_counts || {};
  const approvedCount = actionCounts.approved_simulated || 0;
  const investigatingCount = actionCounts.investigating || 0;
  const rejectedCount = actionCounts.rejected || 0;
  const totalActionCount = Object.values(actionCounts).reduce((sum, count) => sum + count, 0);

  const updateActionStatus = async (
    actionKey,
    status,
    incidentId,
    responseActionId
  ) => {
    try {
      const response = await fetch(
        `${API_BASE}/incidents/${incidentId}/actions/${responseActionId}/decision`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ decision: status }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "Action failed");
      }

      console.log("Response Action:", data);

      setActionStatuses((prev) => ({
        ...prev,
        [actionKey]: data.action.status,
      }));
      await loadWorkspace();
    } catch (error) {
      console.error("Response action error:", error);
      alert("Could not record response decision.");
    }
  };

  const createIncident = async (event) => {
    event.preventDefault();
    setSavingIncident(true);
    try {
      const response = await fetch(`${API_BASE}/incidents`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(incidentDraft),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Incident could not be created.");
      setIncidentDraft({ title: "", severity: "MEDIUM", description: "" });
      await loadWorkspace();
    } catch (error) {
      setIncidentError(typeof error.message === "string" ? error.message : "Incident could not be created.");
    } finally {
      setSavingIncident(false);
    }
  };

  const updateIncidentStatus = async (incidentId, status) => {
    try {
      const response = await fetch(`${API_BASE}/incidents/${incidentId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Incident status could not be updated.");
      await loadWorkspace();
    } catch (error) {
      setIncidentError(error.message || "Incident status could not be updated.");
    }
  };

  const loadIncidentDetail = async (incidentId) => {
    try {
      const response = await fetch(`${API_BASE}/incidents/${incidentId}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Incident details could not be loaded.");
      setIncidentDetail(data);
    } catch (error) {
      setIncidentError(error.message || "Incident details could not be loaded.");
    }
  };

  // =========================================================
  // THREAT INTELLIGENCE DATA
  // =========================================================

  const overallSeverity =
    threatIntelligence?.overall_severity || "NONE";

  const intelligenceAttackCount =
    threatIntelligence?.attack_count ?? attacks;

  const intelligenceBenignCount =
    threatIntelligence?.benign_count ?? benign;

  const intelligenceThreatRate =
    threatIntelligence?.threat_rate ?? threatRate;

  const severitySummary =
    threatIntelligence?.severity_summary || {};

  const criticalCount =
    severitySummary.critical || 0;

  const highCount =
    severitySummary.high || 0;

  const mediumCount =
    severitySummary.medium || 0;

  const lowCount =
    severitySummary.low || 0;

  const intelligenceThreats =
    threatIntelligence?.threats || [];

  // =========================================================
  // UI
  // =========================================================

  return (
    <div className="dashboard">

      {/* =====================================================
          HEADER
      ====================================================== */}

      <header className="header">

        <div>
          <h1>AegisSphere</h1>

          <p>
            Autonomous Security Operations &
            Threat Intelligence
          </p>
        </div>

        <nav className="main-nav" aria-label="Main navigation">
          <a href="#overview">Overview</a>
          <a href="#incidents">Incidents ({workspaceStats?.open_incidents ?? 0})</a>
          <a href="#responses">Response</a>
          <a href="#activity">Activity</a>
        </nav>

                <div className="system-status">

          <span
            className={
              backendStatus === "healthy"
                ? "status-dot online"
                : "status-dot offline"
            }
          />

          <span>
            Backend:{" "}
            {backendStatus === "healthy"
              ? "Online"
              : backendStatus}
          </span>

          <button
            className="refresh-button"
            onClick={checkBackend}
          >
            ↻
          </button>

        </div>

      </header>

      {/* =====================================================
          MAIN
      ====================================================== */}

      <main className="content">

        {/* PAGE TITLE */}

        <div className="page-title" id="overview">

          <h2>
            Security Operations Center
          </h2>

          <p>
            Real-time network threat detection
            powered by machine learning and
            multi-agent security analysis.
          </p>

        </div>

        {/* =====================================================
            STAT CARDS
        ====================================================== */}

        <div className="cards">

          <div className="card">

            <span className="card-icon">
              📊
            </span>

            <div>
              <h3>Total Logs</h3>
              <p>{totalLogs}</p>
            </div>

          </div>

          <div className="card threat-card">

            <span className="card-icon">
              🚨
            </span>

            <div>
              <h3>Threats Detected</h3>
              <p>{attacks}</p>
            </div>

          </div>

          <div className="card safe-card">

            <span className="card-icon">
              🛡️
            </span>

            <div>
              <h3>Benign Logs</h3>
              <p>{benign}</p>
            </div>

          </div>

          <div className="card">

            <span className="card-icon">
              ⚠️
            </span>

            <div>
              <h3>Threat Rate</h3>
              <p>{threatRate}%</p>
            </div>

          </div>

        </div>

        <section className="section live-operations">
          <div className="section-header">
            <div>
              <h2>Persisted operations</h2>
              <p>Incident and analysis totals read from the backend database.</p>
            </div>
            <button className="secondary-button" onClick={loadWorkspace}>Refresh data</button>
          </div>
          <div className="result-summary">
            <div className="result-box"><span>Open incidents</span><strong>{workspaceStats?.open_incidents ?? 0}</strong></div>
            <div className="result-box"><span>Latest analysis</span><strong>{workspaceStats?.latest_analysis?.total_logs ?? 0} logs</strong></div>
            <div className="result-box attack"><span>Detected in latest analysis</span><strong>{workspaceStats?.latest_analysis?.attack_count ?? 0}</strong></div>
            <div className="result-box benign"><span>Response decisions</span><strong>{totalActionCount}</strong></div>
          </div>
        </section>

        <section className="section" id="incidents">
          <div className="section-header">
            <div><h2>Incident management</h2><p>Create, review, and update persistent security incidents.</p></div>
          </div>
          {incidentError && <p className="inline-error" role="alert">{incidentError}</p>}
          <form className="incident-form" onSubmit={createIncident}>
            <label>Incident title<input required minLength={3} maxLength={180} value={incidentDraft.title} onChange={(event) => setIncidentDraft({ ...incidentDraft, title: event.target.value })} placeholder="Suspicious outbound traffic" /></label>
            <label>Severity<select value={incidentDraft.severity} onChange={(event) => setIncidentDraft({ ...incidentDraft, severity: event.target.value })}><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>
            <label>Description<textarea maxLength={4000} rows={2} value={incidentDraft.description} onChange={(event) => setIncidentDraft({ ...incidentDraft, description: event.target.value })} placeholder="Context and investigation notes" /></label>
            <button className="analyze-button" disabled={savingIncident}>{savingIncident ? "Saving…" : "Create incident"}</button>
          </form>
          <div className="incident-list">
            {incidents.length ? incidents.map((incident) => (
              <article className="incident-row" key={incident.id}>
                <div><span className={`severity-badge ${incident.severity.toLowerCase()}`}>{incident.severity}</span><h3>#{incident.id} · {incident.title}</h3><p>{incident.description || "No description provided."}</p><small>Created {new Date(incident.created_at).toLocaleString()} · Source: {incident.source}</small></div>
                <div className="incident-controls"><strong>{incident.status}</strong><button className="secondary-button" onClick={() => loadIncidentDetail(incident.id)}>View details</button><select aria-label={`Update incident ${incident.id} status`} value={incident.status} onChange={(event) => updateIncidentStatus(incident.id, event.target.value)}><option>OPEN</option><option>INVESTIGATING</option><option>RESOLVED</option><option>CLOSED</option></select></div>
              </article>
            )) : <p className="table-note">No incidents recorded yet. Analysis creates incidents for detected attacks.</p>}
          </div>
          {incidentDetail && (
            <section className="incident-detail-panel" aria-label={`Incident ${incidentDetail.id} details`}>
              <div className="section-header"><div><h3>Incident #{incidentDetail.id} details</h3><p>{incidentDetail.title} · {incidentDetail.status}</p></div><button className="secondary-button" onClick={() => setIncidentDetail(null)}>Close details</button></div>
              <h4>Response proposals</h4>
              {incidentDetail.response_actions.length ? incidentDetail.response_actions.map((action) => <div className="incident-detail-item" key={action.id}><strong>#{action.id} · {action.action} · {action.status}</strong><p>{action.recommendation || "No recommendation supplied."}</p><small>Decision: {action.decision} · Priority: {action.priority}</small></div>) : <p className="table-note">No response action is linked to this incident.</p>}
              <h4>Audit events</h4>
              {incidentDetail.audit_history.length ? incidentDetail.audit_history.map((entry) => <div className="incident-detail-item" key={entry.id}><strong>{entry.event.replaceAll("_", " ")}</strong><small>{new Date(entry.created_at).toLocaleString()}</small><p>{JSON.stringify(entry.details)}</p></div>) : <p className="table-note">No audit events recorded.</p>}
            </section>
          )}
        </section>

        {/* =====================================================
            FILE UPLOAD / ANALYSIS
        ====================================================== */}

        <section className="section analysis-section">

          <div className="section-header">

            <div>

              <h2>
                AI Threat Detection
              </h2>

              <p>
                Upload a CICIDS2017-compatible
                security log for automated
                multi-agent analysis.
              </p>

            </div>

            {predictionResult && (

              <button
                className="secondary-button"
                onClick={clearAnalysis}
              >
                New Analysis
              </button>

            )}

          </div>

          <div className="upload-area">

            <input
              id="log-file"
              type="file"
              accept=".csv"
              onChange={handleFileChange}
            />

            {selectedFile && (

              <div className="selected-file">

                📄

                <span>
                  {selectedFile.name}
                </span>

              </div>

            )}

            <button
              className="analyze-button"
              onClick={analyzeFile}
              disabled={
                analyzing || !selectedFile
              }
            >

              {analyzing
                ? "Analyzing Network Logs..."
                : "🔍 Analyze Security Logs"}

            </button>

          </div>

        </section>

        {/* =====================================================
            THREAT DETECTION RESULTS
        ====================================================== */}

        {predictionResult && (

          <section className="section">

            <div className="section-header">

              <div>

                <h2>
                  Threat Analysis Results
                </h2>

                <p>
                  Multi-agent security analysis
                  completed successfully.
                </p>

              </div>

            </div>

            {/* SUMMARY */}

            <div className="result-summary">

              <div className="result-box">

                <span>
                  Total Logs
                </span>

                <strong>
                  {totalLogs}
                </strong>

              </div>

              <div className="result-box attack">

                <span>
                  Attacks
                </span>

                <strong>
                  {attacks}
                </strong>

              </div>

              <div className="result-box benign">

                <span>
                  Benign
                </span>

                <strong>
                  {benign}
                </strong>

              </div>

              <div className="result-box warning">

                <span>
                  Threat Rate
                </span>

                <strong>
                  {threatRate}%
                </strong>

              </div>

            </div>

            {/* THREAT METER */}

            <div className="threat-meter">

              <div className="meter-label">

                <span>
                  Threat Distribution
                </span>

                <strong>
                  {threatRate}%
                </strong>

              </div>

              <div className="meter">

                <div
                  className="meter-fill"
                  style={{
                    width: `${threatRate}%`,
                  }}
                />

              </div>

            </div>

            {/* PREDICTION TABLE */}

            <div className="prediction-table-container">

              <h3>
                Detection Results
              </h3>

              <table className="prediction-table">

                <thead>

                  <tr>
                    <th>#</th>
                    <th>Classification</th>
                    <th>Confidence</th>
                    <th>Status</th>
                  </tr>

                </thead>

                <tbody>

                  {results
                    .slice(0, 50)
                    .map((result, index) => {

                      const isAttack =
                        result.prediction ===
                        "ATTACK";

                      return (

                        <tr key={index}>

                          <td>
                            {index + 1}
                          </td>

                          <td>

                            <span
                              className={
                                isAttack
                                  ? "badge attack-badge"
                                  : "badge benign-badge"
                              }
                            >
                              {result.prediction}
                            </span>

                          </td>

                          <td>
                            {(
                              Number(
                                result.confidence || 0
                              ) * 100
                            ).toFixed(2)}
                            %
                          </td>

                          <td>
                            {isAttack
                              ? "🚨 Threat"
                              : "🛡️ Safe"}
                          </td>

                        </tr>

                      );
                    })}

                </tbody>

              </table>

              {results.length > 50 && (

                <p className="table-note">

                  Showing the first 50 results
                  out of {results.length}.

                </p>

              )}

            </div>

          </section>

        )}

        {/* =====================================================
            LOG ANALYSIS AGENT
        ====================================================== */}

        {agentAnalysis && (

          <section className="section">

            <div className="section-header">

              <div>

                <h2>
                  📋 Log Analysis Agent
                </h2>

                <p>
                  Statistical analysis of uploaded
                  security logs.
                </p>

              </div>

            </div>

            <div className="agent-result">

              {logAnalysis ? (

                <pre>
                  {JSON.stringify(
                    logAnalysis,
                    null,
                    2
                  )}
                </pre>

              ) : (

                <p>
                  No log analysis data returned.
                </p>

              )}

            </div>

          </section>

        )}

        {/* =====================================================
            THREAT INTELLIGENCE AGENT
        ====================================================== */}

        {agentAnalysis && (

          <section className="section">

            <div className="section-header">

              <div>

                <h2>
                  🧠 Threat Intelligence
                </h2>

                <p>
                  Contextual analysis of detected
                  security threats.
                </p>

              </div>

            </div>

            {threatIntelligence ? (

              <>

                {/* OVERALL SUMMARY */}

                <div className="result-summary">

                  <div className="result-box">

                    <span>
                      Overall Severity
                    </span>

                    <strong>
                      {overallSeverity}
                    </strong>

                  </div>

                  <div className="result-box attack">

                    <span>
                      Total Threats
                    </span>

                    <strong>
                      {intelligenceAttackCount}
                    </strong>

                  </div>

                  <div className="result-box warning">

                    <span>
                      Threat Rate
                    </span>

                    <strong>
                      {intelligenceThreatRate}%
                    </strong>

                  </div>

                  <div className="result-box benign">

                    <span>
                      Benign Logs
                    </span>

                    <strong>
                      {intelligenceBenignCount}
                    </strong>

                  </div>

                </div>

                {/* SEVERITY DISTRIBUTION */}

                <div className="prediction-table-container">

                  <h3>
                    Severity Distribution
                  </h3>

                  <table className="prediction-table">

                    <thead>

                      <tr>
                        <th>
                          Severity
                        </th>

                        <th>
                          Count
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      <tr>

                        <td>
                          🔴 CRITICAL
                        </td>

                        <td>
                          {criticalCount}
                        </td>

                      </tr>

                      <tr>

                        <td>
                          🟠 HIGH
                        </td>

                        <td>
                          {highCount}
                        </td>

                      </tr>

                      <tr>

                        <td>
                          🟡 MEDIUM
                        </td>

                        <td>
                          {mediumCount}
                        </td>

                      </tr>

                      <tr>

                        <td>
                          🟢 LOW
                        </td>

                        <td>
                          {lowCount}
                        </td>

                      </tr>

                    </tbody>

                  </table>

                </div>

                {/* DETECTED THREATS */}

                <div className="prediction-table-container">

                  <h3>
                    Detected Threat Intelligence
                  </h3>

                  {intelligenceThreats.length > 0 ? (

                    intelligenceThreats
                      .slice(0, 20)
                      .map((threat, index) => (

                        <div
                          className="agent-result"
                          key={index}
                          style={{
                            marginBottom: "15px",
                          }}
                        >

                          <h3>
                            Threat #{threat.log_id}
                          </h3>

                          <p>
                            <strong>
                              Type:
                            </strong>{" "}
                            {threat.threat_type ||
                              "Network Attack"}
                          </p>

                          <p>
                            <strong>
                              Severity:
                            </strong>{" "}
                            {threat.severity ||
                              "UNKNOWN"}
                          </p>

                          <p>
                            <strong>
                              Confidence:
                            </strong>{" "}
                            {(
                              Number(
                                threat.confidence || 0
                              ) * 100
                            ).toFixed(2)}
                            %
                          </p>

                          <p>
                            <strong>
                              Description:
                            </strong>{" "}
                            {threat.description ||
                              "Machine learning detected network activity that matches an attack pattern."}
                          </p>

                          <p>
                            <strong>
                              Risk:
                            </strong>{" "}
                            {threat.risk ||
                              "Potentially malicious network activity requiring investigation."}
                          </p>

                          <p>
                            <strong>
                              Recommended Action:
                            </strong>{" "}
                            {threat.recommended_action ||
                              "Investigate the affected log, review source and destination traffic, and apply appropriate security controls."}
                          </p>

                        </div>

                      ))

                  ) : (

                    <p>
                      No threats detected.
                    </p>

                  )}

                </div>

              </>

            ) : (

              <p>
                No threat intelligence data returned.
              </p>

            )}

          </section>

        )}

{/* =====================================================
          RESPONSE AGENT
===================================================== */}

  <section className="section" id="responses">

    <div className="section-header">

      <div>

        <h2>
          🛡️ Response Recommendations
        </h2>

        <p>
          Recommended response actions generated by the response agent.
        </p>

      </div>

    </div>

    {responseAgent?.responses?.length > 0 ? (

      <div className="response-list">

        {responseAgent.responses.map((response, index) => {

          const severity =
            (response.severity || "UNKNOWN").toUpperCase();

          const priority =
            (response.priority || "NORMAL").toUpperCase();

          const severityClass =
            severity === "CRITICAL"
              ? "critical"
              : severity === "HIGH"
              ? "high"
              : severity === "MEDIUM"
              ? "medium"
              : "low";

          return (

            <div
              className="response-card"
              key={response.log_id || index}
            >

              {/* HEADER */}

              <div className="response-card-header">

                <div className="response-heading">

                  <span className="response-log-id">
                    LOG #{response.log_id}
                  </span>

                  <h3>
                    {response.threat_type || "Security Threat"}
                  </h3>

                </div>

                <span
                  className={`response-severity ${severityClass}`}
                >
                  {severity}
                </span>

              </div>


              {/* DETAILS */}

              <div className="response-details">

                <div className="response-detail">

                  <span>
                    Priority
                  </span>

                  <strong>
                    ⚡ {priority}
                  </strong>

                </div>


                <div className="response-detail">

                  <span>
                    Threat Type
                  </span>

                  <strong>
                    {response.threat_type || "Unknown"}
                  </strong>

                </div>

              </div>


              {/* ACTION */}

              <div className="recommended-action">

                <h4>
                  Recommended Action
                </h4>

                <p>
                  {response.recommended_action ||
                    "Investigate the affected security event and apply appropriate security controls."}
                </p>

              </div>

            </div>

          );

        })}

      </div>

    ) : (

      <div className="agent-result">
        <p>
          {agentAnalysis ? "No response recommendations returned." : "Upload and analyze a CSV to view response recommendations."}
        </p>
      </div>

    )}

  </section>
{/* =====================================================
    AUTOMATED RESPONSE ACTIONS
====================================================== */}

  <section className="section">

    <div className="section-header">
      <div>
        <h2>⚡ Automated Response Actions</h2>
        <p>
          Simulated security actions generated from
          response recommendations.
        </p>
      </div>

      {responseActions && (
        <span className="response-mode-badge">
          SIMULATION MODE
        </span>
      )}
    </div>
    {responseActions?.omitted_incident_count > 0 && <p className="table-note">This run created proposals for the first 500 detected attacks. {responseActions.omitted_incident_count} additional response proposals were not persisted.</p>}
    <div className="response-summary">

  <div className="response-summary-card">
    <span>Total Actions</span>
    <strong>{totalActionCount}</strong>
  </div>

  <div className="response-summary-card">
    <span>Approved</span>
    <strong>{approvedCount}</strong>
  </div>

  <div className="response-summary-card">
    <span>Investigating</span>
    <strong>{investigatingCount}</strong>
  </div>

  <div className="response-summary-card">
    <span>Rejected</span>
    <strong>{rejectedCount}</strong>
  </div>

</div>

    {responseActions?.actions?.length > 0 ? (

      <div className="response-action-list">

        {responseActions.actions.map((action, index) => {
          const actionKey = `${action.log_id}-${index}`;
          const currentStatus = actionStatuses[actionKey] || action.status || "PENDING_APPROVAL";
          const finalDecision = ["APPROVED_SIMULATED", "REJECTED"].includes(currentStatus);

          return (
            <div
              className="response-action-card"
              key={`${action.log_id}-${index}`}
            >

              <div className="response-action-header">

                <div>
                  <span className="response-action-log">
                    LOG #{action.log_id}
                  </span>

                  <h3>
                    {action.threat_type || "Security Threat"}
                  </h3>
                </div>

                <div className="response-action-status">

                  <span className={`response-action-severity ${String(action.severity || "low").toLowerCase()}`}>
                    {action.severity}
                  </span>

                  <span className="response-action-simulated">
                    {action.status === "PENDING_APPROVAL" ? "Awaiting approval" : action.status}
                  </span>

                </div>

              </div>

              <div className="response-action-details">

                <div className="response-action-detail">
                  <span>Automated Action</span>
                  <strong>
                    ⚡ {action.action}
                  </strong>
                </div>

                <div className="response-action-detail">
                  <span>Priority</span>
                  <strong>
                    {action.priority}
                  </strong>
                </div>

              </div>

              <div className="response-execution">

                <div className="response-execution-icon">
                  ✓
                </div>

                <div>
                  <h4>Simulation Result</h4>

                  <p>
                    {action.execution_message}
                  </p>
                </div>

              </div>

              <div className="response-action-controls">

                <button
                  className="approve-button"
                  disabled={finalDecision || !action.incident_id || !action.action_id}
                  onClick={() =>
                    updateActionStatus(
                      actionKey,
                      "APPROVED",
                      action.incident_id,
                      action.action_id
                    )
                  }
                >
                  ✓ Approve
                </button>

                <button
                  className="investigate-button"
                  disabled={finalDecision || !action.incident_id || !action.action_id}
                  onClick={() =>
                    updateActionStatus(
                      actionKey,
                      "INVESTIGATING",
                      action.incident_id,
                      action.action_id
                    )
                  }
                >
                  🔍 Investigate
                </button>

                <button
                  className="reject-button"
                  disabled={finalDecision || !action.incident_id || !action.action_id}
                  onClick={() =>
                    updateActionStatus(
                      actionKey,
                      "REJECTED",
                      action.incident_id,
                      action.action_id
                    )
                  }
                >
                  ✕ Reject
                </button>

              </div>

              <div className="response-decision-status">
                Status: <strong>{currentStatus}</strong>
              </div>

            </div>
          );
        })}

      </div>

    ) : (

      <div className="agent-result">
        <p>{agentAnalysis ? "No automated response actions generated." : "Upload and analyze a CSV to create incident linked response proposals."}</p>
      </div>

    )}

  </section>
  
{/* =====================================================
    ACTION HISTORY
====================================================== */}

  <section className="section" id="activity">

    <div className="section-header">
      <div>
        <h2>📜 Action History</h2>
        <p>
          Record of analyst decisions and simulated response actions.
        </p>
      </div>
    </div>

    <div className="response-action-list">

      {!actionHistory.length && <p className="table-note">No activity has been recorded yet.</p>}

      {actionHistory.map((item, index) => (

        <div
          className="response-action-card"
          key={`${item.id}-${index}`}
        >

          <div className="response-action-header">

            <div>
              <span className="response-action-log">{item.incident_id ? `INCIDENT #${item.incident_id}` : "SYSTEM"}</span>

              <h3>
                {item.event.replaceAll("_", " ")}
              </h3>
            </div>

            <span className="response-action-simulated">
              {new Date(item.created_at).toLocaleString()}
            </span>

          </div>

          <div className="response-action-details">

            <div className="response-action-detail">
              <span>Decision</span>
              <strong>
                {item.details?.decision || item.details?.to || "Recorded"}
              </strong>
            </div>

            <div className="response-action-detail">
              <span>Time</span>
              <strong>
                {item.action_id ? `Action #${item.action_id}` : "Audit event"}
              </strong>
            </div>

          </div>

          <div className="response-execution">

            <div className="response-execution-icon">
              ✓
            </div>

            <div>
              <h4>Execution Result</h4>
              <p>
                {item.details?.simulation_only ? "Recorded as simulation only; no security control was changed." : JSON.stringify(item.details)}
              </p>
            </div>

          </div>

        </div>

      ))}

    </div>

  </section>

        {/* =====================================================
            AI AGENT STATUS
        ====================================================== */}

        <section className="section">

          <h2>
            AI Agent Status
          </h2>

          <div className="agents">

            {/* LOG ANALYSIS */}

            <div className="agent">

              <span
                className={
                  agentAnalysis
                    ? "agent-dot ready"
                    : "agent-dot pending"
                }
              />

              <div>

                <strong>
                  Log Analysis Agent
                </strong>

                <p>
                  {agentAnalysis
                    ? "Completed"
                    : "Ready"}
                </p>

              </div>

            </div>

            {/* THREAT DETECTION */}

            <div className="agent">

              <span
                className={
                  predictionResult
                    ? "agent-dot ready"
                    : "agent-dot pending"
                }
              />

              <div>

                <strong>
                  Threat Detection Agent
                </strong>

                <p>
                  {predictionResult
                    ? "Completed"
                    : "Ready"}
                </p>

              </div>

            </div>

            {/* THREAT INTELLIGENCE */}

            <div className="agent">

              <span
                className={
                  threatIntelligence
                    ? "agent-dot ready"
                    : "agent-dot pending"
                }
              />

              <div>

                <strong>
                  Threat Intelligence Agent
                </strong>

                <p>
                  {threatIntelligence
                    ? "Completed"
                    : "Pending"}
                </p>

              </div>

            </div>

            {/* RESPONSE AGENT */}

            <div className="agent">

              <span
                className={
                  responseAgent
                    ? "agent-dot ready"
                    : "agent-dot pending"
                }
              />

              <div>

                <strong>
                  Response Agent
                </strong>

                <p>
                  {responseAgent
                    ? "Completed"
                    : "Pending"}
                </p>

              </div>

            </div>

          </div>

        </section>

      </main>

    </div>
  );
}

export default App;
