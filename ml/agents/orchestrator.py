from ml.agents.log_analysis import analyze_logs
from ml.agents.threat_detection import detect_threats
from ml.agents.threat_intelligence import analyze_threats
from ml.agents.response import generate_response


def run_security_pipeline(model, feature_names, df):
    """
    Run the complete AegisSphere multi-agent
    security analysis pipeline.
    """

    # ---------------------------------------
    # Agent 1: Log Analysis
    # ---------------------------------------

    log_analysis = analyze_logs(df)

    # ---------------------------------------
    # Agent 2: Threat Detection
    # ---------------------------------------

    detection = detect_threats(
        model,
        feature_names,
        df
    )

    if detection.get("status") == "error":
        return detection

    # ---------------------------------------
    # Agent 3: Threat Intelligence
    # ---------------------------------------

    intelligence = analyze_threats(
        detection["results"]
    )

    # ---------------------------------------
    # Agent 4: Response
    # ---------------------------------------

    response = generate_response(
        intelligence["threats"]
    )

    # ---------------------------------------
    # Combined Result
    # ---------------------------------------

    return {
        "status": "success",

        "log_analysis": log_analysis,

        "threat_detection": detection,

        "threat_intelligence": intelligence,

        "response": response
    }