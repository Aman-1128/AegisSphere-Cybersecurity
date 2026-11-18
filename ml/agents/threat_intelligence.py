def analyze_threats(prediction_results):
    """
    Analyze ML predictions and assign threat severity
    with basic threat intelligence information.
    """

    threats = []

    attack_count = 0
    benign_count = 0

    for index, result in enumerate(prediction_results):

        prediction = result.get("prediction")
        confidence = float(
            result.get("confidence", 0)
        )

        # ---------------------------------------
        # ATTACK ANALYSIS
        # ---------------------------------------

        if prediction == "ATTACK":

            attack_count += 1

            # -----------------------------------
            # SEVERITY
            # -----------------------------------

            if confidence >= 0.90:
                severity = "CRITICAL"

            elif confidence >= 0.75:
                severity = "HIGH"

            elif confidence >= 0.50:
                severity = "MEDIUM"

            else:
                severity = "LOW"

            # -----------------------------------
            # THREAT INTELLIGENCE
            # -----------------------------------

            threat = {
                "log_id": index + 1,

                "threat_type": "Network Attack",

                "severity": severity,

                "confidence": round(
                    confidence,
                    4
                ),

                "description": (
                    "Machine learning detected "
                    "network activity that matches "
                    "an attack pattern."
                ),

                "risk": (
                    "Potentially malicious network "
                    "activity requiring investigation."
                ),

                "recommended_action": (
                    "Investigate the affected log, "
                    "review the source and destination "
                    "traffic, and apply appropriate "
                    "security controls."
                )
            }

            threats.append(threat)

        else:

            benign_count += 1

    # ---------------------------------------
    # SUMMARY
    # ---------------------------------------

    total_logs = len(prediction_results)

    threat_rate = (
        (attack_count / total_logs) * 100
        if total_logs > 0
        else 0
    )

    # ---------------------------------------
    # SEVERITY COUNTS
    # ---------------------------------------

    critical_count = sum(
        1
        for threat in threats
        if threat["severity"] == "CRITICAL"
    )

    high_count = sum(
        1
        for threat in threats
        if threat["severity"] == "HIGH"
    )

    medium_count = sum(
        1
        for threat in threats
        if threat["severity"] == "MEDIUM"
    )

    low_count = sum(
        1
        for threat in threats
        if threat["severity"] == "LOW"
    )

    # ---------------------------------------
    # OVERALL STATUS
    # ---------------------------------------

    if critical_count > 0:
        overall_severity = "CRITICAL"

    elif high_count > 0:
        overall_severity = "HIGH"

    elif medium_count > 0:
        overall_severity = "MEDIUM"

    elif low_count > 0:
        overall_severity = "LOW"

    else:
        overall_severity = "NONE"

    # ---------------------------------------
    # FINAL RESPONSE
    # ---------------------------------------

    return {

        "status": "success",

        "total_logs": total_logs,

        "attack_count": attack_count,

        "benign_count": benign_count,

        "threat_rate": round(
            threat_rate,
            2
        ),

        "overall_severity": overall_severity,

        "severity_summary": {

            "critical": critical_count,

            "high": high_count,

            "medium": medium_count,

            "low": low_count
        },

        "threats": threats
    }