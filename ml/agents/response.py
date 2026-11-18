def generate_response(threats):
    """
    Generate recommended defensive actions
    based on detected threat severity.
    """

    responses = []

    for threat in threats:

        severity = threat.get("severity", "LOW")
        threat_type = threat.get(
            "threat_type",
            "Unknown Threat"
        )

        if severity == "CRITICAL":
            action = "Block source and investigate immediately."
            priority = "IMMEDIATE"

        elif severity == "HIGH":
            action = "Restrict suspicious traffic and investigate."
            priority = "HIGH"

        elif severity == "MEDIUM":
            action = "Monitor traffic and perform further analysis."
            priority = "MEDIUM"

        else:
            action = "Continue monitoring the activity."
            priority = "LOW"

        responses.append({
            "log_id": threat.get("log_id"),
            "threat_type": threat_type,
            "severity": severity,
            "priority": priority,
            "recommended_action": action
        })

    return {
        "status": "success",
        "total_responses": len(responses),
        "responses": responses
    }