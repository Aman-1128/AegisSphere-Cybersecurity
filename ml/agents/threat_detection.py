import pandas as pd


def detect_threats(model, feature_names, df):
    """
    Run the trained ML model against security logs
    and return threat classifications.
    """

    # Normalize column names
    df.columns = df.columns.str.strip()

    # Check required features
    missing_features = [
        feature
        for feature in feature_names
        if feature not in df.columns
    ]

    if missing_features:
        return {
            "status": "error",
            "message": "Required features are missing",
            "missing_features": missing_features
        }

    # Select features in the same order used during training
    X = df[feature_names].copy()

    # Convert values to numeric
    X = X.apply(pd.to_numeric, errors="coerce")

    # Replace invalid/missing values
    X = X.fillna(0)

    # Generate predictions
    predictions = model.predict(X)

    # Generate confidence scores
    probabilities = model.predict_proba(X)

    results = []

    for prediction, probability in zip(predictions, probabilities):

        if prediction == 1:
            label = "ATTACK"
        else:
            label = "BENIGN"

        confidence = float(max(probability))

        results.append({
            "prediction": label,
            "confidence": round(confidence, 4)
        })

    # Count results
    attack_count = sum(
        1
        for result in results
        if result["prediction"] == "ATTACK"
    )

    benign_count = len(results) - attack_count

    return {
        "status": "success",
        "total_logs": len(results),
        "attack_count": attack_count,
        "benign_count": benign_count,
        "results": results
    }