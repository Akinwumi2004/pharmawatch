
"""Transparent weighted risk-scoring model for the prototype.

Weights and thresholds are initial development parameters. They must
be evaluated and documented before being presented as validated.
"""


INDICATOR_WEIGHTS = {
    "repeated_failures": 0.25,
    "high_frequency": 0.15,
    "duplicate_activity": 0.15,
    "time_location_inconsistency": 0.15,
    "expired_batch": 0.10,
    "recalled_batch": 0.20,
}

# Weights sum to 1.0. Each indicator is expected to be in [0, 1].
RISK_THRESHOLDS = {
    "medium": 30.0,
    "high": 60.0,
}


def calculate_risk(indicators):
    """Return score, risk level, priority and indicator contributions.

    This is a surveillance-prioritisation aid, not a determination
    that a medicine is counterfeit.
    """
    missing = set(INDICATOR_WEIGHTS) - set(indicators)
    if missing:
        raise ValueError(
            f"Missing risk indicators: {', '.join(sorted(missing))}"
        )

    contributions = {}

    for name, weight in INDICATOR_WEIGHTS.items():
        value = float(indicators[name])

        if not 0.0 <= value <= 1.0:
            raise ValueError(
                f"Indicator '{name}' must be between 0 and 1."
            )

        contributions[name] = round(weight * value * 100, 2)

    score = round(sum(contributions.values()), 2)

    if score >= RISK_THRESHOLDS["high"]:
        level = "high"
    elif score >= RISK_THRESHOLDS["medium"]:
        level = "medium"
    else:
        level = "low"

    # Expired/recalled status is escalated separately in the application.
    
    if indicators["recalled_batch"] == 1.0:
        priority = "urgent_review"
    elif indicators["expired_batch"] == 1.0:
        priority = "urgent_review"
    elif level == "high":
        priority = "high"
    elif level == "medium":
        priority = "medium"
    else:
        priority = "routine"
    return {
        "risk_score": score,
        "risk_level": level,
        "surveillance_priority": priority,
        "contributions": contributions,
    }
