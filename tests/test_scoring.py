
import pytest

from risk_engine.scoring import calculate_risk


def clean_indicators():
    return {
        "repeated_failures": 0,
        "high_frequency": 0,
        "duplicate_activity": 0,
        "time_location_inconsistency": 0,
        "expired_batch": 0,
        "recalled_batch": 0,
    }


def test_no_risk_indicators():
    result = calculate_risk(clean_indicators())

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["surveillance_priority"] == "routine"


def test_recalled_batch_has_high_score():
    indicators = clean_indicators()
    indicators["recalled_batch"] = 1

    result = calculate_risk(indicators)

    assert result["risk_score"] == 20
    assert result["risk_level"] == "low"


def test_combined_indicators_can_raise_priority():
    indicators = {
        "repeated_failures": 1,
        "high_frequency": 1,
        "duplicate_activity": 1,
        "time_location_inconsistency": 1,
        "expired_batch": 1,
        "recalled_batch": 1,
    }

    result = calculate_risk(indicators)

    assert result["risk_score"] == 100
    assert result["risk_level"] == "high"
    assert result["surveillance_priority"] == "urgent_review"


def test_rejects_values_outside_range():
    indicators = clean_indicators()
    indicators["high_frequency"] = 2

    with pytest.raises(ValueError):
        calculate_risk(indicators)


def test_rejects_missing_indicators():
    indicators = clean_indicators()
    del indicators["expired_batch"]

    with pytest.raises(ValueError):
        calculate_risk(indicators)
