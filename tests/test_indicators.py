from datetime import date, datetime

from risk_engine.indicators import derive_indicators


def test_expired_and_recalled_flags():
    batch = {
        "expiry_date": date(2025, 1, 1),
        "batch_status": "recalled",
    }

    indicators = derive_indicators(batch, [], today=date(2026, 10, 22))

    assert indicators["expired_batch"] == 1.0
    assert indicators["recalled_batch"] == 1.0


def test_repeated_failures_are_detected():
    batch = {
        "expiry_date": date(2027, 1, 1),
        "batch_status": "active",
    }
    records = [
        {
            "verification_result": "failure",
            "verified_at": datetime(2026, 10, 20, 10, minute),
            "verification_location": "Location B",
            "device_reference": "DEVICE-010",
        }
        for minute in (0, 1, 2)
    ]

    indicators = derive_indicators(batch, records, today=date(2026, 10, 22))

    assert indicators["repeated_failures"] == 1.0
    assert indicators["duplicate_activity"] == 1.0


def test_location_change_is_flagged():
    batch = {
        "expiry_date": date(2027, 1, 1),
        "batch_status": "active",
    }
    records = [
        {
            "verification_result": "success",
            "verified_at": datetime(2026, 10, 20, 10, 0),
            "verification_location": "Location B",
            "device_reference": "DEVICE-001",
        },
        {
            "verification_result": "success",
            "verified_at": datetime(2026, 10, 20, 10, 2),
            "verification_location": "Location C",
            "device_reference": "DEVICE-001",
        },
    ]

    indicators = derive_indicators(batch, records, today=date(2026, 10, 22))

    assert indicators["time_location_inconsistency"] == 1.0
