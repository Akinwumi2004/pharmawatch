from datetime import date, datetime, timedelta


INDICATOR_NAMES = (
    "repeated_failures",
    "high_frequency",
    "duplicate_activity",
    "time_location_inconsistency",
    "expired_batch",
    "recalled_batch",
)


def derive_indicators(batch, records, today=None):
    """Derive transparent prototype indicators from batch and event data.

    records must contain verification_result, verified_at,
    verification_location, and device_reference.

    These initial detection rules are for simulated-data evaluation,
    not validated counterfeit-detection rules.
    """
    today = today or date.today()

    expiry = batch.get("expiry_date")
    if isinstance(expiry, datetime):
        expiry = expiry.date()

    if isinstance(expiry, str):
        expiry = date.fromisoformat(expiry)

    status = (batch.get("batch_status") or "active").lower()

    parsed_records = []
    for record in records:
        timestamp = record["verified_at"]
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        parsed_records.append({
            **record,
            "verified_at": timestamp,
        })

    # Count verification events in the most recent 24 hours
    # relative to the latest event in this batch's dataset.
    if parsed_records:
        latest = max(r["verified_at"] for r in parsed_records)
        window_start = latest - timedelta(hours=24)
        recent = [
            r for r in parsed_records
            if window_start <= r["verified_at"] <= latest
        ]
    else:
        recent = []

    failures = sum(
        r["verification_result"] == "failure"
        for r in recent
    )

    # Prototype normalization: 3 or more failures saturate at 1.
    repeated_failures = min(failures / 3, 1.0)

    # Prototype frequency rule: up to 3 events is baseline;
    # 10 or more events in the window saturates at 1.
    high_frequency = min(max(len(recent) - 3, 0) / 7, 1.0)

    # Duplicate activity: same non-empty device reference, same batch,
    # with events no more than 2 minutes apart.
    duplicate_activity = 0.0
    for i, first in enumerate(recent):
        device = first.get("device_reference")
        if not device:
            continue

        for second in recent[i + 1:]:
            if (
                second.get("device_reference") == device
                and abs(
                    (second["verified_at"] - first["verified_at"])
                    .total_seconds()
                ) <= 120
            ):
                duplicate_activity = 1.0
                break

        if duplicate_activity:
            break

    # Prototype inconsistency rule: different known locations for the
    # same device within 5 minutes. This is only a flag for review.
    time_location_inconsistency = 0.0
    for i, first in enumerate(recent):
        device = first.get("device_reference")
        location = first.get("verification_location")

        if not device or not location:
            continue

        for second in recent[i + 1:]:
            if (
                second.get("device_reference") == device
                and second.get("verification_location")
                and second["verification_location"] != location
                and abs(
                    (second["verified_at"] - first["verified_at"])
                    .total_seconds()
                ) <= 300
            ):
                time_location_inconsistency = 1.0
                break

        if time_location_inconsistency:
            break

    return {
        "repeated_failures": round(repeated_failures, 3),
        "high_frequency": round(high_frequency, 3),
        "duplicate_activity": duplicate_activity,
        "time_location_inconsistency": time_location_inconsistency,
        "expired_batch": float(expiry is not None and expiry < today),
        "recalled_batch": float(status == "recalled"),
    }