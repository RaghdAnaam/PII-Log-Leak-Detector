"""
Utilities module — FIXED version (demo).

All print() debug statements have been updated to use non-sensitive identifiers only.
No PII is written to stdout or logs.
"""


def validate_ic(ic_number: str, customer_id: str = "unknown") -> bool:
    """
    Validate a Malaysian IC number format.

    FIX F — print only the customer_id, never the raw IC number.
    """
    # FIX F: reference customer_id only, not the IC number
    print(f"[DEBUG] IC validation complete for customer_id={customer_id}")

    parts = ic_number.split("-")
    if len(parts) != 3:
        return False
    dob, state, seq = parts
    return len(dob) == 6 and len(state) == 2 and len(seq) == 4


def send_notification_email(customer_id: str, email: str, message: str) -> bool:
    """
    Queue a notification email to the given address.

    FIX G — print only the customer_id, never the raw email address.
    """
    # FIX G: reference customer_id only, not the email address
    print(f"[DEBUG] Notification queued for customer_id={customer_id}")

    return True


if __name__ == "__main__":
    ic = "[redacted-ic]"
    is_valid = validate_ic(ic, customer_id="CUST-001")
    print(f"IC valid: {is_valid}")

    ok = send_notification_email(
        customer_id="CUST-001",
        email="[redacted]",
        message="Your account has been updated.",
    )
    print(f"Notification sent: {ok}")
