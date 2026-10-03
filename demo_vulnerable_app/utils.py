"""
Utilities module — VULNERABLE version (demo).

This file intentionally leaks PII via print() debug statements for demo purposes.
All data is synthetic/fake.
"""


def validate_ic(ic_number: str) -> bool:
    """
    Validate a Malaysian IC number format.

    VULNERABILITY F — IC number written to stdout via print() debug statement.
    """
    # VULNERABILITY F: raw IC number printed for debugging
    print(f"[DEBUG] Validating IC: {ic_number}")

    parts = ic_number.split("-")
    if len(parts) != 3:
        return False
    dob, state, seq = parts
    return len(dob) == 6 and len(state) == 2 and len(seq) == 4


def send_notification_email(customer_id: str, email: str, message: str) -> bool:
    """
    Queue a notification email to the given address.

    VULNERABILITY G — recipient email address written to stdout via print().
    """
    # VULNERABILITY G: raw email address printed for debugging
    print(f"[DEBUG] Sending to: {email}")

    # Simulated send — returns True on success
    return True


if __name__ == "__main__":
    ic = "901231-14-5678"
    is_valid = validate_ic(ic)
    print(f"IC valid: {is_valid}")

    ok = send_notification_email(
        customer_id="CUST-001",
        email="jane.smith@testmail.com",
        message="Your account has been updated.",
    )
    print(f"Notification sent: {ok}")
