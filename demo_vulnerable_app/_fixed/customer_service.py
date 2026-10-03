"""
Customer Service module — FIXED version (demo).

All logging statements have been updated to use non-sensitive identifiers only.
No PII is written to logs.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Customer:
    customer_id: str
    email: str
    phone: str
    ic_number: str

    def __str__(self) -> str:
        # FIX: __str__ now exposes only the non-sensitive customer_id
        return f"Customer(id={self.customer_id})"


def _load_customer(customer_id: str) -> Customer:
    """Simulate loading a customer from the database."""
    # FIX: hardcoded test values replaced with generic non-PII placeholders
    return Customer(
        customer_id=customer_id,
        email="[redacted]",
        phone="[redacted]",
        ic_number="[redacted]",
    )


def _send_notification(customer: Customer, message: str) -> None:
    """Send a notification to the customer's registered email."""
    logger.debug("Dispatching notification to customer_id=%s", customer.customer_id)


def process_customer(customer_id: str = "CUST-001") -> None:
    """
    Main entry point: load and process a customer record.

    FIX A — log only customer_id instead of the raw email field.
    FIX B — Customer.__str__ no longer includes sensitive fields.
    """
    customer = _load_customer(customer_id)

    # FIX A: log the non-sensitive customer_id only
    logger.info("Processing customer customer_id=%s", customer.customer_id)

    _send_notification(customer, "Your request has been received.")
    logger.info("Customer processing complete customer_id=%s", customer.customer_id)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    process_customer()
