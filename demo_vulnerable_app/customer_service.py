"""
Customer Service module — VULNERABLE version (demo).

This file intentionally leaks PII through logging statements for demo purposes.
All data is synthetic/fake.
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
        # BUG: __str__ exposes sensitive fields — logged below
        return (
            f"Customer(id={self.customer_id}, email={self.email}, "
            f"phone={self.phone}, ic={self.ic_number})"
        )


def _load_customer(customer_id: str) -> Customer:
    """Simulate loading a customer from the database."""
    # In production this would be a DB query; here we return a mock record.
    return Customer(
        customer_id=customer_id,
        email="john.doe@example.com",
        phone="+60 12-345 6789",
        ic_number="901231-14-5678",
    )


def _send_notification(customer: Customer, message: str) -> None:
    """Send a notification to the customer's registered email."""
    logger.debug("Dispatching notification to customer_id=%s", customer.customer_id)
    # ... notification dispatch logic ...


def process_customer(customer_id: str = "CUST-001") -> None:
    """
    Main entry point: load and process a customer record.

    VULNERABILITY A — direct field logging: logs the raw email address.
    VULNERABILITY B — object logging: Customer.__str__ exposes email + phone + IC.
    """
    customer = _load_customer(customer_id)

    # VULNERABILITY A: raw email field in log message
    logger.info(f"Processing customer email: {customer.email}")

    # VULNERABILITY B: str(customer) contains email, phone and IC number
    logger.info(f"Processing customer: {customer}")

    _send_notification(customer, "Your request has been received.")
    logger.info("Customer processing complete customer_id=%s", customer.customer_id)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    process_customer()
