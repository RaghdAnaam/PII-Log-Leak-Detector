"""
Payments module — VULNERABLE version (demo).

This file intentionally leaks payment PII through logging statements for demo purposes.
All data is synthetic/fake.
"""

import logging
import uuid

logger = logging.getLogger(__name__)


def _generate_transaction_ref() -> str:
    return f"TXN-{uuid.uuid4().hex[:8].upper()}"


def process_payment(amount: float, currency: str = "MYR") -> dict:
    """
    Charge a customer's card.

    VULNERABILITY C — credit card number logged in plain text.
    """
    card_number = "4111 1111 1111 1111"
    transaction_ref = _generate_transaction_ref()

    # VULNERABILITY C: raw card number written to log
    logger.info(f"Processing payment for card: {card_number}")

    # Simulate charging; in production this calls a payment gateway
    logger.debug("Sending charge request transaction_ref=%s amount=%.2f %s",
                 transaction_ref, amount, currency)

    return {"status": "success", "transaction_ref": transaction_ref}


def transfer_funds(amount: float, currency: str = "MYR") -> dict:
    """
    Transfer funds from a source account.

    VULNERABILITY D — account number logged in plain text.
    """
    account_number = "ACC-1234567890"
    transaction_ref = _generate_transaction_ref()

    # VULNERABILITY D: raw account number written to log
    logger.info(f"Transferring from account: {account_number}")

    logger.debug("Transfer initiated transaction_ref=%s amount=%.2f %s",
                 transaction_ref, amount, currency)

    return {"status": "initiated", "transaction_ref": transaction_ref}


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    process_payment(199.90)
    transfer_funds(500.00)
