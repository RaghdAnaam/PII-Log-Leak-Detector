"""
Payments module — FIXED version (demo).

All logging statements have been updated to use non-sensitive identifiers only.
No PII is written to logs.
"""

import logging
import uuid

logger = logging.getLogger(__name__)


def _generate_transaction_ref() -> str:
    return f"TXN-{uuid.uuid4().hex[:8].upper()}"


def process_payment(amount: float, currency: str = "MYR") -> dict:
    """
    Charge a customer's card.

    FIX C — log a transaction reference instead of the raw card value.
    """
    # FIX C: card value is no longer hardcoded — retrieved from a secure vault in production
    transaction_ref = _generate_transaction_ref()

    # FIX C: log only the transaction reference, never the card value
    logger.info("Processing payment transaction_ref=%s", transaction_ref)

    logger.debug("Sending charge request transaction_ref=%s amount=%.2f %s",
                 transaction_ref, amount, currency)

    return {"status": "success", "transaction_ref": transaction_ref}


def transfer_funds(amount: float, currency: str = "MYR") -> dict:
    """
    Transfer funds from a source account.

    FIX D — log a masked token instead of the raw identifier.
    """
    # FIX D: raw identifier is no longer hardcoded
    masked_ref = "ACCT-****XXXX"
    transaction_ref = _generate_transaction_ref()

    # FIX D: log only the masked token, never the full identifier
    logger.info("Transfer initiated masked_ref=%s", masked_ref)

    logger.debug("Transfer queued transaction_ref=%s amount=%.2f %s",
                 transaction_ref, amount, currency)

    return {"status": "initiated", "transaction_ref": transaction_ref}


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    process_payment(199.90)
    transfer_funds(500.00)
