"""
Error handling module — FIXED version (demo).

All logging statements have been updated to use non-sensitive identifiers only.
No PII is written to logs.
"""

import logging

logger = logging.getLogger(__name__)


def _call_external_api(payload: dict) -> dict:
    """Simulate a call to an external service that occasionally fails."""
    raise ConnectionError("upstream timeout after 30s")


def handle_customer_request(customer_id: str = "CUST-002") -> dict:
    """
    Handle an inbound customer request by calling an external API.

    FIX E — log only customer_id and the exception type, never the full payload.
    """
    request_payload = {
        "customer_id": customer_id,
        "action": "update_profile",
        "phone": "[redacted]",
        "channel": "web",
    }

    try:
        response = _call_external_api(request_payload)
        logger.info("Request succeeded customer_id=%s", customer_id)
        return response
    except Exception as e:  # noqa: BLE001
        # FIX E: log only the customer_id and the error class, not the raw payload
        logger.error("Request failed customer_id=%s error=%s", customer_id, type(e).__name__)
        return {"status": "error", "message": str(e)}


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    result = handle_customer_request()
    print(result)
