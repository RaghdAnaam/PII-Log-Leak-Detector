"""
Error handling module — VULNERABLE version (demo).

This file intentionally leaks PII via exception logging for demo purposes.
All data is synthetic/fake.
"""

import logging

logger = logging.getLogger(__name__)


def _call_external_api(payload: dict) -> dict:
    """Simulate a call to an external service that occasionally fails."""
    # Simulated transient failure for demo purposes
    raise ConnectionError("upstream timeout after 30s")


def handle_customer_request(customer_id: str = "CUST-002") -> dict:
    """
    Handle an inbound customer request by calling an external API.

    VULNERABILITY E — full request payload (containing phone number) is logged
                      inside the except block when the upstream call fails.
    """
    request_payload = {
        "customer_id": customer_id,
        "action": "update_profile",
        "phone": "+60 11-2233 4455",
        "channel": "web",
    }

    try:
        response = _call_external_api(request_payload)
        logger.info("Request succeeded customer_id=%s", customer_id)
        return response
    except Exception as e:  # noqa: BLE001
        # VULNERABILITY E: request_payload contains sensitive phone number
        logger.error(f"Request failed for customer: {request_payload}")
        return {"status": "error", "message": str(e)}


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    result = handle_customer_request()
    print(result)
