# Line 1: comment
# Line 2: import
import logging

logger = logging.getLogger(__name__)

# Line 5: function definition
def process_user():
    # Line 7: email leak
    logger.info("User email: john.doe@example.com")
    # Line 9: phone leak
    logger.error("Phone: +60 12-345 6789")
    # Line 11: IC leak
    logger.warning("IC: 901231-14-5678")
    # Line 13: credit card leak
    logger.debug("Card: 4111 1111 1111 1111")
    # Line 15: account number
    logger.info("account: ACC-1234567890")
