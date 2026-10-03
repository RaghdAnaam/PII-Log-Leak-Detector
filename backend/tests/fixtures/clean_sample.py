import logging

logger = logging.getLogger(__name__)

def calculate_total(items):
    """Calculate the total price of items."""
    total = sum(item.price for item in items)
    logger.info("Total calculated: %s items processed", len(items))
    return total

def format_currency(amount):
    return f"RM {amount:.2f}"
