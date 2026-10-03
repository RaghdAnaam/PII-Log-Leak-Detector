"""
Tests for all masker functions.
"""
from backend.app.masking.maskers import (
    mask_account_number,
    mask_card_number,
    mask_email,
    mask_ic,
    mask_phone,
)


def test_mask_email():
    assert mask_email("john.doe@example.com") == "j***@example.com"
    assert "@" in mask_email("a@b.com")
    assert mask_email("") == "***"  # graceful edge case


def test_mask_email_single_char_local():
    result = mask_email("a@b.com")
    assert result == "a***@b.com"


def test_mask_phone():
    result = mask_phone("+60 12-345 6789")
    assert "***" in result or "*" in result
    assert result != "+60 12-345 6789"


def test_mask_phone_contains_stars():
    result = mask_phone("+60 11-2233 4455")
    assert "*" in result


def test_mask_ic():
    result = mask_ic("901231-14-5678")
    assert "901231" in result        # year/month/day visible
    assert "****" in result or "**" in result


def test_mask_ic_plain():
    result = mask_ic("901231145678")
    assert "901231" in result
    assert "*" in result


def test_mask_card_number():
    result = mask_card_number("4111 1111 1111 1111")
    assert "4111" in result         # first group visible
    assert "1111" in result         # last group visible
    assert "****" in result         # middle masked


def test_mask_card_number_hyphens():
    result = mask_card_number("4111-1111-1111-1111")
    assert "4111" in result
    assert "1111" in result
    assert "****" in result


def test_mask_account_number():
    result = mask_account_number("ACC-1234567890")
    assert "***" in result or "*" in result
    assert result != "ACC-1234567890"


def test_mask_account_number_keeps_suffix():
    """Last 4 chars of the numeric part should be visible."""
    result = mask_account_number("ACC-1234567890")
    # The number part is "1234567890"; last 4 = "7890"
    assert "7890" in result


def test_mask_account_number_empty():
    result = mask_account_number("")
    assert result == "***"
