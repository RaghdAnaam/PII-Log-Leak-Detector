"""
Tests for all five PII detectors, parametrised.
"""
import pytest

from backend.app.detectors.account_number_detector import AccountNumberDetector
from backend.app.detectors.credit_card_detector import CreditCardDetector
from backend.app.detectors.email_detector import EmailDetector
from backend.app.detectors.ic_detector import ICDetector
from backend.app.detectors.phone_detector import PhoneDetector

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_email_detector = EmailDetector()
_phone_detector = PhoneDetector()
_ic_detector = ICDetector()
_card_detector = CreditCardDetector()
_account_detector = AccountNumberDetector()


# ---------------------------------------------------------------------------
# Email detector
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected_count", [
    ('Email: john.doe@example.com', 1),
    ('No email here', 0),
    ('Two emails: a@b.com and c@d.org', 2),
    ('Not an email: @nodomain', 0),
    ('logger.info("user: john.doe@example.com")', 1),
])
def test_email_detector(text, expected_count):
    findings = _email_detector.detect(text)
    assert len(findings) == expected_count, (
        f"Expected {expected_count} email finding(s) in {text!r}, got {len(findings)}"
    )


def test_email_detector_masked_differs_from_matched():
    """Masked value must differ from the original matched value."""
    findings = _email_detector.detect('Email: john.doe@example.com')
    assert len(findings) == 1
    f = findings[0]
    assert f.matched_value != f.masked_value


# ---------------------------------------------------------------------------
# Phone detector
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,min_count", [
    ('+60 12-345 6789', 1),
    ('No phone here', 0),
    ('+60 11-2233 4455', 1),
])
def test_phone_detector(text, min_count):
    findings = _phone_detector.detect(text)
    assert len(findings) >= min_count, (
        f"Expected at least {min_count} phone finding(s) in {text!r}, got {len(findings)}"
    )


def test_phone_detector_masked_differs_from_matched():
    findings = _phone_detector.detect('+60 12-345 6789')
    assert len(findings) >= 1
    f = findings[0]
    assert f.matched_value != f.masked_value


# ---------------------------------------------------------------------------
# IC detector
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected_count", [
    ('IC: 901231-14-5678', 1),
    ('No IC here', 0),
    ('901231145678', 1),   # without hyphens
])
def test_ic_detector(text, expected_count):
    findings = _ic_detector.detect(text)
    assert len(findings) == expected_count, (
        f"Expected {expected_count} IC finding(s) in {text!r}, got {len(findings)}"
    )


def test_ic_detector_masked_differs_from_matched():
    findings = _ic_detector.detect('IC: 901231-14-5678')
    assert len(findings) == 1
    f = findings[0]
    assert f.matched_value != f.masked_value


# ---------------------------------------------------------------------------
# Credit card detector
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected_count", [
    ('Card: 4111 1111 1111 1111', 1),
    ('No card here', 0),
    ('4111-1111-1111-1111', 1),
])
def test_credit_card_detector(text, expected_count):
    findings = _card_detector.detect(text)
    assert len(findings) == expected_count, (
        f"Expected {expected_count} card finding(s) in {text!r}, got {len(findings)}"
    )


def test_credit_card_detector_masked_differs_from_matched():
    findings = _card_detector.detect('Card: 4111 1111 1111 1111')
    assert len(findings) == 1
    f = findings[0]
    assert f.matched_value != f.masked_value


# ---------------------------------------------------------------------------
# Account number detector
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected_count", [
    ('account: ACC-1234567890', 1),
    ('No account here', 0),
    ('account_number: 1234567890', 1),
])
def test_account_number_detector(text, expected_count):
    findings = _account_detector.detect(text)
    assert len(findings) == expected_count, (
        f"Expected {expected_count} account finding(s) in {text!r}, got {len(findings)}"
    )


def test_account_number_detector_masked_differs_from_matched():
    findings = _account_detector.detect('account: ACC-1234567890')
    assert len(findings) == 1
    f = findings[0]
    assert f.matched_value != f.masked_value
