"""
PII masking functions.

Each function takes a raw PII string and returns a safe, partially-redacted
display string. Masking is:
- **One-way** — the original value cannot be recovered from the masked form.
- **Deterministic** — the same input always produces the same masked output.
- **Consistent** — enough structure is preserved to confirm the PII type without
  exposing the full value (e.g. first character of an email, date-of-birth from IC).

These functions are called by detectors immediately on match. The raw value is
stored only in the internal :class:`Finding` model and is never serialised to
the API or printed to the CLI.
"""

import re


def mask_email(value: str) -> str:
    """Return a masked email address, e.g. ``john@example.com`` → ``j***@example.com``.

    Preserves the first character of the local part and the full domain so the
    address can be identified as an email without revealing the account name.

    Args:
        value: A raw email address string.

    Returns:
        A masked string such as ``j***@example.com``. Returns ``"***"`` if
        *value* is empty or contains no ``@`` character.
    """
    if not value or "@" not in value:
        return "***"
    local, _, domain = value.partition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


def mask_phone(value: str) -> str:
    """Return a masked phone number, e.g. ``+60121234567`` → ``+601*****67``.

    Preserves the first 4 characters (typically country code + operator prefix)
    and the last 2 characters, masking everything in between with ``*``.

    Args:
        value: A raw phone number string (may include spaces, dashes, parentheses).

    Returns:
        A masked string such as ``+601*****67``. Returns ``"***"`` if the digit
        count is less than 4.
    """
    # Strip to digits only for length check, but operate on original
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "***"
    # Work on the raw value: keep first 4 chars, keep last 2 chars, mask middle
    if len(value) <= 6:
        return value[:2] + "*" * (len(value) - 2)
    prefix = value[:4]
    suffix = value[-2:]
    middle_len = len(value) - 6
    return f"{prefix}{'*' * middle_len}{suffix}"


def mask_ic(value: str) -> str:
    """Return a masked Malaysian IC number, e.g. ``901231-14-5678`` → ``901231-**-****``.

    Preserves only the date-of-birth portion (``YYMMDD``). The state/country code
    and sequence number are fully redacted, preventing re-identification while
    confirming the approximate age of the subject.

    Args:
        value: A Malaysian IC number string, with or without hyphen separators.

    Returns:
        A masked string such as ``901231-**-****``. Falls back gracefully for
        shorter-than-expected inputs.
    """
    # Remove all separators to normalise
    clean = re.sub(r"[-\s]", "", value)
    if len(clean) < 12:
        # Best-effort: keep first 6, mask rest
        if len(clean) >= 6:
            return clean[:6] + "-**-****"
        return "******-**-****"
    yymmdd = clean[:6]
    return f"{yymmdd}-**-****"


def mask_card_number(value: str) -> str:
    """Return a masked payment card number, e.g. ``4111111111111111`` → ``4111 **** **** 1111``.

    Follows the PCI-DSS convention of showing only the first 6 and last 4 digits
    (this implementation shows the first 4 and last 4 for simplicity). Spaces are
    used as separators regardless of the original format.

    Args:
        value: A raw card number string (digits only or grouped with spaces/hyphens).

    Returns:
        A masked string such as ``4111 **** **** 1111``. Returns
        ``"**** **** **** ****"`` if fewer than 8 digits are present.
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) < 8:
        return "**** **** **** ****"
    first4 = digits[:4]
    last4 = digits[-4:]
    return f"{first4} **** **** {last4}"


def mask_account_number(value: str) -> str:
    """Return a masked account number, e.g. ``ACC-1234567890`` → ``ACC-******7890``.

    Preserves an optional alphabetic prefix (e.g. ``ACC-``, ``SA``) and the last
    4 characters of the numeric/alphanumeric portion, masking the rest with ``*``.

    Args:
        value: The account number capture (the value portion, not the keyword context).

    Returns:
        A masked string such as ``ACC-******7890``. Returns ``"***"`` for empty input.
        For values of 4 characters or fewer, the entire value is masked.
    """
    if not value:
        return "***"
    # Determine if there's a prefix (letters/dashes before the number)
    match = re.match(r"^([A-Za-z]+[-_]?)(.+)$", value)
    if match:
        prefix = match.group(1)
        number = match.group(2)
    else:
        prefix = ""
        number = value

    if len(number) <= 4:
        return f"{prefix}{'*' * len(number)}"

    visible = number[-4:]
    masked_part = "*" * (len(number) - 4)
    return f"{prefix}{masked_part}{visible}"
