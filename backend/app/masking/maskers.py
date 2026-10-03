import re


def mask_email(value: str) -> str:
    """j***@example.com — masks local part keeping only the first character."""
    if not value or "@" not in value:
        return "***"
    local, _, domain = value.partition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


def mask_phone(value: str) -> str:
    """Keep first 4 chars, mask the rest with *, keep last 2: +601*****89"""
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
    """901231-**-**** — masks PB (state) and XXXX (sequence) parts."""
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
    """4111 **** **** 1111 — shows first and last group only."""
    digits = re.sub(r"\D", "", value)
    if len(digits) < 8:
        return "**** **** **** ****"
    first4 = digits[:4]
    last4 = digits[-4:]
    return f"{first4} **** **** {last4}"


def mask_account_number(value: str) -> str:
    """ACC-******7890 — masks all but last 4 characters of the numeric/alphanumeric part."""
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
