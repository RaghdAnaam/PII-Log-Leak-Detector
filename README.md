# PII Log Leak Detector

A developer security tool that scans source code and application logs for potential **Personally Identifiable Information (PII)** leaks, traces findings to the relevant source line, and provides remediation guidance.

Built as a portfolio project around **Python, security-aware development, code analysis, API development, testing, and CI/CD**.

---

## Problem

Sensitive information can accidentally end up in application logs during development.

For example:

```python
logger.info(f"Processing {customer}")
```

If `customer` contains an IC number, card number, email, or account number, sensitive data may be written to logs and become accessible to people or systems that do not need access to the original data.

These leaks can also happen indirectly through object logging or exception messages containing request data, making them easy to miss during code review.

---

## Solution

**PII Log Leak Detector** scans a codebase and application logs for potential PII exposure.

For each finding, the tool provides:

* PII type
* Source file
* Line number
* Severity
* Confidence level
* Masked value
* Detection reason
* Recommended remediation

The project demonstrates the complete workflow:

**Scan → Detect → Trace → Fix → Rescan → Clean**

---

## Detected PII

The current detector identifies potential:

* Email addresses
* Phone numbers
* Malaysian IC/NRIC numbers
* Credit/debit card numbers
* Account numbers

Findings are displayed with **masked values** to avoid unnecessarily exposing the detected information.

---

## Key Features

* Scan source code recursively
* Scan application/test-run logs
* Trace findings to source files and line numbers
* Pattern-based PII detection
* Severity and confidence classification
* Masked finding previews
* Remediation recommendations
* CLI built with Typer and Rich
* REST API built with FastAPI
* React dashboard for reviewing findings
* Severity filtering
* Controlled demo remediation
* Automatic rescan after remediation
* Automated backend tests
* Ruff linting
* Docker support
* GitHub Actions CI

---

## Example Results

The project was tested using intentionally vulnerable files containing **mock data**.

### Source Code Scan

```text
16 potential PII leaks detected in 4 files
5 HIGH
11 MEDIUM
```

### Application Log Scan

```text
39 potential PII leaks detected in 1 file
```

### After Demo Remediation

```text
0 potential PII leaks detected
4 files scanned
Clean
```

---

## Dashboard

The React dashboard provides a visual interface for:

* Running the demo scan
* Viewing finding summaries
* Filtering by severity
* Inspecting individual findings
* Viewing masked values and detection details
* Reviewing recommended fixes
* Applying the controlled demo fix
* Confirming a clean rescan

---

## Tech Stack

| Area             | Technologies                          |
| ---------------- | ------------------------------------- |
| Backend          | Python, FastAPI, Pydantic             |
| CLI              | Typer, Rich                           |
| Detection        | Python pattern-based rules            |
| Frontend         | React, TypeScript, Vite, Tailwind CSS |
| Testing          | pytest                                |
| Linting          | Ruff                                  |
| Containerization | Docker, Docker Compose                |
| CI/CD            | GitHub Actions                        |
| Version Control  | Git, GitHub                           |

---

## Project Structure

```text
PII-Log-Leak-Detector/
├── backend/
│   ├── app/
│   └── tests/
├── cli/
├── frontend/
├── demo_vulnerable_app/
├── demo_logs/
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## CLI Usage

Scan a codebase:

```bash
pii-scan scan ./demo_vulnerable_app
```

Scan an application log:

```bash
pii-scan scan-log ./demo_logs/application.log
```

Apply the controlled demo remediation:

```bash
pii-scan fix ./demo_vulnerable_app
```

The demo fix is intentionally restricted to the included vulnerable demo application.

---

## Testing & CI

The project includes automated tests for the detection and application logic.

Verified test result:

```text
69 passed
```

GitHub Actions validates:

* Backend tests
* Ruff linting
* Frontend production build

---

## Security Considerations

The tool is designed to reduce accidental exposure of sensitive information during development.

* Detected values are masked in displayed findings.
* API responses do not expose the original matched value.
* Scanned source code is not executed.
* Demo remediation is restricted to the included demo project.
* The project uses synthetic/mock data for demonstration.

---

## Limitations

Detection is currently **pattern-based**, so the tool can produce false positives or miss PII that does not match the implemented patterns. Generic numeric values, for example, can sometimes be ambiguous.

This project is intended as a **development-time detection and awareness tool**, rather than a replacement for comprehensive enterprise security or data-loss-prevention systems.

---

## Intended Users

The concept is relevant to:

* Developers
* Security engineers
* Compliance teams
* Data-protection teams

The goal is to catch potential log leaks **during development**, before sensitive information reaches production logging systems.

---

## Project Purpose

This project demonstrates a practical security-focused development workflow:

**Python → PII Detection → Code Analysis → API → React Dashboard → Testing → CI/CD**

It was developed as a portfolio project based on the **PII Log Leak Detector** use case for the Developer Kaki × IBM Bob challenge.
