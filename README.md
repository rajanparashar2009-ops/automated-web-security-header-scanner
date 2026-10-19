# Automated Web Scanner

A beginner-friendly Python tool that checks common HTTP security headers and performs a basic, non-invasive CORS configuration check.

## Features
- Checks for six common security headers.
- Makes a basic `OPTIONS` request using a synthetic test origin.
- Prints a readable terminal report.
- Optionally saves results as JSON.
- Uses timeouts and does not attempt exploitation.

## Requirements
- Python 3.10 or newer recommended
- Internet connection
- `requests` Python package

## Setup

### Windows
1. Install Python from https://www.python.org/downloads/ and select **Add Python to PATH** during installation.
2. Open Command Prompt in this project folder.
3. Run:

```bash
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run the scanner

```bash
python scanner.py https://example.com
```

On Windows, `py scanner.py https://example.com` also works.

Save a JSON report:

```bash
python scanner.py https://example.com --json report.json
```

Set a longer timeout:

```bash
python scanner.py https://example.com --timeout 20
```

## Understanding results
- **PRESENT** means the response included the header.
- **MISSING** means it was not seen in that response; it does not automatically prove a vulnerability.
- CORS behavior can vary by endpoint, request type, and server. Treat results as a first-pass indicator and manually review the site's intended access policy.
- `Access-Control-Allow-Origin: *` can be valid for public resources. The tool flags wildcard origin plus credentials for review, but does not make a final security verdict.

## Ethical use
Only scan websites you own or have explicit permission to assess. This project performs basic checks only; it is not a full penetration-testing tool. Respect site terms, privacy, and applicable laws.

## Project structure

```text
automated-web-scanner/
├── scanner.py
├── requirements.txt
├── README.md
└── Project_Report.pdf
```

## Author
Student Project — Automated Web Scanner
