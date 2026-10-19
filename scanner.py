#!/usr/bin/env python3
"""
Automated Web Scanner
Checks HTTP security headers and performs a basic, non-invasive CORS misconfiguration check.

Use only on websites you own or have explicit permission to test.
This tool makes ordinary HTTP requests and does not exploit vulnerabilities.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Encourages HTTPS-only connections.",
    "Content-Security-Policy": "Helps reduce certain injection and XSS risks.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "X-Frame-Options": "Helps prevent clickjacking in older browser support.",
    "Referrer-Policy": "Controls how much referrer information is sent.",
    "Permissions-Policy": "Controls access to selected browser features.",
}

TEST_ORIGIN = "https://scanner-test.invalid"


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Enter a valid http:// or https:// URL.")
    return value


def scan(url: str, timeout: float = 10.0) -> dict:
    headers = {
        "User-Agent": "AutomatedWebScanner/1.0 (educational security audit)"
    }
    result = {
        "target": url,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "http_status": None,
        "final_url": None,
        "https": urlparse(url).scheme == "https",
        "security_headers": {},
        "cors": {},
        "notes": [],
    }

    try:
        response = requests.get(
            url, headers=headers, timeout=timeout, allow_redirects=True
        )
        result["http_status"] = response.status_code
        result["final_url"] = response.url
        response_headers = response.headers

        for header, description in SECURITY_HEADERS.items():
            value = response_headers.get(header)
            result["security_headers"][header] = {
                "present": value is not None,
                "value": value,
                "description": description,
            }

        # Send a harmless OPTIONS request with a clearly synthetic Origin.
        # Some servers do not support OPTIONS; that is reported as inconclusive.
        try:
            options_response = requests.options(
                response.url,
                headers={
                    **headers,
                    "Origin": TEST_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                },
                timeout=timeout,
                allow_redirects=True,
            )
            cors_headers = options_response.headers
            allow_origin = cors_headers.get("Access-Control-Allow-Origin")
            allow_credentials = cors_headers.get("Access-Control-Allow-Credentials", "")
            result["cors"] = {
                "options_status": options_response.status_code,
                "access_control_allow_origin": allow_origin,
                "access_control_allow_credentials": allow_credentials,
                "allows_test_origin": allow_origin == TEST_ORIGIN or allow_origin == "*",
                "wildcard_with_credentials_warning": (
                    allow_origin == "*" and allow_credentials.lower() == "true"
                ),
                "note": (
                    "A wildcard origin may be appropriate for public resources. "
                    "Review context and authentication requirements before concluding."
                ),
            }
        except requests.RequestException as exc:
            result["cors"] = {
                "inconclusive": True,
                "error": str(exc),
                "note": "The OPTIONS request failed; CORS behavior could not be assessed.",
            }

        if result["https"] is False:
            result["notes"].append(
                "Target was entered with HTTP rather than HTTPS. Verify HTTPS availability."
            )
        if response.status_code >= 400:
            result["notes"].append(
                "The target returned an HTTP error status; findings may be incomplete."
            )
        result["notes"].append(
            "Missing headers are review items, not proof of a vulnerability. "
            "Choose controls appropriate to the website."
        )
    except requests.RequestException as exc:
        result["error"] = str(exc)

    return result


def print_report(report: dict) -> None:
    print("\n=== Automated Web Scanner ===")
    print(f"Target: {report['target']}")
    if report.get("error"):
        print(f"Request failed: {report['error']}")
        return

    print(f"HTTP status: {report['http_status']}")
    print(f"Final URL: {report['final_url']}")
    print(f"HTTPS used: {'Yes' if report['https'] else 'No'}")
    print("\nSecurity headers:")
    for name, item in report["security_headers"].items():
        status = "PRESENT" if item["present"] else "MISSING"
        print(f"  [{status}] {name}")
        if item["value"]:
            print(f"      Value: {item['value']}")

    print("\nBasic CORS check:")
    cors = report.get("cors", {})
    if cors.get("inconclusive"):
        print(f"  Inconclusive: {cors.get('error', 'No result')}")
    else:
        print(f"  OPTIONS status: {cors.get('options_status')}")
        print(f"  Access-Control-Allow-Origin: "
              f"{cors.get('access_control_allow_origin') or '(not returned)'}")
        print(f"  Access-Control-Allow-Credentials: "
              f"{cors.get('access_control_allow_credentials') or '(not returned)'}")
        if cors.get("wildcard_with_credentials_warning"):
            print("  WARNING: wildcard origin and credentials were both reported.")

    if report.get("notes"):
        print("\nNotes:")
        for note in report["notes"]:
            print(f"  - {note}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit security headers and basic CORS behavior on an authorized website."
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", dest="json_path",
                        help="Optional path to save full results as JSON")
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    try:
        url = normalize_url(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    report = scan(url, args.timeout)
    print_report(report)

    if args.json_path:
        try:
            with open(args.json_path, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=2, ensure_ascii=False)
            print(f"\nJSON report saved to: {args.json_path}")
        except OSError as exc:
            print(f"Could not save JSON report: {exc}", file=sys.stderr)
            return 2

    return 1 if report.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
