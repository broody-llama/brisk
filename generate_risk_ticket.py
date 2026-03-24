#!/usr/bin/env python3
"""Generate a vendor risk ticket from vendor name + vendor type."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import date, timedelta
from xml.sax.saxutils import escape


_MAX_VENDOR_NAME_LEN = 120
_ALLOWED_VENDOR_NAME = re.compile(r"^[\w .,&()'+\-/]+$")


@dataclass(frozen=True)
class Risk:
    risk_id: int
    title: str
    description: str
    severity: str
    impact: str


RISK_LIBRARY = {
    "saas": [
        Risk(1, "Unauthorized access to vendor tenant", "Weak IAM controls can allow unauthorized access to Block data.", "HIGH", "Data exposure and incident response overhead."),
        Risk(2, "Inadequate encryption controls", "Data may be insufficiently protected in transit or at rest.", "HIGH", "Confidentiality compromise and compliance issues."),
        Risk(3, "Logging and monitoring gaps", "Insufficient audit logging can delay detection of malicious activity.", "MEDIUM", "Longer dwell time and delayed containment."),
        Risk(4, "Vendor outage affects operations", "Service downtime can block business-critical workflows.", "MEDIUM", "Operational disruption and manual fallback burden."),
    ],
    "payments": [
        Risk(1, "Fraud and transaction manipulation", "Weak transaction controls increase fraud risk.", "CRITICAL", "Financial loss and customer trust impact."),
        Risk(2, "PCI scope and compliance drift", "Control failures may violate PCI obligations.", "HIGH", "Regulatory findings and remediation costs."),
        Risk(3, "Settlement and reconciliation failures", "Processing or reporting issues can break financial reconciliation.", "HIGH", "Revenue leakage and accounting risk."),
        Risk(4, "Third-party dependency outage", "Upstream failures may interrupt payment flows.", "MEDIUM", "Payment delays and operational incident load."),
    ],
    "analytics": [
        Risk(1, "Excessive data collection", "Analytics integrations may ingest more data than needed.", "HIGH", "Privacy exposure and policy violations."),
        Risk(2, "Cross-border data transfer risk", "Data residency or transfer requirements may not be met.", "HIGH", "Regulatory non-compliance and legal risk."),
        Risk(3, "Model or insight integrity risk", "Poor data quality controls can produce misleading outputs.", "MEDIUM", "Bad decisions and operational inefficiency."),
    ],
    "infrastructure": [
        Risk(1, "Privileged access abuse", "Infrastructure providers often hold broad privileged access.", "CRITICAL", "Large blast radius compromise."),
        Risk(2, "Supply chain vulnerability", "Compromised dependencies or images can propagate risk.", "HIGH", "Widespread service compromise."),
        Risk(3, "Resilience configuration gaps", "Misconfigured backup/DR can increase outage duration.", "HIGH", "Extended downtime and service degradation."),
    ],
}


def _clean_text(value: str, *, max_len: int = 500) -> str:
    """Remove control characters and XML-escape untrusted values."""
    value = value.strip()
    value = "".join(ch for ch in value if ch.isprintable())
    value = re.sub(r"\s+", " ", value)
    value = value[:max_len]
    return escape(value, {"\"": "&quot;", "'": "&apos;"})


def validate_vendor_name(vendor_name: str) -> str:
    cleaned = _clean_text(vendor_name, max_len=_MAX_VENDOR_NAME_LEN)
    if not cleaned:
        raise ValueError("vendor_name must not be empty")
    # Validate against original user intent, not the escaped output
    normalized = re.sub(r"\s+", " ", vendor_name.strip())
    if len(normalized) > _MAX_VENDOR_NAME_LEN:
        raise ValueError(f"vendor_name exceeds max length {_MAX_VENDOR_NAME_LEN}")
    if not _ALLOWED_VENDOR_NAME.match(normalized):
        raise ValueError("vendor_name contains unsupported characters")
    return cleaned


def due_date_for(risks: list[Risk]) -> str:
    highest = "LOW"
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for risk in risks:
        if order.index(risk.severity) > order.index(highest):
            highest = risk.severity

    days = {"CRITICAL": 30, "HIGH": 30, "MEDIUM": 60, "LOW": 90}[highest]
    return str(date.today() + timedelta(days=days))


def build_controls(risks: list[Risk]) -> str:
    status = "Postponed"
    lines: list[str] = ["<controls>"]
    for idx, risk in enumerate(risks, start=1):
        lines.extend(
            [
                f"- Control ID: {idx}",
                f"- Related Risk ID(s): {risk.risk_id}",
                "- Control Description: Implement preventive and detective controls aligned to the risk, documented in vendor security requirements.",
                f"- DRI Status: {status}",
                "- Implementation Notes: Validate through contract clauses, security questionnaire evidence, and annual control review.",
                "",
            ]
        )
    lines.append("</controls>")
    return "\n".join(lines)


def generate_ticket(vendor_name: str, vendor_type: str) -> str:
    vtype = vendor_type.lower()
    if vtype not in RISK_LIBRARY:
        supported = ", ".join(sorted(RISK_LIBRARY.keys()))
        raise ValueError(f"Unsupported vendor type '{vendor_type}'. Supported types: {supported}")

    safe_vendor_name = validate_vendor_name(vendor_name)

    risks = RISK_LIBRARY[vtype]
    due_date = due_date_for(risks)
    created = str(date.today())

    risk_lines = ["<security_risks>"]
    for risk in risks:
        risk_lines.extend(
            [
                f"- Risk ID: {risk.risk_id}",
                f"- Risk Title: {_clean_text(risk.title)}",
                f"- Description: {_clean_text(risk.description)}",
                f"- Severity: {risk.severity}",
                f"- Potential Impact: {_clean_text(risk.impact)}",
                "",
            ]
        )
    risk_lines.append("</security_risks>")

    return "\n".join(
        [
            "<vendor_service_description>",
            f"Vendor {safe_vendor_name} is evaluated as a {vtype} provider supporting Block business operations.",
            "- Data access and integrations must be validated during onboarding.",
            "- Business purpose should be documented by the requesting team.",
            "</vendor_service_description>",
            "",
            *risk_lines,
            "",
            build_controls(risks),
            "",
            "<assignment_and_tracking>",
            "- Assigned To: Unassigned - To be assigned to Block team member",
            f"- Created Date: {created}",
            f"- Due Date: {due_date}",
            "- Status: Open - Pending Review",
            "</assignment_and_tracking>",
            "",
            "<comments_section>",
            "Comments and Discussion:",
            "---",
            "[No comments yet. Team members can add comments here to discuss risks, controls, and implementation status.]",
            "</comments_section>",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate vendor risk tracker ticket XML")
    parser.add_argument("vendor_name", help="Vendor name")
    parser.add_argument("vendor_type", choices=sorted(RISK_LIBRARY.keys()), help="Vendor type")
    args = parser.parse_args()

    try:
        print(generate_ticket(args.vendor_name, args.vendor_type))
    except ValueError as exc:
        raise SystemExit(f"Error: {exc}") from exc


if __name__ == "__main__":
    main()
