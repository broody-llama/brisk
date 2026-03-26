"""AI-assisted generation engine for Brisk risk/control tracker output.

Uses LLM when configured, otherwise falls back to deterministic extraction
from pasted vendor evidence.
"""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from datetime import date, timedelta
from typing import Any

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONTROL_STATUSES = {
    "in progress": "In Progress",
    "in place": "In Place",
    "deferred": "Deferred",
    "unavailable": "Unavailable",
    "waived": "Waived",
    "not applicable": "Not Applicable",
    "postponed": "Deferred",
}

DEFAULT_RISKS = [
    {
        "risk_id": "R-001",
        "title": "Identity and access control gaps",
        "description": "Weak identity federation and access lifecycle controls can create unauthorized access risk.",
        "severity": "HIGH",
        "potential_impact": "Data exposure and unauthorized usage of enterprise AI capabilities.",
    },
    {
        "risk_id": "R-002",
        "title": "Audit and compliance evidence gaps",
        "description": "Missing audit APIs or insufficient logs can prevent compliance attestation and incident reconstruction.",
        "severity": "HIGH",
        "potential_impact": "Inability to satisfy SOX/HIPAA/PCI evidence requirements.",
    },
    {
        "risk_id": "R-003",
        "title": "Data egress and content control limitations",
        "description": "Insufficient egress filtering and DLP may allow uncontrolled sensitive data movement.",
        "severity": "MEDIUM",
        "potential_impact": "Data leakage or policy violations due to weak governance controls.",
    },
]


def normalize_status(raw: str) -> str:
    cleaned = re.sub(r"\s+", " ", raw.strip().lower())
    return CONTROL_STATUSES.get(cleaned, "In Progress")


def _due_date_for_severity(severity: str) -> str:
    days = {"CRITICAL": 30, "HIGH": 30, "MEDIUM": 60, "LOW": 90}[severity]
    return str(date.today() + timedelta(days=days))


def _vendor_profile(vendor_name: str, evidence_text: str) -> dict[str, Any] | None:
    lower = f"{vendor_name} {evidence_text}".lower()

    if any(token in lower for token in ["claude", "anthropic", "channel", "cowork"]):
        risks = [
            {
                "risk_id": "R-001",
                "title": "Unattended externally-triggered execution",
                "description": "Channels can trigger background Claude sessions from external messages while users are away.",
                "severity": "CRITICAL",
                "potential_impact": "Autonomous command execution with filesystem/shell access and high blast radius.",
            },
            {
                "risk_id": "R-002",
                "title": "Prompt injection via external messaging platforms",
                "description": "Trusted sender channels can carry malicious or socially engineered prompts into sessions.",
                "severity": "HIGH",
                "potential_impact": "Unauthorized tool actions, code changes, and data exfiltration.",
            },
            {
                "risk_id": "R-003",
                "title": "Compliance API and audit visibility gap",
                "description": "Channel-initiated activity coverage in compliance logging may be incomplete or unconfirmed.",
                "severity": "HIGH",
                "potential_impact": "SOX/HIPAA/PCI evidence gaps and incident-response blind spots.",
            },
            {
                "risk_id": "R-004",
                "title": "Plugin supply chain bypass in preview mode",
                "description": "Development channel loading and broad plugin controls can bypass approved plugin policy.",
                "severity": "HIGH",
                "potential_impact": "Execution of untrusted plugin code in privileged environments.",
            },
            {
                "risk_id": "R-005",
                "title": "Org-wide enablement without granular access control",
                "description": "Binary org-wide toggles can expose all users before readiness controls are in place.",
                "severity": "MEDIUM",
                "potential_impact": "Premature rollout and inconsistent enforcement across teams.",
            },
        ]

        controls = [
            ("C-001", ["R-001"], "disableBypassPermissionsMode", "Prevent --dangerously-skip-permissions for unattended sessions.", "Managed settings via MDM", "In Progress"),
            ("C-002", ["R-004"], "allowManagedMcpServersOnly", "Restrict channel plugins to approved server allowlist.", "Managed settings via MDM", "In Progress"),
            ("C-003", ["R-004"], "allowManagedHooksOnly", "Block user/project/plugin hooks as secondary execution paths.", "Managed settings via MDM", "In Progress"),
            ("C-004", ["R-002"], "Sender allowlist enforcement", "Require paired senders + policy allowlist before go-live.", "Per-user onboarding flow with verification", "In Progress"),
            ("C-005", ["R-003"], "OpenTelemetry to SIEM", "Validate channel session telemetry ingestion before feature enablement.", "Managed telemetry endpoint", "In Progress"),
            ("C-006", ["R-003"], "Compliance API coverage confirmation", "Block regulated use until vendor confirms channel activity coverage.", "Contract + vendor commitment", "Deferred"),
            ("C-007", ["R-005"], "Phased rollout governance", "Gate enablement on readiness checklist and training completion.", "Security + business approval process", "In Progress"),
        ]

        return {
            "vendor_service_description": (
                f"{vendor_name} appears to provide AI coding assistant capabilities with optional external-channel triggering. "
                "The primary incremental risk is externally-triggered unattended execution rather than new local tool permissions."
            ),
            "risks": risks,
            "controls": [
                {
                    "control_id": cid,
                    "related_risk_ids": related,
                    "control_name": name,
                    "description": desc,
                    "deployment_guidance": deploy,
                    "status": status,
                    "owner": "Unassigned",
                    "due_date": _due_date_for_severity("HIGH"),
                    "status_rationale": "",
                }
                for cid, related, name, desc, deploy, status in controls
            ],
            "open_questions": [
                "Is channel-initiated activity definitively captured by Compliance API?",
                "Can channels be scoped per user/team instead of org-wide toggle?",
                "Are custom Slack/development channels explicitly disallowed in policy?",
            ],
            "assumptions": [
                "Assessment assumes channel-like externally triggered workflows are in scope.",
            ],
        }

    if "vertex" in lower:
        risks = [
            {
                "risk_id": "R-001",
                "title": "Model endpoint and service-account privilege sprawl",
                "description": "Overprivileged service accounts and broad project IAM can expose model endpoints and data paths.",
                "severity": "HIGH",
                "potential_impact": "Unauthorized model invocation, prompt/data access, and environment compromise.",
            },
            {
                "risk_id": "R-002",
                "title": "Training/inference data residency and retention ambiguity",
                "description": "Unclear data processing paths and retention controls can violate data locality policies.",
                "severity": "HIGH",
                "potential_impact": "Regulatory exposure and contract non-compliance.",
            },
            {
                "risk_id": "R-003",
                "title": "Prompt and response data leakage through logging/telemetry",
                "description": "Application logs and observability pipelines may inadvertently store sensitive prompts or outputs.",
                "severity": "HIGH",
                "potential_impact": "Sensitive data leakage and broader access to confidential content.",
            },
            {
                "risk_id": "R-004",
                "title": "Model safety and abuse controls insufficiently tuned",
                "description": "Default safety controls may not align with enterprise abuse scenarios.",
                "severity": "MEDIUM",
                "potential_impact": "Unsafe outputs and policy violations in production workflows.",
            },
        ]
        controls = [
            ("C-001", ["R-001"], "Least-privilege IAM for model workloads", "Restrict service accounts, API keys, and project-level roles.", "Cloud IAM + workload identity", "In Progress"),
            ("C-002", ["R-002"], "Data residency and retention policy mapping", "Document region constraints and retention/deletion SLAs.", "Contract + cloud policy controls", "In Progress"),
            ("C-003", ["R-003"], "Prompt/response redaction in logs", "Apply redaction and minimize sensitive payload storage.", "Logging pipeline controls", "In Progress"),
            ("C-004", ["R-004"], "Safety policy tuning and red-team tests", "Tune moderation/safety settings and validate with abuse cases.", "Model governance process", "Deferred"),
        ]
        return {
            "vendor_service_description": (
                f"{vendor_name} appears to provide managed AI model infrastructure and inference APIs. "
                "Risk posture centers on IAM, data governance, and safe model operations."
            ),
            "risks": risks,
            "controls": [
                {
                    "control_id": cid,
                    "related_risk_ids": related,
                    "control_name": name,
                    "description": desc,
                    "deployment_guidance": deploy,
                    "status": status,
                    "owner": "Unassigned",
                    "due_date": _due_date_for_severity("HIGH"),
                    "status_rationale": "",
                }
                for cid, related, name, desc, deploy, status in controls
            ],
            "open_questions": [
                "Are prompts/outputs used for model training by default for this contract tier?",
                "What regional failover paths exist for data and inference traffic?",
            ],
            "assumptions": [
                "Assessment assumes cloud-hosted model API usage and enterprise integration patterns.",
            ],
        }

    return None


def _infer_risks_from_controls(controls: list[dict[str, str]]) -> list[dict[str, str]]:
    risks = deepcopy(DEFAULT_RISKS)
    text = " ".join(
        c.get("control_name", "").lower() + " " + c.get("status_rationale", "").lower()
        for c in controls
    )

    if "audit" in text or "compliance api" in text:
        risks[1]["severity"] = "CRITICAL"
        risks[1]["potential_impact"] = "Regulatory non-compliance and inability to investigate incidents."
    if "web search" in text or "egress" in text or "dlp" in text:
        risks[2]["severity"] = "HIGH"

    return risks


def _parse_control_rows(evidence_text: str) -> list[dict[str, str]]:
    controls: list[dict[str, str]] = []
    for line in evidence_text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("control"):
            continue

        if "|" in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 4:
                controls.append(
                    {
                        "control_name": parts[0],
                        "what_it_does": parts[1],
                        "how_to_deploy": parts[2],
                        "status": normalize_status(parts[3]),
                        "notes": "",
                    }
                )
                continue

        match = re.search(r"\b(In Progress|In Place|Deferred|Unavailable|Waived|Not Applicable)\b$", line, flags=re.I)
        if match:
            status = normalize_status(match.group(1))
            control_name = re.sub(r"\b(In Progress|In Place|Deferred|Unavailable|Waived|Not Applicable)\b$", "", line, flags=re.I).strip(" -:")
            controls.append(
                {
                    "control_name": control_name or "Unspecified control",
                    "what_it_does": "See evidence text",
                    "how_to_deploy": "To be defined",
                    "status": status,
                    "notes": "",
                }
            )

    if not controls:
        controls = [
            {
                "control_name": "Security due diligence package",
                "what_it_does": "Collect SOC 2/ISO evidence and required security attestations.",
                "how_to_deploy": "Security questionnaire + contract requirements",
                "status": "In Progress",
                "notes": "Fallback because no structured controls were parsed from provided evidence.",
            }
        ]

    normalized_controls = []
    for idx, control in enumerate(controls, start=1):
        normalized_controls.append(
            {
                "control_id": f"C-{idx:03d}",
                "related_risk_ids": ["R-001"],
                "control_name": control["control_name"],
                "description": control["what_it_does"],
                "deployment_guidance": control["how_to_deploy"],
                "status": control["status"],
                "owner": "Unassigned",
                "due_date": _due_date_for_severity("HIGH"),
                "status_rationale": control["notes"],
            }
        )

    return normalized_controls


def _attach_risk_links(controls: list[dict[str, Any]]) -> None:
    for control in controls:
        name = (control.get("control_name") or "").lower()
        if any(term in name for term in ["audit", "compliance", "log"]):
            control["related_risk_ids"] = ["R-002"]
        elif any(term in name for term in ["network", "dlp", "domain", "egress", "search"]):
            control["related_risk_ids"] = ["R-003"]
        else:
            control["related_risk_ids"] = ["R-001"]


def generate_assessment(
    vendor_name: str,
    vendor_type: str,
    evidence_text: str,
    researched_sources: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    profile = _vendor_profile(vendor_name, evidence_text)
    if profile:
        risks = profile["risks"]
        controls = profile["controls"]
        service_description = profile["vendor_service_description"]
        open_questions = profile["open_questions"]
        assumptions = profile["assumptions"]
    else:
        controls = _parse_control_rows(evidence_text)
        _attach_risk_links(controls)
        risks = _infer_risks_from_controls(controls)
        service_description = (
            f"{vendor_name} is assessed as a {vendor_type} vendor using available evidence. "
            "This draft is auto-generated and requires security and business review."
        )
        open_questions = [
            "Confirm whether audit logs are exportable to Block SIEM.",
            "Confirm compliance scope and contractual commitments for unavailable controls.",
        ]
        assumptions = [
            "Status values were inferred from submitted evidence text.",
            "Control ownership defaults to Unassigned until business owner assignment.",
        ]

    highest = max((risk["severity"] for risk in risks), key=lambda s: SEVERITY_ORDER[s])

    return {
        "vendor": {
            "name": vendor_name,
            "vendor_type": vendor_type,
            "business_owner": "Unassigned",
            "data_classification": "To be determined",
        },
        "vendor_service_description": service_description,
        "risks": risks,
        "controls": controls,
        "assignment_and_tracking": {
            "assigned_to": "Unassigned - To be assigned to Block team member",
            "created_date": str(date.today()),
            "status": "Open - Pending Review",
            "recommended_due_date": _due_date_for_severity(highest),
        },
        "open_questions": open_questions,
        "assumptions": assumptions,
        "sources": researched_sources or [],
    }


def maybe_generate_with_llm(
    vendor_name: str,
    vendor_type: str,
    evidence_text: str,
    researched_sources: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Use LLM if configured; fallback to deterministic generation."""
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    if not api_key:
        return generate_assessment(vendor_name, vendor_type, evidence_text, researched_sources=researched_sources)

    try:
        from openai import OpenAI  # type: ignore

        client = OpenAI(api_key=api_key)
        prompt = (
            "Return only JSON with keys vendor, vendor_service_description, risks, controls, "
            "assignment_and_tracking, open_questions, assumptions. "
            f"Vendor: {vendor_name} ({vendor_type}). Evidence:\n{evidence_text}"
        )
        resp = client.responses.create(model=model, input=prompt)
        text = resp.output_text
        payload = json.loads(text)
        payload.setdefault("sources", researched_sources or [])
        return payload
    except Exception:
        return generate_assessment(vendor_name, vendor_type, evidence_text, researched_sources=researched_sources)
