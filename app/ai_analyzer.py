"""Apply deployment policy locally and optionally personalize the hardening checklist."""

import json
import os
from enum import Enum
from time import monotonic

import httpx

from .knowledge_db import get_relevant_knowledge
from .scanner import BY_ID, CHUNK


class Target(str, Enum):
    public = "public_cloud"
    internal = "internal_tool"
    mvp = "hackathon_mvp"


class Sensitivity(str, Enum):
    high = "high_auth_payments"
    moderate = "moderate_user_data"
    low = "low_public_static"


CHECKS = {
    "credentials": "Store runtime credentials in a secret manager and rotate exposed values.",
    "identity": "Use a least-privilege service identity and a non-root container user.",
    "access": "Restrict network access and verify authentication on private endpoints.",
    "input": "Validate untrusted input and use parameterized database queries.",
    "browser": "Restrict CORS to approved origins and review how the UI renders untrusted text.",
    "monitoring": "Verify health checks, redacted logs, and an alerting path before launch.",
    "payments": "Verify authorization boundaries and keep payment and auth data out of logs.",
    "coverage": "Review skipped files and paths separately before deploying.",
}


def _format_kb_context(knowledge):
    cwe_entries = [
        {
            "rule_id": item["rule_id"],
            "cwe_id": item["cwe_id"],
            "title": item["title"],
            "severity": item["severity"],
            "attack_vector": item["attack_vector"],
            "secure_fix_template": item["secure_fix_template"],
        }
        for item in knowledge.get("cwe_knowledge", {}).values()
    ]
    cal_entries = [
        {
            "deployment_target": item["deployment_target"],
            "data_sensitivity": item["data_sensitivity"],
            "expected_verdict": item["expected_verdict"],
            "rationale": item["rationale"],
        }
        for item in knowledge.get("calibration_examples", [])
    ]
    return json.dumps({"cwe_knowledge": cwe_entries, "calibration_examples": cal_entries})


def checklist_order(ids, target, sensitivity, knowledge=None):
    if not os.getenv("GEMINI_API_KEY"):
        return None
    if knowledge is None:
        knowledge = get_relevant_knowledge(ids, target.value, sensitivity.value)
    kb_context = _format_kb_context(knowledge)
    prompt = (
        f"Deployment target: {target.value}. Data sensitivity: {sensitivity.value}. "
        f"Observed scanner categories: {', '.join(sorted(set(ids))) or 'none'}. "
        f"Authoritative Security Knowledge & Calibration Examples: {kb_context}. "
        "Rank the provided hardening checklist items for the first day of deployment. "
    )
    if target == Target.mvp:
        prompt += "Prioritize immediate launch risks and keep the checklist short."
    if sensitivity == Sensitivity.high:
        prompt += " Prioritize authentication, credential handling and sensitive data."
    request = {
        "systemInstruction": {"parts": [{"text": "You are a defensive release reviewer. Return a JSON array of exactly three distinct checklist IDs from this catalog: " + json.dumps(CHECKS)}]},
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json", "maxOutputTokens": 256, "thinkingConfig": {"thinkingBudget": 0}},
    }
    deadline = monotonic() + 6
    try:
        with httpx.Client(timeout=httpx.Timeout(4, connect=2)) as client:
            with client.stream(
                "POST", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
                headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"], "Accept-Encoding": "identity"}, json=request,
            ) as response:
                response.raise_for_status()
                if response.headers.get("content-encoding", "identity") != "identity":
                    return None
                body = bytearray()
                for part in response.iter_raw():
                    if monotonic() > deadline or len(body) + len(part) > CHUNK:
                        return None
                    body.extend(part)
        payload = json.loads(body)
        choices = json.loads(payload["candidates"][0]["content"]["parts"][0]["text"])
        if isinstance(choices, list) and len(choices) == 3 and all(isinstance(item, str) and item in CHECKS for item in choices) and len(set(choices)) == 3:
            return choices
    except (httpx.HTTPError, KeyError, IndexError, ValueError, TypeError, RecursionError):
        pass
    return None


def analyze(matches, coverage, target, sensitivity):
    weights = {"critical": 85, "high": 58, "medium": 26}
    strict = target == Target.public and sensitivity == Sensitivity.high
    threshold = 55 if strict else 70 if sensitivity == Sensitivity.high or target == Target.public else 80
    ordered = sorted(matches, key=lambda match: -weights[BY_ID[match[0]].severity])
    scores = [weights[BY_ID[match[0]].severity] for match in ordered]
    score = min(100, scores[0] + min(24, sum(scores[1:]) // 5)) if scores else 0
    incomplete = coverage["limited"] or coverage["scanned_files"] == 0
    verdict = "BLOCK" if score >= threshold else "WARN" if ordered or incomplete else "PASS"
    summary = {
        "BLOCK": "Resolve the highest-priority findings before deployment.",
        "WARN": "Review the findings and scan coverage before deployment.",
        "PASS": "The scanner found no supported risk patterns in the inspected files.",
    }[verdict]
    rule_ids = [match[0] for match in ordered]
    knowledge = get_relevant_knowledge(rule_ids, target.value, sensitivity.value)
    cwe_kb = knowledge.get("cwe_knowledge", {})
    findings = []
    for rule_id, file, line, diff in ordered:
        rule = BY_ID[rule_id]
        kb = cwe_kb.get(rule_id)
        findings.append({
            "rule_id": rule_id, "severity": rule.severity, "file": file, "line": line,
            "category": kb["cwe_id"] if kb else rule.category,
            "exploit_scenario": kb["attack_vector"] if kb else rule.scenario,
            "remediation": kb["secure_fix_template"] if kb else rule.fix,
            "remediation_diff": diff,
            "snippet": coverage.get("snippets", {}).get(str(matches.index((rule_id, file, line, diff)))),
        })
    defaults = ["credentials", "input", "monitoring"]
    if target == Target.internal:
        defaults = ["access", "identity", "monitoring"]
    if sensitivity == Sensitivity.high:
        defaults = ["credentials", "payments", "access"]
    ai = checklist_order(rule_ids, target, sensitivity, knowledge=knowledge)
    checks = ai or defaults
    if incomplete and "coverage" not in checks:
        checks = [*checks, "coverage"]
    return {
        "verdict": verdict, "risk_score": score, "executive_summary": summary,
        "findings": findings, "day1_hardening_checklist": list(dict.fromkeys([*coverage.get("hardening_advice", []), *[CHECKS[key] for key in checks]])),
        "coverage": {key: value for key, value in coverage.items() if key != "snippets"}, "analysis_mode": "gemini_assisted" if ai else "deterministic",
    }
