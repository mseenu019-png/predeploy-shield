"""In-memory archive hardener: injects protection files and applies safe deterministic fixes."""

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
from zipfile import ZIP_DEFLATED, ZipFile

from .ai_analyzer import analyze
from .scanner import (
    BY_ID,
    MAX_EXPANDED,
    MATCHERS,
    SECRET_IDS,
    ScanError,
    is_env,
    preflight,
    scan_zip,
    validate_entry,
)

SHIELD_VERSION = "1.0.0"
ENV_VAR_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{1,48})\s*[:=]")


def _comment_prefix(path_str):
    ext = Path(path_str).suffix.lower()
    if ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".cs", ".rs", ".php"}:
        return "//"
    return "#"


def _infer_var_name(line, rule_id):
    match = ENV_VAR_RE.search(line)
    if match:
        return match.group(1).upper()
    return {
        "aws-key": "AWS_ACCESS_KEY_ID",
        "google-key": "GEMINI_API_KEY",
        "openai-key": "OPENAI_API_KEY",
        "jwt-secret": "JWT_SECRET",
    }.get(rule_id, "APP_SECRET")


def _redact_secret_line(line, rule_id, path_str, redacted_vars):
    var_name = _infer_var_name(line, rule_id)
    redacted_vars.add(var_name)
    ext = Path(path_str).suffix.lower()
    pattern = next((p for rid, p in MATCHERS if rid == rule_id), None)
    if not pattern:
        return line, False

    if rule_id == "jwt-secret":
        # Replace the quoted secret value at the end of the assignment.
        if ext == ".py":
            updated = re.sub(r'(["\'])[^"\'\r\n]{4,}\1', f'os.getenv("{var_name}", "")', line, count=1)
        elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            updated = re.sub(r'(["\'])[^"\'\r\n]{4,}\1', f'process.env.{var_name} || ""', line, count=1)
        else:
            updated = re.sub(r'(["\'])[^"\'\r\n]{4,}\1', f'"${{{var_name}}}"', line, count=1)
        return updated, updated != line

    if ext == ".py":
        updated = re.sub(r'(["\'])[^"\'\r\n]*' + pattern.pattern + r'[^"\'\r\n]*\1', f'os.getenv("{var_name}", "")', line, count=1)
    elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        updated = re.sub(r'(["\'])[^"\'\r\n]*' + pattern.pattern + r'[^"\'\r\n]*\1', f'process.env.{var_name} || ""', line, count=1)
    else:
        updated = pattern.sub(f"${{{var_name}}}", line, count=1)
    if updated == line:
        updated = pattern.sub(f"<REDACTED_{var_name}>", line, count=1)
    return updated, updated != line


def _harden_text_content(path_str, text, file_findings, redacted_vars):
    lines = text.splitlines()
    had_trailing_newline = text.endswith("\n")
    applied = []

    if is_env(Path(path_str).name):
        new_lines = []
        for ln in lines:
            stripped = ln.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.split("=", 1)[0].strip()
                if key:
                    redacted_vars.add(key)
                    new_lines.append(f"{key}=# REDACTED_BY_PREDEPLOY_SHIELD")
                    continue
            new_lines.append(ln)
        applied.append(f"Redacted .env values in {path_str}")
        out = "\n".join(new_lines) + ("\n" if had_trailing_newline else "")
        return out, applied

    # Process findings from bottom to top so inserted comment lines do not shift earlier line numbers.
    sorted_findings = sorted(file_findings, key=lambda f: f["line"], reverse=True)
    for finding in sorted_findings:
        idx = finding["line"] - 1
        if idx < 0 or idx >= len(lines):
            continue
        rule_id = finding["rule_id"]
        line = lines[idx]

        if rule_id in {"aws-key", "google-key", "openai-key", "jwt-secret"}:
            updated, changed = _redact_secret_line(line, rule_id, path_str, redacted_vars)
            if changed:
                lines[idx] = updated
                applied.append(f"Redacted {rule_id} in {path_str}:{finding['line']}")
                continue

        if rule_id == "chmod" and "777" in line:
            lines[idx] = line.replace("777", "700", 1)
            applied.append(f"Tightened chmod 777 -> 700 in {path_str}:{finding['line']}")
            continue

        prefix = _comment_prefix(path_str)
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        todo = f"{indent}{prefix} SECURITY TODO [PreDeploy Shield]: {finding['remediation']}"
        if idx == 0 or "SECURITY TODO [PreDeploy Shield]" not in lines[idx - 1]:
            lines.insert(idx, todo)
            applied.append(f"Added remediation guidance for {rule_id} in {path_str}:{finding['line']}")

    out = "\n".join(lines) + ("\n" if had_trailing_newline else "")
    return out, applied


def _build_security_md(report, applied_protections):
    lines = [
        "# Security Policy & Pre-Deployment Hardening",
        "",
        f"- **Original Verdict:** `{report['verdict']}` (Risk Score: `{report['risk_score']}/100`)",
        f"- **Analysis Mode:** `{report['analysis_mode']}`",
        "",
        "## Day-1 Hardening Checklist",
        "",
    ]
    for item in report.get("day1_hardening_checklist", []):
        lines.append(f"- [ ] {item}")
    if applied_protections:
        lines.extend(["", "## Applied Archive Protections", ""])
        for item in applied_protections:
            lines.append(f"- {item}")
    lines.extend([
        "",
        "## Reporting a Vulnerability",
        "",
        "Do not open public issues for security vulnerabilities. Rotate exposed credentials immediately and contact the repository maintainers.",
        "",
    ])
    return "\n".join(lines)


def _build_env_example(redacted_vars):
    lines = [
        "# Environment variables required by this project (generated by PreDeploy Shield)",
        "# Copy to .env locally and populate via a secret manager in production.",
        "",
    ]
    if redacted_vars:
        for var in sorted(redacted_vars):
            lines.append(f"{var}=")
    else:
        lines.append("# No literal secret keys required redaction during this scan.")
    lines.append("")
    return "\n".join(lines)


def harden_zip(archive, original_filename, target, sensitivity, include_tests=False):
    """Build an in-memory hardened ZIP archive with safe fixes and protection files."""
    preflight(archive)
    matches, coverage = scan_zip(archive, include_tests=include_tests)
    report = analyze(matches, coverage, target, sensitivity)

    findings_by_file = {}
    for finding in report["findings"]:
        findings_by_file.setdefault(finding["file"], []).append(finding)

    redacted_vars = set()
    applied_protections = []
    output_entries = {}
    expanded = 0

    archive.seek(0)
    with ZipFile(archive) as source_zip:
        for entry in source_zip.infolist():
            clean_path = validate_entry(entry)
            if entry.is_dir():
                continue
            path_str = str(clean_path)
            raw = source_zip.read(entry)
            expanded += len(raw)
            if expanded > MAX_EXPANDED:
                raise ScanError("ZIP expanded content exceeds the 10 MB limit.", 413)

            if path_str in findings_by_file:
                try:
                    decoded = raw.decode("utf-8")
                    hardened_text, file_actions = _harden_text_content(
                        path_str, decoded, findings_by_file[path_str], redacted_vars
                    )
                    raw = hardened_text.encode("utf-8")
                    applied_protections.extend(file_actions)
                except UnicodeDecodeError:
                    pass
            output_entries[path_str] = raw

    injected_files = ["SECURITY.md", ".env.example", ".predeploy-shield.json"]
    output_entries["SECURITY.md"] = _build_security_md(report, applied_protections).encode("utf-8")
    output_entries[".env.example"] = _build_env_example(redacted_vars).encode("utf-8")

    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(output_entries.items())}
    manifest = {
        "shield_version": SHIELD_VERSION,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "deployment_target": target.value,
        "data_sensitivity": sensitivity.value,
        "original_risk_score": report["risk_score"],
        "original_verdict": report["verdict"],
        "applied_protections": applied_protections,
        "injected_files": injected_files,
        "sha256": hashes,
    }
    output_entries[".predeploy-shield.json"] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")

    out_buffer = io.BytesIO()
    with ZipFile(out_buffer, "w", compression=ZIP_DEFLATED) as out_zip:
        for name, data in sorted(output_entries.items()):
            out_zip.writestr(name, data)

    stem = PurePosixPath(original_filename or "project.zip").stem
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-") or "project"
    out_filename = f"{safe_stem}-shielded.zip"

    meta = {
        "injected_files": injected_files,
        "fixes_applied": len(applied_protections),
        "redacted_vars": sorted(redacted_vars),
    }
    return out_buffer.getvalue(), out_filename, meta
