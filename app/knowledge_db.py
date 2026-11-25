"""Lightweight SQLite knowledge base and calibration feedback store."""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_DB_PATH = DATA_DIR / "shield_kb.db"

CWE_SEED = [
    (
        "aws-key",
        "CWE-798",
        "Hardcoded AWS Access Key",
        "critical",
        "Committed AWS access keys (AKIA/ASIA) in source or config can be scraped from repositories to authenticate directly against AWS APIs and pivot into cloud resources.",
        "Revoke and rotate the exposed IAM key immediately; use IAM roles / workload identity federation or fetch secrets from Cloud Secret Manager at runtime.",
        "Example keys like " + "AKIA" + "IOSFODNN7EXAMPLE in unit-test fixtures or documentation may be benign placeholders.",
    ),
    (
        "google-key",
        "CWE-798",
        "Hardcoded Google / Gemini API Key",
        "high",
        "Exposed Google API keys (AIza...) allow unauthorized callers to consume billable Gemini or Maps quotas and access project-scoped APIs.",
        "Restrict and rotate the key in Google Cloud Console; inject GEMINI_API_KEY via Cloud Run environment variables or Secret Manager.",
        "Keys read via os.getenv('GEMINI_API_KEY') without a literal value are safe.",
    ),
    (
        "openai-key",
        "CWE-798",
        "Hardcoded OpenAI API Key",
        "high",
        "Committed OpenAI keys (sk-...) enable unauthorized model invocations billed to your organization.",
        "Revoke the key in the OpenAI dashboard and load credentials from environment variables or a secret manager.",
        "Redacted placeholders like sk-**** or test mocks inside tests/ are typically benign.",
    ),
    (
        "jwt-secret",
        "CWE-798",
        "Hardcoded JWT Signing Secret",
        "critical",
        "A known symmetric JWT signing secret lets attackers forge arbitrary session tokens and impersonate any user or admin.",
        "Generate a high-entropy 256-bit secret per environment, store it in a secret manager, and rotate it to invalidate forged tokens.",
        "Local-only test fixtures in tests/ using ephemeral secrets do not affect production if excluded from builds.",
    ),
    (
        "private-key",
        "CWE-321",
        "Embedded Cryptographic Private Key",
        "critical",
        "Committed PEM private keys compromise TLS identity, SSH access, or token signing across all environments sharing that key.",
        "Revoke the compromised key/certificate, purge it from Git history, and mount runtime keys from a managed KMS or Secret Manager.",
        "Public certificates (-----BEGIN CERTIFICATE-----) do not contain private key material.",
    ),
    (
        "env-file",
        "CWE-312",
        "Committed Environment File",
        "high",
        "A committed .env file often bundles database passwords, API tokens, and signing secrets in plaintext.",
        "Remove .env from version control, add .env* to .gitignore, and commit only a sanitized .env.example template.",
        ".env.example and .env.template files with empty values are expected and safe.",
    ),
    (
        "eval",
        "CWE-95",
        "Dynamic Code Evaluation via eval()",
        "high",
        "Passing unvalidated user input to eval() allows arbitrary Python or JavaScript code execution within the service process.",
        "Replace eval() with ast.literal_eval() for literals, json.loads() for JSON, or an explicit expression parser.",
        "References to 'eval(' inside documentation comments or scanner rule definitions are not executable calls.",
    ),
    (
        "exec",
        "CWE-95",
        "Dynamic Code Execution via exec()",
        "high",
        "Unrestricted exec() executes arbitrary statements with full process privileges and filesystem access.",
        "Replace dynamic exec() dispatch with an explicit allowlisted mapping of handler functions.",
        "String literals describing exec() in documentation are not executable calls.",
    ),
    (
        "shell",
        "CWE-78",
        "OS Command Injection via shell=True",
        "high",
        "Invoking subprocess with shell=True passes arguments through a system shell, enabling command chaining via metacharacters.",
        "Pass an argument list with shell=False (default) and validate any external arguments against an allowlist.",
        "Constant commands with no external input still carry risk; prefer shell=False in all cases.",
    ),
    (
        "sql",
        "CWE-89",
        "SQL Injection via String Concatenation",
        "high",
        "Concatenating or f-string interpolating untrusted values into SQL statements allows attackers to alter query logic or exfiltrate tables.",
        "Use parameterized queries (e.g. cursor.execute('SELECT ... WHERE id = ?', (user_id,))) or an ORM query builder.",
        "Static SQL strings without runtime variable interpolation are safe.",
    ),
    (
        "innerhtml",
        "CWE-79",
        "DOM Cross-Site Scripting via innerHTML",
        "medium",
        "Assigning untrusted data to element.innerHTML executes injected HTML/script payloads in the victim's browser session.",
        "Use element.textContent for plain text or sanitize rich HTML with an audited sanitizer before insertion.",
        "Assigning static, developer-authored markup or clearing with innerHTML = '' is lower risk but textContent is preferred.",
    ),
    (
        "chmod",
        "CWE-732",
        "Overly Permissive File Mode (chmod 777)",
        "medium",
        "Granting world-writable permissions (0777) allows any local or container user to tamper with application binaries or scripts.",
        "Apply least-privilege permissions such as chmod 750 for executables or 640 for configuration files.",
        "Temporary build artifacts inside ephemeral CI containers are lower risk, but 755/644 is still recommended.",
    ),
    (
        "docker-root",
        "CWE-250",
        "Container Running as Root User",
        "medium",
        "Running a container without a non-root USER instruction gives a compromised process root privileges inside the container namespace.",
        "Create an unprivileged system user (e.g. useradd --system --uid 10001) and set USER 10001 in the final Dockerfile stage.",
        "Multi-stage builder stages may run as root if the final runtime stage switches to a non-root USER.",
    ),
    (
        "cors",
        "CWE-942",
        "Permissive Wildcard CORS Policy",
        "medium",
        "Setting Access-Control-Allow-Origin or allow_origins=['*'] permits any third-party website to read API responses.",
        "Restrict allow_origins to an explicit list of trusted frontend origins.",
        "Fully public, unauthenticated read-only endpoints may intentionally allow '*' when no credentials are used.",
    ),
]

CALIBRATION_SEED = [
    (
        'AWS_ACCESS_KEY_ID = "' + "AKIA" + '1234567890ABCDEF"',
        "app/config.py",
        "public_cloud",
        "high_auth_payments",
        "BLOCK",
        "Hardcoded live-format AWS key in a public cloud service handling auth/payments is a critical credential leak.",
    ),
    (
        "result = eval(request.args.get('expr'))",
        "app/routes.py",
        "public_cloud",
        "moderate_user_data",
        "BLOCK",
        "Direct eval() on HTTP query input enables remote code execution on public cloud.",
    ),
    (
        'cursor.execute("SELECT * FROM users WHERE email = \'" + email + "\'")',
        "app/db.py",
        "public_cloud",
        "high_auth_payments",
        "BLOCK",
        "SQL string concatenation on user email exposes authentication records to SQL injection.",
    ),
    (
        "chmod 777 scripts/start.sh",
        "deploy/start.sh",
        "internal_tool",
        "low_public_static",
        "WARN",
        "World-writable startup script in an internal tool should be tightened to 750 but is non-critical.",
    ),
    (
        'DUMMY_KEY = "' + "AKIA" + 'ZZZZZZZZZZZZZZZZ"',
        "tests/test_scanner.py",
        "public_cloud",
        "low_public_static",
        "PASS",
        "Synthetic placeholder credential inside an excluded test fixture is a true negative.",
    ),
    (
        'api_key = os.getenv("GEMINI_API_KEY", "")',
        "app/ai_analyzer.py",
        "public_cloud",
        "high_auth_payments",
        "PASS",
        "Reading credentials from environment variables at runtime is the recommended pattern.",
    ),
    (
        "statusEl.textContent = userMessage;",
        "static/app.js",
        "public_cloud",
        "moderate_user_data",
        "PASS",
        "Using textContent instead of innerHTML safely neutralizes HTML/script injection.",
    ),
    (
        "USER 10001\nCMD [\"uvicorn\", \"app.main:app\"]",
        "Dockerfile",
        "public_cloud",
        "high_auth_payments",
        "PASS",
        "Final container stage explicitly drops privileges to non-root UID 10001.",
    ),
]


def _connect(db_path=None):
    target = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None):
    """Initialize SQLite schema and idempotently seed CWE knowledge and calibration examples."""
    target = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    with _connect(target) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cwe_knowledge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT UNIQUE NOT NULL,
                cwe_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                attack_vector TEXT NOT NULL,
                secure_fix_template TEXT NOT NULL,
                false_positive_notes TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS calibration_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_snippet TEXT NOT NULL,
                file_path TEXT NOT NULL,
                deployment_target TEXT NOT NULL,
                data_sensitivity TEXT NOT NULL,
                expected_verdict TEXT NOT NULL,
                rationale TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO cwe_knowledge
                (rule_id, cwe_id, title, severity, attack_vector, secure_fix_template, false_positive_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            CWE_SEED,
        )
        count = conn.execute("SELECT COUNT(*) FROM calibration_feedback").fetchone()[0]
        if count == 0:
            now = datetime.now(timezone.utc).isoformat()
            conn.executemany(
                """
                INSERT INTO calibration_feedback
                    (code_snippet, file_path, deployment_target, data_sensitivity, expected_verdict, rationale, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [(*row, now) for row in CALIBRATION_SEED],
            )
        conn.commit()
    return target


def get_relevant_knowledge(matched_rule_ids, deployment_target, data_sensitivity, db_path=None):
    """Retrieve matching CWE knowledge records and top relevant few-shot calibration examples."""
    init_db(db_path)
    unique_ids = sorted({str(rid) for rid in matched_rule_ids if rid})
    cwe_map = {}
    examples = []
    with _connect(db_path) as conn:
        if unique_ids:
            placeholders = ",".join("?" for _ in unique_ids)
            rows = conn.execute(
                f"SELECT rule_id, cwe_id, title, severity, attack_vector, secure_fix_template, false_positive_notes "
                f"FROM cwe_knowledge WHERE rule_id IN ({placeholders})",
                unique_ids,
            ).fetchall()
            cwe_map = {row["rule_id"]: dict(row) for row in rows}
        cal_rows = conn.execute(
            """
            SELECT id, code_snippet, file_path, deployment_target, data_sensitivity, expected_verdict, rationale, created_at
            FROM calibration_feedback
            ORDER BY
                (CASE WHEN deployment_target = ? THEN 2 ELSE 0 END) +
                (CASE WHEN data_sensitivity = ? THEN 1 ELSE 0 END) DESC,
                id DESC
            LIMIT 6
            """,
            (str(deployment_target), str(data_sensitivity)),
        ).fetchall()
        examples = [dict(row) for row in cal_rows]
    return {"cwe_knowledge": cwe_map, "calibration_examples": examples}


def record_calibration_feedback(
    code_snippet,
    file_path,
    deployment_target,
    data_sensitivity,
    expected_verdict,
    rationale,
    db_path=None,
):
    """Persist a verified scan outcome or false-positive correction into SQLite."""
    init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    snippet = str(code_snippet or "").strip()[:500] or "(no snippet)"
    path = str(file_path or "").strip()[:250] or "(unknown)"
    note = str(rationale or "").strip()[:500] or "User-submitted calibration feedback."
    verdict = str(expected_verdict).upper()
    if verdict not in {"BLOCK", "WARN", "PASS"}:
        raise ValueError("expected_verdict must be BLOCK, WARN, or PASS")
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO calibration_feedback
                (code_snippet, file_path, deployment_target, data_sensitivity, expected_verdict, rationale, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (snippet, path, str(deployment_target), str(data_sensitivity), verdict, note, now),
        )
        conn.commit()
        return cursor.lastrowid
