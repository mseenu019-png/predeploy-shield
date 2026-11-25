"""Bounded ZIP inspection. Archive paths are never used as filesystem paths."""

import ast
import io
import json
import tokenize
import re
import stat
import struct
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

MAX_ARCHIVE = 5_000_000
MAX_PYTHON = 64 * 1024
MAX_FILE = 512 * 1024
MAX_EXPANDED = 10 * 1024 * 1024
MAX_ENTRIES = 1000
MAX_FILES = 50
CHUNK = 64 * 1024
MAX_FINDINGS = 100

TEXT_EXT = set(".py .js .jsx .ts .tsx .mjs .cjs .html .htm .css .json .yaml .yml .toml .ini .cfg .conf .sh .bash .sql .php .rb .go .java .cs .rs .txt .md .xml .pem .key .env".split())
IGNORED = {".git", "node_modules", ".venv", "venv", "vendor", "__pycache__", "dist", "build"}


class ScanError(Exception):
    def __init__(self, message, status=422):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    category: str
    pattern: str
    scenario: str
    fix: str


RULES = (
    Rule("aws-key", "critical", "CWE-798", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "The AWS credential identifier may indicate committed credentials that can grant cloud access.", "Rotate exposed credentials and use workload identity or a secret manager."),
    Rule("google-key", "high", "CWE-798", r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])", "An exposed Google or Gemini key may authorize billable requests.", "Rotate the key and load it from a secret manager."),
    Rule("openai-key", "high", "CWE-798", r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])", "An exposed OpenAI key may authorize requests on the associated account.", "Rotate the key and load it from a secret manager."),
    Rule("jwt-secret", "critical", "CWE-798", r"""(?i)\b(?:jwt_secret(?:_key)?|jwt_signing_key)\b\s*["']?\s*[:=]\s*["'][^"'\r\n]{4,}["']""", "A disclosed symmetric signing key can undermine token authenticity.", "Rotate the signing key, invalidate affected tokens, and load the replacement securely."),
    Rule("private-key", "critical", "CWE-321", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----", "A disclosed private key can undermine the identity it represents.", "Revoke and replace the key, and remove it from source control history."),
    Rule("env-file", "high", "Secret management", "", "A committed environment file may disclose credentials.", "Keep local environment files out of version control and rotate exposed credentials."),
    Rule("eval", "high", "CWE-95", r"(?<![\w.])eval\s*\(", "Untrusted input reaching dynamic evaluation can run code.", "Parse the expected input format with a dedicated parser."),
    Rule("exec", "high", "CWE-95", r"(?<![\w.])exec\s*\(", "Untrusted input reaching dynamic execution can run code.", "Replace dynamic execution with explicit handlers."),
    Rule("shell", "high", "CWE-78", "", "Shell processing can interpret metacharacters in untrusted arguments.", "Use an argument list with shell disabled and validate external arguments."),
    Rule("sql", "high", "CWE-89", r"""(?i)(?:["']\s*(?:select|insert|update|delete)\b[^"'\n]*["']\s*\+|f["']\s*(?:select|insert|update|delete)\b[^"'\n]*\{)""", "Untrusted values concatenated into SQL can change query behavior.", "Use the database driver's parameter binding."),
    Rule("innerhtml", "medium", "CWE-79", r"\.innerHTML\s*(?:\+=|=(?!=))", "HTML assignment can introduce script-capable markup when fed untrusted content.", "Use textContent for plain text or an audited sanitizer for HTML."),
    Rule("chmod", "medium", "CWE-732", r"\bchmod\s+(?:-[\w-]+\s+)*0?777\b", "World-writable permissions let other principals modify deployed files.", "Grant only the permissions required by the runtime identity."),
    Rule("docker-root", "medium", "CWE-250", "", "A root runtime identity gives a compromised process broader container privileges.", "Create or select an unprivileged user and set USER in the final stage."),
    Rule("cors", "medium", "CWE-942", r"""(?i)(?:allow_origins\s*=\s*\[\s*|Access-Control-Allow-Origin["']?\s*[:=]\s*|origin\s*:\s*)["']?\*["']?""", "A wildcard origin allows cross-origin reads of otherwise readable responses.", "Allowlist the required frontend origins."),
)
BY_ID = {rule.id: rule for rule in RULES}
MATCHERS = [(rule.id, re.compile(rule.pattern)) for rule in RULES if rule.pattern]
SECRET_IDS = {rule.id for rule in RULES[:6]}


def preflight(archive):
    size = archive.seek(0, 2)
    if size > MAX_ARCHIVE:
        raise ScanError("ZIP exceeds the 5 MB compressed limit.", 413)
    archive.seek(max(0, size - 65557))
    tail = archive.read(65557)
    end = tail.rfind(b"PK\x05\x06")
    if end < 0 or len(tail) - end < 22:
        raise ScanError("Invalid ZIP archive.")
    _, disk, central_disk, disk_count, count, central_size, offset, comment = struct.unpack_from("<4s4H2LH", tail, end)
    physical_end = size - len(tail) + end
    if disk or central_disk or disk_count != count or end + 22 + comment != len(tail):
        raise ScanError("Unsupported ZIP layout.")
    if count > MAX_ENTRIES or central_size > 512 * 1024:
        raise ScanError("ZIP directory exceeds the scan limits.", 413)
    if offset + central_size != physical_end:
        raise ScanError("Unsupported ZIP directory layout.")
    # zipfile iterates actual directory records, even when the declared count is false.
    archive.seek(offset)
    directory = archive.read(central_size)
    position = 0
    actual = 0
    while position < central_size:
        if position + 46 > central_size or directory[position:position + 4] != b"PK\x01\x02":
            raise ScanError("Invalid ZIP directory record.")
        name, extra, note = struct.unpack_from("<3H", directory, position + 28)
        position += 46 + name + extra + note
        actual += 1
        if actual > MAX_ENTRIES:
            raise ScanError("ZIP contains too many entries.", 413)
    if position != central_size or actual != count:
        raise ScanError("Invalid ZIP directory count.")
    archive.seek(0)


def validate_entry(entry):
    name = entry.orig_filename
    if (
        not name or len(name) > 512 or re.search(r"[\x00-\x1f\x7f\\:]", name)
        or name.startswith("/") or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
    ):
        raise ScanError("ZIP contains an unsafe path.")
    mode = stat.S_IFMT(entry.external_attr >> 16)
    if mode not in {0, stat.S_IFREG, stat.S_IFDIR} or entry.flag_bits & 1:
        raise ScanError("ZIP contains a link, special file, or encrypted entry.")
    return PurePosixPath(name)


def is_env(name):
    name = name.lower()
    return (name == ".env" or name.startswith(".env.")) and not name.endswith((".example", ".sample", ".template"))


def file_priority(path):
    name = path.name.lower()
    if name.startswith(".env") or path.suffix in {".pem", ".key"}:
        return 0, str(path)
    if name.startswith(("dockerfile", "docker-compose")) or name in {"requirements.txt", "package.json"}:
        return 1, str(path)
    if "auth" in name or "config" in name:
        return 2, str(path)
    return 3, str(path)


def test_file(path):
    return bool(set(path.parts[:-1]) & {"tests", "test", "__tests__"}) or path.name.startswith("test_") or path.name.endswith(("_test.py", ".test.js", ".spec.ts"))


def python_code(source):
    """Mask string/comment spans for executable-pattern detection, preserving lines."""
    lines = source.splitlines(keepends=True)
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type not in {tokenize.STRING, tokenize.COMMENT}:
                continue
            (start, col), (end, end_col) = token.start, token.end
            for row in range(start - 1, end):
                left = col if row == start - 1 else 0
                right = end_col if row == end - 1 else len(lines[row].rstrip("\r\n"))
                lines[row] = lines[row][:left] + " " * (right - left) + lines[row][right:]
    except (tokenize.TokenError, IndentationError):
        return source.splitlines()
    return "".join(lines).splitlines()


def manifest_advice(path, source):
    if path.name == "requirements.txt":
        requirements = [line.split("#", 1)[0].strip() for line in source.splitlines()]
        if any(line and not re.fullmatch(r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+-]+(?:\s*;.*)?", line) for line in requirements):
            return ["Python manifest contains entries without an exact version pin or requiring manual review. Resolve and lock dependencies, then run pip-audit."]
    if path.name == "package.json":
        try:
            data = json.loads(source)
            dependencies = data.get("dependencies", {})
            if isinstance(dependencies, dict) and any(not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[\w.-]+)?", version) for version in dependencies.values()):
                return ["JavaScript runtime dependencies contain flexible or non-registry references. Commit a reviewed lockfile and run npm audit."]
        except (ValueError, AttributeError, RecursionError):
            return ["Review the unreadable package.json manifest manually."]
    return []


def inspect_text(path, source):
    if is_env(path.name):
        yield "env-file", 1
    is_python = path.suffix.lower() == ".py"
    docker = path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile.")
    final_user = None
    final_from = None
    emitted = set()

    code_lines = python_code(source) if is_python else source.splitlines()
    for number, line in enumerate(source.splitlines(), 1):
        for rule_id, pattern in MATCHERS:
            if rule_id in {"eval", "exec"} and is_python and len(source) <= MAX_PYTHON:
                continue
            candidate = line
            if is_python and rule_id not in SECRET_IDS:
                candidate = code_lines[number - 1]
                if rule_id == "cors" and "allow_origins" in candidate:
                    candidate = line
                if rule_id == "sql" and re.search(r"\b(?:query|sql|execute)\b", candidate, re.I):
                    candidate = line
            if rule_id not in emitted and pattern.search(candidate):
                emitted.add(rule_id)
                yield rule_id, number
        if docker:
            match = re.match(r"\s*(FROM|USER)\s+(.+)", line, re.I)
            if match:
                if match[1].upper() == "FROM":
                    final_from, final_user = number, None
                else:
                    final_user = (number, match[2].split()[0].split(":")[0])
    if final_from and (final_user is None or final_user[1] in {"root", "0"}):
        yield "docker-root", final_user[0] if final_user else final_from

    if is_python and len(source) <= MAX_PYTHON:
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            rule_id = None
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                rule_id = node.func.id
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            ):
                rule_id = "shell"
            if rule_id and rule_id not in emitted:
                emitted.add(rule_id)
                yield rule_id, node.lineno


def safe_patch(rule_id, path, number, source):
    # Only produce a patch for a narrowly matched line with no user-supplied values.
    if rule_id != "chmod":
        return None
    original = source.splitlines()[number - 1]
    if not re.fullmatch(r"[ \t]*chmod 777 [./a-zA-Z_-]{1,40}[ \t]*", original):
        return None
    path_label = str(path)
    if not re.fullmatch(r"[a-zA-Z0-9_./-]+", path_label):
        return None
    replacement = original.replace("chmod 777", "chmod 700", 1)
    patch = list(unified_diff([original + "\n"], [replacement + "\n"], f"a/{path_label}", f"b/{path_label}"))
    patch[2] = f"@@ -{number} +{number} @@\n"
    return "".join(patch)


def scan_zip(archive, include_tests=False):
    preflight(archive)
    findings = []
    advice = []
    snippets = {}
    coverage = dict(scanned_files=0, skipped_files=0, limited=False)
    try:
        with ZipFile(archive) as bundle, TemporaryDirectory(prefix="predeploy-") as temp:
            entries = []
            seen = set()
            expanded = 0
            for entry in bundle.infolist():
                path = validate_entry(entry)
                if path in seen:
                    raise ScanError("ZIP contains duplicate paths.")
                seen.add(path)
                expanded += entry.file_size
                if expanded > MAX_EXPANDED:
                    raise ScanError("ZIP exceeds the 10 MiB expanded limit.", 413)
                if entry.is_dir():
                    continue
                if set(path.parts[:-1]) & IGNORED or (not include_tests and test_file(path)):
                    coverage["skipped_files"] += 1
                    continue
                if path.suffix.lower() in TEXT_EXT or path.name.lower().startswith("dockerfile") or path.name.startswith(".env") or not path.suffix:
                    entries.append((entry, path))
                else:
                    coverage["skipped_files"] += 1

            # Inspect credential/config candidates first when the archive exceeds coverage.
            entries.sort(key=lambda item: file_priority(item[1]))
            destination = Path(temp) / "current"
            for entry, path in entries:
                if coverage["scanned_files"] >= MAX_FILES:
                    coverage["skipped_files"] += 1
                    coverage["limited"] = True
                    continue
                if entry.file_size > MAX_FILE or entry.compress_type not in {0, 8}:
                    coverage["skipped_files"] += 1
                    coverage["limited"] = True
                    continue
                with bundle.open(entry) as member, destination.open("wb") as extracted:
                    written = 0
                    while chunk := member.read(CHUNK):
                        written += len(chunk)
                        if written > MAX_FILE:
                            raise ScanError("ZIP member exceeds the extraction limit.", 413)
                        extracted.write(chunk)
                raw = destination.read_bytes()
                if b"\x00" in raw:
                    coverage["skipped_files"] += 1
                    continue
                try:
                    source = raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    coverage["skipped_files"] += 1
                    continue
                advice.extend(manifest_advice(path, source))
                coverage["scanned_files"] += 1
                if path.suffix.lower() == ".py" and len(source) > MAX_PYTHON:
                    coverage["limited"] = True
                for rule_id, line in inspect_text(path, source):
                    if len(findings) >= MAX_FINDINGS:
                        coverage["limited"] = True
                        break
                    file_label = str(path)
                    for secret_id, pattern in MATCHERS:
                        if secret_id in SECRET_IDS:
                            file_label = pattern.sub("[redacted]", file_label)
                    patch = safe_patch(rule_id, path, line, source) if file_label == str(path) else None
                    if rule_id not in SECRET_IDS and not is_env(path.name):
                        excerpt = source.splitlines()[line - 1]
                        for secret_id, matcher in MATCHERS:
                            if secret_id in SECRET_IDS:
                                excerpt = matcher.sub("[redacted]", excerpt)
                        snippets[str(len(findings))] = excerpt[:300]
                    findings.append((rule_id, file_label, line, patch))
    except (BadZipFile, NotImplementedError, RuntimeError, EOFError, ValueError, OSError) as exc:
        raise ScanError("The ZIP archive could not be read safely.") from exc
    if not any(path.name.lower() == "security.md" for path in seen):
        advice.append("Add SECURITY.md with a vulnerability reporting contact and supported versions.")
    advice.append("Verify API rate limits and object-level authorization for every sensitive endpoint. These controls require manual review.")
    coverage["hardening_advice"] = list(dict.fromkeys(advice))[:12]
    coverage["include_tests"] = include_tests
    coverage["snippets"] = snippets
    return findings, coverage
