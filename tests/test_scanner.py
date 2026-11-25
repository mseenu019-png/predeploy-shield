import io
import json
import stat
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import httpx
import pytest
from fastapi.testclient import TestClient

from app import ai_analyzer, main
from app.ai_analyzer import Sensitivity, Target, analyze
from app.scanner import MAX_ARCHIVE, MAX_ENTRIES, MAX_EXPANDED, MAX_FILES, ScanError, scan_zip

CONTEXT = {"deployment_target": "public_cloud", "data_sensitivity": "high_auth_payments"}


def archive(entries):
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as bundle:
        for name, content in entries:
            bundle.writestr(name, content)
    return stream


@pytest.fixture(autouse=True)
def no_gemini(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)


@pytest.fixture
def client():
    with TestClient(main.app) as client:
        yield client


@pytest.mark.parametrize("path", ["../outside.py", "safe/../../outside", "/absolute", "C:/drive", r"safe\..\outside"])
def test_unsafe_archive_path(path):
    with pytest.raises(ScanError, match="unsafe path"):
        scan_zip(archive([(path, "ignored")]))


def test_symlink_is_rejected():
    entry = ZipInfo("link")
    entry.create_system = 3
    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(ScanError, match="link"):
        scan_zip(archive([(entry, "elsewhere")]))


def test_compressed_size_limit():
    with pytest.raises(ScanError) as error:
        scan_zip(io.BytesIO(b"x" * (MAX_ARCHIVE + 1)))
    assert error.value.status == 413


def test_expanded_size_limit():
    with pytest.raises(ScanError, match="expanded"):
        scan_zip(archive([("large.txt", "a" * (MAX_EXPANDED + 1))]))


def test_entry_count_limit():
    with pytest.raises(ScanError, match="directory exceeds"):
        scan_zip(archive([(f"entry{i}.txt", "") for i in range(MAX_ENTRIES + 1)]))


def test_text_count_and_binary_skips():
    entries = [("image.txt", b"\x00\x01"), ("deps/image.png", b"binary")]
    entries += [(f"src/{i:02d}.txt", "plain text") for i in range(MAX_FILES + 1)]
    _, coverage = scan_zip(archive(entries))
    assert {key: coverage[key] for key in ("scanned_files", "skipped_files", "limited")} == {"scanned_files": 50, "skipped_files": 3, "limited": True}


@pytest.mark.parametrize(("file", "content", "rule", "line"), [
    ("config.py", 'a = "AKIA' + "Z" * 16 + '"', "aws-key", 1),
    ("app.txt", "AIza" + "X" * 35, "google-key", 1),
    ("app.txt", "sk-proj-" + "Y" * 30, "openai-key", 1),
    ("config.json", '{"JWT_SECRET": "test-only-value"}', "jwt-secret", 1),
    ("key.pem", "-----BEGIN PRIVATE KEY-----", "private-key", 1),
    (".env.production", "PORT=8080", "env-file", 1),
    ("app.py", "# a comment\neval(value)", "eval", 2),
    ("app.py", 'exec(value)', "exec", 1),
    ("app.py", "subprocess.run(\n    arguments,\n    shell=True,\n)", "shell", 1),
    ("db.py", 'query = "SELECT name FROM users " + fragment', "sql", 1),
    ("view.js", "node.innerHTML = value", "innerhtml", 1),
    ("deploy.sh", "chmod 777 app", "chmod", 1),
    ("Dockerfile", "FROM python\nUSER 0:100", "docker-root", 2),
    ("Dockerfile.prod", "FROM python\nCOPY . .", "docker-root", 1),
    ("cors.py", 'allow_origins=["*"]', "cors", 1),
])
def test_individual_rules(file, content, rule, line):
    findings, _ = scan_zip(archive([(file, content)]))
    assert [(item[0], item[2]) for item in findings] == [(rule, line)]


def test_expected_safe_patterns():
    findings, _ = scan_zip(archive([
        (".env.example", "PORT=8080"),
        ("Dockerfile", "FROM python AS build\nUSER root\nFROM python\nUSER 10001"),
        ("app.py", '# exec(value)\nsubprocess.run(arguments, shell=False)\nallow_origins=["https://example.org"]'),
        ("app.js", "node.textContent = value; node.innerHTML === expected;"),
    ]))
    assert findings == []


def test_context_routes_and_incomplete_scan():
    findings, coverage = scan_zip(archive([("app.py", "eval(value)")]))
    assert analyze(findings, coverage, Target.public, Sensitivity.high)["verdict"] == "BLOCK"
    assert analyze(findings, coverage, Target.mvp, Sensitivity.low)["verdict"] == "WARN"
    assert analyze([], coverage, Target.public, Sensitivity.high)["verdict"] == "PASS"
    assert analyze([], {**coverage, "limited": True}, Target.mvp, Sensitivity.low)["verdict"] == "WARN"


def test_diff_is_unified_and_secret_stays_out():
    secret = "AKIA" + "Q" * 16
    findings, coverage = scan_zip(archive([("app.sh", f'# {secret}\nchmod 777 app\n')]))
    output = analyze(findings, coverage, Target.public, Sensitivity.high)
    assert secret not in json.dumps(output)
    assert output["findings"][1]["remediation_diff"].endswith("@@ -2 +2 @@\n-chmod 777 app\n+chmod 700 app\n")


def test_root_and_health(client):
    response = client.get("/")
    assert response.status_code == 200
    assert 'aria-live="polite"' in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/health").json() == {"status": "ok"}


def test_zip_api_success(client):
    response = client.post("/api/scan/zip", data=CONTEXT, files={"file": ("app.zip", archive([("hello.py", 'print("hello")')]).getvalue())})
    assert response.status_code == 200, response.text
    assert response.json()["verdict"] == "PASS"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(("name", "contents", "target", "status"), [
    ("bad.zip", b"not zip", "public_cloud", 422),
    ("bad.txt", b"not zip", "public_cloud", 422),
    ("bad.zip", b"not zip", "unknown", 422),
    ("big.zip", b"a" * (MAX_ARCHIVE + 1), "public_cloud", 413),
], ids=["invalid-zip", "invalid-extension", "invalid-target", "oversized"])
def test_upload_validation(client, name, contents, target, status):
    response = client.post("/api/scan/zip", data={**CONTEXT, "deployment_target": target}, files={"file": (name, contents)})
    assert response.status_code == status


def test_chunked_request_limit(client):
    response = client.post(
        "/api/scan/github",
        headers={"Content-Type": "application/json"},
        content=iter([b"x" * 3000, b"x" * 3000]),
    )
    assert response.status_code == 413


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/a/b", "https://github.com.evil.test/a/b", "https://github.com@localhost/a/b",
    "http://github.com/a/b", "https://github.com/a/b/tree/main", "https://github.com/a/b?x=1",
])
def test_github_rejects_invalid_urls(client, url):
    assert client.post("/api/scan/github", json={**CONTEXT, "url": url}).status_code == 422


@pytest.mark.parametrize("allowed", [True, False])
def test_github_fetch_validates_redirect(client, monkeypatch, allowed):
    real_client = httpx.Client
    calls = []

    def handle(request):
        calls.append(request.url.host)
        if request.url.host == "api.github.com":
            host = "codeload.github.com" if allowed else "localhost"
            return httpx.Response(302, headers={"location": f"https://{host}/org/repo/legacy.zip/refs/heads/main"})
        return httpx.Response(200, stream=httpx.ByteStream(archive([("hello.txt", "hello")]).getvalue()))

    monkeypatch.setattr(main.httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs))
    response = client.post("/api/scan/github", json={**CONTEXT, "url": "https://github.com/org/repo"})
    assert response.status_code == (200 if allowed else 502), response.text
    assert calls == (["api.github.com", "codeload.github.com"] if allowed else ["api.github.com"])


@pytest.mark.parametrize("choices", [["identity", "payments", "access"], ["invalid", "payments", "access"]])
def test_gemini_only_receives_rule_ids_and_context(monkeypatch, choices):
    monkeypatch.setenv("GEMINI_API_KEY", "test")
    real_client = httpx.Client

    def handle(request):
        assert "sensitive-name.py" not in request.content.decode()
        assert "eval" in request.content.decode()
        response = {"candidates": [{"content": {"parts": [{"text": json.dumps(choices)}]}}]}
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(response).encode()))

    monkeypatch.setattr(ai_analyzer.httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs))
    findings, coverage = scan_zip(archive([("sensitive-name.py", "eval(value)")]))
    output = analyze(findings, coverage, Target.public, Sensitivity.high)
    assert output["verdict"] == "BLOCK"
    assert output["analysis_mode"] == ("deterministic" if choices[0] == "invalid" else "gemini_assisted")


def test_scan_saturation_returns_503_without_reading_upload(client):
    async def occupy_slots():
        main.app.state.scan_slots.acquire_nowait()
        main.app.state.scan_slots.acquire_nowait()

    async def release_slots():
        main.app.state.scan_slots.release()
        main.app.state.scan_slots.release()

    client.portal.call(occupy_slots)
    try:
        response = client.post("/api/scan/zip", data=CONTEXT, files={"file": ("sample.zip", b"")})
        assert response.status_code == 503
        assert client.get("/health").status_code == 200
    finally:
        client.portal.call(release_slots)


def test_large_multipart_header_has_early_rejection(client):
    response = client.post("/api/scan/zip", data=CONTEXT, files={"file": ("a" * 2500 + ".zip", b"")})
    assert response.status_code == 400



def test_test_files_are_optional_and_real_scanner_calls_remain_detectable():
    entries = [("tests/test_eval.py", "eval(value)"), ("scanner.py", 'pattern = "chmod 777 app"\neval(value)')]
    findings, _ = scan_zip(archive(entries))
    assert [(f[0], f[1]) for f in findings] == [("eval", "scanner.py")]
    findings, _ = scan_zip(archive(entries), include_tests=True)
    assert len(findings) == 2


def test_security_files_prioritized_before_cap():
    entries = [(f"a/{i}.txt", "text") for i in range(60)]
    entries += [("z/auth.py", "eval(value)"), ("z/Dockerfile", "FROM python")]
    findings, coverage = scan_zip(archive(entries))
    assert {finding[0] for finding in findings} == {"eval", "docker-root"}
    assert coverage["limited"]


def test_manifest_advice_does_not_block_clean_project():
    matches, coverage = scan_zip(archive([("requirements.txt", "fastapi>=0.1")]))
    report = analyze(matches, coverage, Target.public, Sensitivity.high)
    assert report["verdict"] == "PASS"
    assert any("version pin" in item for item in report["day1_hardening_checklist"])


def test_demo_and_include_tests_api(client):
    sample = client.get("/api/sample")
    response = client.post("/api/scan/zip", data=CONTEXT, files={"file": ("sample.zip", sample.content)})
    assert response.status_code == 200
    assert response.json()["verdict"] == "BLOCK"
    payload = archive([("tests/test_app.py", "eval(value)")]).getvalue()
    response = client.post("/api/scan/zip", data={**CONTEXT, "include_tests": "true"}, files={"file": ("sample.zip", payload)})
    assert response.json()["findings"][0]["rule_id"] == "eval"


def test_self_scan_passes_without_hiding_executable_calls():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    entries = [(str(path.relative_to(root)), path.read_bytes()) for path in root.rglob("*")
               if path.is_file() and path.suffix in {".py", ".js", ".html", ".css", ".md", ".txt"} and not {"__pycache__", ".venv", "venv", ".git", ".pytest_cache"}.intersection(path.parts)]
    matches, coverage = scan_zip(archive(entries))
    assert analyze(matches, coverage, Target.public, Sensitivity.high)["verdict"] == "PASS"
