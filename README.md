# PreDeploy Shield

PreDeploy Shield gives developers a release gate for common day-one security mistakes. Upload a project ZIP or point it at a public GitHub repository, describe the deployment environment and the data it handles, and get a verdict with file locations, risk explanations and a hardening checklist.

## Run locally

Use Python 3.11 from the repository root.

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port "${PORT:-8080}"
```

Open http://127.0.0.1:8080. Select **ZIP upload** or **GitHub URL**, choose a deployment target and data sensitivity, then run the scan. With the report open, expand individual findings to see their remediation.

Set `GEMINI_API_KEY` in the server's environment to enable checklist prioritization. `.env.example` lists the supported variables. For local development you can copy it to a gitignored `.env` and explicitly export its values before startup. The app reads environment variables directly.

## API

| Endpoint | Input |
| --- | --- |
| `GET /` | Buildless frontend |
| `GET /health` | Returns `{"status":"ok"}` |
| `POST /api/scan/zip` | Multipart `file`, `deployment_target`, `data_sensitivity` |
| `POST /api/scan/github` | JSON `url`, `deployment_target`, `data_sensitivity` |

Deployment targets are `public_cloud`, `internal_tool` and `hackathon_mvp`. Sensitivity levels are `high_auth_payments`, `moderate_user_data` and `low_public_static`.

```sh
curl --fail-with-body http://127.0.0.1:8080/api/scan/zip \
  -F file=@project.zip \
  -F deployment_target=public_cloud \
  -F data_sensitivity=high_auth_payments
```

The report contains `verdict`, `risk_score`, `executive_summary`, `findings`, `day1_hardening_checklist`, `coverage`, and `analysis_mode`. Each finding includes its rule ID, severity, file, line, CWE or category, risk explanation, remediation guidance and a nullable unified diff. A narrowly scoped permission fix can produce a patch. Review the proposed permissions against the runtime identity before applying it. Findings that require application context or credential rotation use written guidance.

Invalid inputs return 400 or 422, unsupported media types return 415, limits return 413, and saturated instances return 503. GitHub not-found and upstream errors return 404 and 502/504 respectively. Errors use a JSON `detail` string.

## Analysis and resource limits

1. **Static inspection.** Validate ZIP metadata and every entry path before reading any member. Reject traversal, special files, duplicate paths, encrypted members, unsupported archive layouts and oversized declarations. Read eligible UTF-8 text using bounded chunks and a service-owned scratch path. Pattern matching covers cloud/API credentials, JWT signing secrets, private keys, environment files, SQL construction, unsafe DOM sinks, broad file permissions, Docker runtime users and wildcard CORS. Python AST inspection identifies direct `eval`, `exec` and `subprocess.*(…, shell=True)` calls. Uploaded code is never executed or imported.
2. **Context and deployment gate.** Rank findings by severity and apply a local gate. The largest severity contributes 85 for critical, 58 for high, or 26 for medium. Additional findings can add up to 24 points, with the final score capped at 100. Block thresholds are 55 for public cloud with high-sensitivity data, 70 for remaining public cloud or high-sensitivity contexts, and 80 otherwise. An observed finding below the threshold, or insufficient coverage, produces WARN. An inspected project with no reported finding or coverage limitation produces PASS.
3. **Optional Gemini ranking.** Gemini receives fixed rule IDs and deployment context and selects three checklist items from a fixed catalog. Its output is validated, and missing credentials, timeouts, invalid output or failures trigger the deterministic checklist. Source, paths and credential values stay out of Gemini requests. AI output cannot alter findings, patches, scores or the deployment verdict.

| Resource | Bound |
| --- | --- |
| Compressed archive | 5,000,000 bytes for ZIP and GitHub, with 16 KiB extra for multipart framing |
| ZIP metadata | 1,000 directory entries and a 512 KiB central directory |
| Declared expanded data | 10 MiB across the archive |
| Inspection | 50 eligible text files, 512 KiB per member, AST limited to 64 KiB of decoded Python characters |
| Report | 100 findings, up to one per rule per file, plus coverage counts |
| Concurrent intake and processing | Two scans per instance with one server worker |
| Spooling and extraction | Uploads roll over at 64 KiB. GitHub downloads stream into a temporary file. One extracted file is overwritten between members. |
| External response | GitHub archive cap and time budget, Gemini response capped at 64 KiB |

Cloud Run's writable filesystem counts toward instance memory. Temporary file sizes are bounded accordingly. Files are cleaned up on success and failure, and archives are closed before Gemini contact. The service has no database or scan history. GitHub requests are unauthenticated and limited to an HTTPS GitHub API endpoint and a single validated HTTPS codeload redirect. The client renders finding text with DOM text nodes and API responses disable caching.

This is a bounded pattern scanner. Coverage excludes unsupported file formats, nested archives, common dependency/build directories and binary data. It does not inspect dependency advisories, validate credentials, trace data flow, or infer the configured user of an arbitrary base image. Treat PASS as the result of the inspected scope. GitHub's unauthenticated rate limit applies. For a multi-tenant deployment that processes confidential archives, add IAM access controls and choose quotas that fit expected traffic.

## Test

```sh
python -m pip install pytest==8.4.2
python -m pytest -q
```

Tests use synthetic data and mock external integrations. They cover archive safety and limits, detection and negative cases, the context gate, request validation, GitHub redirect restrictions, and Gemini fallback. The frontend uses keyboard-operable tabs, explicit labels, visible focus and live status announcements.

## Container and Cloud Run

```sh
docker build -t predeploy-shield .
docker run --rm -p 8080:8080 predeploy-shield
```

From the source root, with a configured Google Cloud project and Cloud Run build permissions, run:

```sh
gcloud run deploy predeploy-shield --source . --allow-unauthenticated --concurrency 8 --memory 512Mi --timeout 60s
```

The single Dockerfile runs a non-root Python 3.11 process and honors the injected `PORT`. GitHub ZIP and Gemini are optional outbound HTTPS dependencies. To enable Gemini on Cloud Run, bind `GEMINI_API_KEY` from Secret Manager with `--set-secrets GEMINI_API_KEY=gemini-api-key:latest` and grant the Cloud Run service identity access to that secret. The service works without the binding.

## Updated scan workflow

Tests are excluded by default. Select **Include test files** to inspect them.
Both scan APIs accept the optional boolean field `include_tests`.
Python executable-pattern checks mask strings and comments, while credential
checks still inspect string contents. This avoids treating detector descriptions
as executed code. Files named scanner.py receive the same checks as other Python files.

Credential files, Docker and package manifests, then auth/config filenames are
prioritized ahead of the 50-file cap. Coverage still reports skipped files.
Manifest advice flags unpinned Python requirements and flexible JavaScript runtime
versions. This is manifest hygiene analysis. Known-vulnerability databases,
transitive dependency resolution, multi-file taint analysis, SSRF and IDOR
detection require additional tooling or manual review.

The dark interface includes a reduced-motion-aware risk gauge, severity counts
and filters, a sample ZIP, bounded code excerpts, copyable supported patches and
Markdown export. A PASS gate applies to the inspected patterns and scope.
Code excerpts redact recognized credential formats. Secrets findings omit excerpts.
Review any displayed excerpt before sharing the exported report.

Gemini integration continues to prioritize a fixed hardening checklist.
It does not generate contextual explanations or arbitrary patches.
A missing or failed API key leaves deterministic analysis active.
To enable Gemini locally in Windows Command Prompt, set the environment
variable in the same terminal before starting the app.

```cmd
set GEMINI_API_KEY=your_key_here
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8080
```

Open http://127.0.0.1:8080 once the server starts.
