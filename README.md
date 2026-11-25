# PreDeploy Shield

**Live Deployment:** [https://predeploy-shield.onrender.com/](https://predeploy-shield.onrender.com/)

PreDeploy Shield is a context-aware pre-deployment security gate and archive hardener for developers shipping web apps and cloud services. Upload a project ZIP or point it at a public GitHub repository, specify your deployment target and data sensitivity, and receive a deterministic release verdict (`BLOCK`, `WARN`, or `PASS`), CWE-mapped findings with unified diffs, a prioritized Day-1 hardening checklist, and an optional one-click auto-hardened ZIP bundle.

## Your Chosen Vertical

**Vertical:** Cybersecurity, DevSecOps & Developer Productivity Assistant

**Target User Persona:** Solo developers, hackathon builders, and release engineers shipping cloud applications who need fast, actionable pre-release security feedback without setting up heavy CI/CD pipelines.

PreDeploy Shield acts as a smart, context-aware assistant rather than a noisy static linter. It dynamically adapts its risk scoring, release verdicts (`BLOCK` / `WARN` / `PASS`), and Day-1 hardening checklists based on two deployment parameters:
- **Deployment Target:** `public_cloud`, `internal_tool`, or `hackathon_mvp`
- **Data Sensitivity:** `high_auth_payments`, `moderate_user_data`, or `low_public_static`

For example, a finding that triggers an immediate `BLOCK` for a `public_cloud` service handling `high_auth_payments` data (threshold `55`) may produce a `WARN` for an internal prototype (threshold `80`), while still surfacing clear remediation steps and copyable patches.

## Approach and Logic

PreDeploy Shield uses a four-stage defense-in-depth pipeline:

1. **Zero-Execution Sandbox Archive Validation:** Before reading any file contents, `app/scanner.py` runs ZIP preflight checks on the central directory, rejects Zip Slip path traversal, symlinks, encrypted entries, and oversized archives (`5 MB` compressed / `10 MiB` expanded / `1,000` entries). Uploaded code is never executed or imported.
2. **Python AST + Regex + Config Static Inspection:** Eligible UTF-8 files (up to `50` prioritized files) are inspected using Python `ast` parsing (`eval`, `exec`, `subprocess(..., shell=True)`), compiled regex rules (AWS/Google/OpenAI keys, JWT secrets, private keys, SQL concatenation, `innerHTML` XSS, world-writable `0777` file modes, wildcard CORS), and Dockerfile `USER` / `.env` checks. Python executable-pattern checks mask string literals and comments so detector descriptions and documentation are not flagged as executed code.
3. **Context-Calibrated Risk Scoring (0–100) & Blocking Thresholds:** Findings are weighted by severity (`critical: 85`, `high: 58`, `medium: 26`, plus up to `24` points from additional findings, capped at `100`) and evaluated against context-sensitive blocking thresholds:
   - `55` for `public_cloud` + `high_auth_payments`
   - `70` for remaining `public_cloud` or `high_auth_payments` contexts
   - `80` for `internal_tool` / `hackathon_mvp` with moderate or low sensitivity
4. **SQLite CWE Knowledge & Calibration Lookup + Privacy-Preserving Gemini Prioritization:** `app/knowledge_db.py` maintains a local SQLite database (`data/shield_kb.db`) with CWE remediation templates (`cwe_knowledge`) and ground-truth few-shot examples (`calibration_feedback`). These records enrich deterministic findings and ground `gemini-2.5-flash` when `GEMINI_API_KEY` is configured to prioritize the top three Day-1 hardening checklist items. Missing keys, timeouts, or invalid responses fall back cleanly to deterministic ranking.

## How the Solution Works

1. **Configure Scan Context:** On the landing page (or via the interactive 3D telemetry stage and live threat simulation presets), the user selects **ZIP upload** (drag-and-drop or sample vulnerable project) or **GitHub URL**, chooses `deployment_target` and `data_sensitivity`, and optionally toggles **Include test files**.
2. **Run Static & AST Inspection:** `POST /api/scan/zip` or `POST /api/scan/github` streams the archive under strict memory/concurrency bounds, runs `scan_zip()`, and passes matched rule IDs and coverage to `analyze()`.
3. **Review Findings, Diffs & Calibrate:** The UI renders a radial risk gauge, `BLOCK` / `WARN` / `PASS` verdict badge, severity filters, CWE-mapped findings with unified `chmod` patches, and a **"Mark as false positive (improve accuracy)"** button backed by `POST /api/calibrate` to record verified feedback into `data/shield_kb.db`.
4. **Export Report or Auto-Hardened ZIP Bundle:** Users can export a Markdown audit (`predeploy-shield-report.md`) or, for `BLOCK` / `WARN` ZIP scans, click **"Download protected archive (.zip)"** (`POST /api/harden/zip` via `app/hardener.py`). This builds an in-memory `<name>-shielded.zip` with committed secret literals replaced by `os.getenv(...)` / `process.env...` placeholders, `# SECURITY TODO [PreDeploy Shield]` comments above flagged `shell=True` / `exec` / SQLi lines, world-writable `777` permissions tightened to `700`, and three injected protection files: `SECURITY.md`, `.env.example`, and `.predeploy-shield.json` (with SHA-256 hashes of all bundled files).

## Assumptions Made

- **Bounded Static Scope:** Scans are capped at `5 MB` compressed, `10 MiB` expanded, `1,000` ZIP directory entries, and `50` prioritized text files (`512 KiB` per file, `64 KiB` for Python AST). Nested archives, binary files, and directories like `node_modules/`, `.venv/`, and `dist/` are skipped.
- **Zero-Execution Boundary:** Because uploaded code is never run or imported, PreDeploy Shield does not perform runtime taint tracing, transitive dependency vulnerability resolution, or live credential probing against external APIs. `PASS` reflects the inspected static scope.
- **Unauthenticated Public GitHub API Constraints:** GitHub scans (`POST /api/scan/github`) fetch only public repositories via `https://api.github.com/repos/{owner}/{name}/zipball` with a single validated `codeload.github.com` redirect and are subject to GitHub's unauthenticated rate limits.
- **Privacy-Preserving AI Boundary:** Raw user source code, file paths, and secret values are never sent to Gemini. Only matched rule IDs, deployment context, and authoritative CWE/calibration records from `data/shield_kb.db` are included in the Gemini request.

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
| `POST /api/harden/zip` | Multipart `file`, `deployment_target`, `data_sensitivity` (returns hardened `-shielded.zip`) |
| `POST /api/calibrate` | JSON `code_snippet`, `file_path`, `deployment_target`, `data_sensitivity`, `classification` |

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
3. **Optional Gemini ranking & SQLite knowledge base.** `app/knowledge_db.py` initializes `data/shield_kb.db` with CWE remediation templates and few-shot calibration examples. Gemini receives fixed rule IDs, deployment context, and retrieved knowledge/calibration records to select three checklist items from a fixed catalog. Its output is validated, and missing credentials, timeouts, invalid output or failures trigger the deterministic checklist. User source, paths and credential values stay out of Gemini requests. AI output cannot alter findings, patches, scores or the deployment verdict.

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
