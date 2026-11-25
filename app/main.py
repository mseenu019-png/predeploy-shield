"""Cloud Run HTTP entry point."""

from contextlib import asynccontextmanager
from pathlib import Path
import re
from tempfile import TemporaryFile
from time import monotonic
from urllib.parse import urlsplit

import anyio
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from python_multipart.multipart import parse_options_header
from python_multipart.exceptions import MultipartParseError
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser
from starlette.requests import ClientDisconnect
from starlette.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from .ai_analyzer import Sensitivity, Target, analyze
from .scanner import CHUNK, MAX_ARCHIVE, ScanError, scan_zip

STATIC = Path(__file__).resolve().parent.parent / "static"
UPLOAD_BODY_LIMIT = MAX_ARCHIVE + 16 * 1024
GITHUB_BODY_LIMIT = 4096
REPO_PATH = re.compile(r"/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100})/?")
CDN_PATH = re.compile(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:legacy\.zip|zip)(?:/[A-Za-z0-9_./%~-]*)?")
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


@asynccontextmanager
async def lifespan(app):
    app.state.scan_slots = anyio.Semaphore(2)
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(ScanError)
async def scan_error(request, error):
    return JSONResponse({"detail": str(error)}, status_code=error.status)


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


class ScanContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment_target: Target
    data_sensitivity: Sensitivity
    include_tests: bool = False


class GitHubInput(ScanContext):
    url: str = Field(max_length=250)


@asynccontextmanager
async def scan_slot(request):
    slots = request.app.state.scan_slots
    try:
        slots.acquire_nowait()
    except anyio.WouldBlock as exc:
        raise ScanError("Scan capacity is full. Try again shortly.", 503) from exc
    try:
        yield
    finally:
        slots.release()


async def bounded_body(request, limit):
    length = request.headers.get("content-length")
    if length is not None:
        if not length.isascii() or not length.isdecimal() or len(length) > 10:
            raise ScanError("Invalid Content-Length.", 400)
        if int(length) > limit:
            raise ScanError("Request exceeds the size limit.", 413)
    total = 0
    deadline = monotonic() + 15
    stream = request.stream()
    while True:
        try:
            with anyio.fail_after(max(0, deadline - monotonic())):
                chunk = await anext(stream)
        except StopAsyncIteration:
            break
        except TimeoutError as exc:
            raise ScanError("Request upload timed out.", 408) from exc
        except ClientDisconnect as exc:
            raise ScanError("Upload disconnected.", 400) from exc
        total += len(chunk)
        if total > limit:
            raise ScanError("Request exceeds the size limit.", 413)
        for offset in range(0, len(chunk), CHUNK):
            yield chunk[offset:offset + CHUNK]


class UploadParser(MultiPartParser):
    spool_max_size = CHUNK

    def on_part_begin(self):
        super().on_part_begin()
        self.header_bytes = 0

    def count_header(self, length):
        self.header_bytes += length
        if self.header_bytes > 2048:
            raise MultiPartException("Multipart part headers are too large.")

    def on_header_field(self, data, start, end):
        self.count_header(end - start)
        super().on_header_field(data, start, end)

    def on_header_value(self, data, start, end):
        self.count_header(end - start)
        super().on_header_value(data, start, end)

    async def parse(self):
        try:
            return await super().parse()
        except BaseException:
            for file in self._files_to_close_on_error:
                file.close()
            raise


@app.post("/api/scan/zip")
async def scan_upload(request: Request):
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "multipart/form-data":
        raise ScanError("Send the ZIP as multipart/form-data.", 415)
    _, options = parse_options_header(request.headers["content-type"])
    if not 0 < len(options.get(b"boundary", b"")) <= 70:
        raise ScanError("Invalid multipart boundary.", 400)
    async with scan_slot(request):
        parser = UploadParser(request.headers, bounded_body(request, UPLOAD_BODY_LIMIT), max_files=1, max_fields=3, max_part_size=256)
        try:
            form = await parser.parse()
        except (MultiPartException, MultipartParseError) as exc:
            raise ScanError("Invalid ZIP upload form.", 400) from exc
        try:
            file = form.get("file")
            if not isinstance(file, UploadFile) or not (file.filename or "").lower().endswith(".zip"):
                raise ScanError("Select a .zip file.")
            if file.size is not None and file.size > MAX_ARCHIVE:
                raise ScanError("ZIP exceeds the 5 MB compressed limit.", 413)
            context = ScanContext(
                deployment_target=form.get("deployment_target"),
                data_sensitivity=form.get("data_sensitivity"),
                include_tests=form.get("include_tests", False),
            )
            matches, coverage = await run_in_threadpool(scan_zip, file.file, context.include_tests)
        except ValidationError as exc:
            raise ScanError("Choose a valid deployment target and data sensitivity.") from exc
        finally:
            with anyio.CancelScope(shield=True):
                await form.close()
        return await run_in_threadpool(analyze, matches, coverage, context.deployment_target, context.data_sensitivity)


def repository(url):
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ScanError("Enter a public GitHub repository URL.") from exc
    match = REPO_PATH.fullmatch(parsed.path)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or parsed.query or parsed.fragment or not match:
        raise ScanError("Enter a public repository URL in the form https://github.com/owner/repo.")
    owner, name = match.groups()
    name = name.removesuffix(".git")
    if name in {"", ".", ".."}:
        raise ScanError("Invalid repository name.")
    return owner, name


def fetch_report(context):
    owner, name = repository(context.url)
    url = f"https://api.github.com/repos/{owner}/{name}/zipball"
    headers = {"Accept-Encoding": "identity", "User-Agent": "PreDeploy-Shield"}
    deadline = monotonic() + 18
    try:
        with httpx.Client(timeout=httpx.Timeout(5, connect=3), follow_redirects=False) as client, TemporaryFile() as archive:
            with client.stream("GET", url, headers=headers) as initial:
                if initial.status_code == 404:
                    raise ScanError("Public repository not found.", 404)
                location = initial.headers.get("location", "")
                redirect = urlsplit(location)
                if (
                    initial.status_code not in {301, 302, 303, 307, 308}
                    or redirect.scheme != "https" or redirect.netloc != "codeload.github.com"
                    or redirect.query or redirect.fragment or not CDN_PATH.fullmatch(redirect.path)
                ):
                    raise ScanError("GitHub did not provide a permitted archive URL.", 502)
            with client.stream("GET", location, headers=headers) as response:
                if response.status_code != 200 or response.headers.get("content-encoding", "identity") != "identity":
                    raise ScanError("GitHub could not provide the archive.", 502)
                size = response.headers.get("content-length", "")
                if size.isdecimal() and (len(size) > 10 or int(size) > MAX_ARCHIVE):
                    raise ScanError("Repository archive exceeds 5 MB.", 413)
                written = 0
                for chunk in response.iter_raw():
                    if monotonic() > deadline:
                        raise ScanError("GitHub archive download timed out.", 504)
                    written += len(chunk)
                    if written > MAX_ARCHIVE:
                        raise ScanError("Repository archive exceeds 5 MB.", 413)
                    archive.write(chunk)
            matches, coverage = scan_zip(archive, context.include_tests)
    except httpx.TimeoutException as exc:
        raise ScanError("GitHub archive download timed out.", 504) from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise ScanError("GitHub archive download failed.", 502) from exc
    return analyze(matches, coverage, context.deployment_target, context.data_sensitivity)


@app.post("/api/scan/github")
async def scan_github(request: Request):
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise ScanError("Send repository details as JSON.", 415)
    async with scan_slot(request):
        data = bytearray()
        async for chunk in bounded_body(request, GITHUB_BODY_LIMIT):
            data.extend(chunk)
        try:
            context = GitHubInput.model_validate_json(data)
        except ValidationError as exc:
            raise ScanError("Enter a repository URL and choose a valid deployment context.") from exc
        return await run_in_threadpool(fetch_report, context)


@app.get("/api/sample")
def sample_project():
    from io import BytesIO
    from zipfile import ZipFile
    from fastapi.responses import Response

    archive = BytesIO()
    with ZipFile(archive, "w") as sample:
        sample.writestr("app.py", "def calculate(value):\n    return eval(value)\n")
        sample.writestr("deploy.sh", "chmod 777 app\n")
        sample.writestr("Dockerfile", "FROM python:3.11-slim\nCOPY . /app\n")
    return Response(archive.getvalue(), media_type="application/zip")
