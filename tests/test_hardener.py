"""Unit and API tests for the in-memory archive hardener."""

import io
import json
from zipfile import ZipFile

from fastapi.testclient import TestClient

from app import main


def _make_zip(entries):
    buf = io.BytesIO()
    with ZipFile(buf, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def test_harden_zip_injects_protection_files_and_redacts_secrets():
    fake_openai = "sk-" + "proj-" + "Y" * 28
    payload = _make_zip([
        ("app.py", f'API_KEY = "{fake_openai}"\nprint("ok")\n'),
        ("deploy.sh", "chmod 777 app\n"),
        ("README.md", "# Demo App\n"),
    ])

    with TestClient(main.app) as client:
        response = client.post(
            "/api/harden/zip",
            data={
                "deployment_target": "public_cloud",
                "data_sensitivity": "high_auth_payments",
            },
            files={"file": ("my-demo.zip", payload, "application/zip")},
        )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert 'filename="my-demo-shielded.zip"' in response.headers["content-disposition"]

    with ZipFile(io.BytesIO(response.content)) as out_zip:
        names = set(out_zip.namelist())
        assert {"SECURITY.md", ".env.example", ".predeploy-shield.json"}.issubset(names)
        assert {"app.py", "deploy.sh", "README.md"}.issubset(names)

        app_py = out_zip.read("app.py").decode("utf-8")
        assert fake_openai not in app_py
        assert 'os.getenv("API_KEY"' in app_py
        assert 'print("ok")' in app_py

        deploy_sh = out_zip.read("deploy.sh").decode("utf-8")
        assert "chmod 700 app" in deploy_sh

        readme = out_zip.read("README.md").decode("utf-8")
        assert readme == "# Demo App\n"

        env_example = out_zip.read(".env.example").decode("utf-8")
        assert "API_KEY=" in env_example

        manifest = json.loads(out_zip.read(".predeploy-shield.json").decode("utf-8"))
        assert manifest["deployment_target"] == "public_cloud"
        assert manifest["data_sensitivity"] == "high_auth_payments"
        assert manifest["original_verdict"] == "BLOCK"
        assert "app.py" in manifest["sha256"]
        assert "SECURITY.md" in manifest["sha256"]


def test_harden_zip_blocks_zip_slip():
    payload = _make_zip([("../outside.py", "print('evil')\n")])
    with TestClient(main.app) as client:
        response = client.post(
            "/api/harden/zip",
            data={
                "deployment_target": "public_cloud",
                "data_sensitivity": "moderate_user_data",
            },
            files={"file": ("evil.zip", payload, "application/zip")},
        )
    assert response.status_code == 422
    assert "unsafe path" in response.json()["detail"].lower()
