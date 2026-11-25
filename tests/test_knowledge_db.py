"""Unit tests for the SQLite knowledge base and calibration endpoint."""

import sqlite3

from fastapi.testclient import TestClient

from app import knowledge_db, main


def test_init_db_seeds_cwe_and_calibration(tmp_path):
    db_file = tmp_path / "shield_kb.db"
    knowledge_db.init_db(db_file)
    assert db_file.exists()

    with sqlite3.connect(db_file) as conn:
        cwe_count = conn.execute("SELECT COUNT(*) FROM cwe_knowledge").fetchone()[0]
        cal_count = conn.execute("SELECT COUNT(*) FROM calibration_feedback").fetchone()[0]
    assert cwe_count >= 14
    assert cal_count >= 6

    # Re-running init_db must be idempotent and not duplicate calibration rows.
    knowledge_db.init_db(db_file)
    with sqlite3.connect(db_file) as conn:
        assert conn.execute("SELECT COUNT(*) FROM calibration_feedback").fetchone()[0] == cal_count


def test_get_relevant_knowledge_returns_matching_cwe_and_examples(tmp_path):
    db_file = tmp_path / "shield_kb.db"
    knowledge_db.init_db(db_file)

    kb = knowledge_db.get_relevant_knowledge(
        ["aws-key", "sql"], "public_cloud", "high_auth_payments", db_path=db_file
    )
    assert set(kb["cwe_knowledge"].keys()) == {"aws-key", "sql"}
    assert kb["cwe_knowledge"]["aws-key"]["cwe_id"] == "CWE-798"
    assert "parameterized" in kb["cwe_knowledge"]["sql"]["secure_fix_template"].lower()
    assert 1 <= len(kb["calibration_examples"]) <= 6
    assert kb["calibration_examples"][0]["deployment_target"] == "public_cloud"


def test_record_calibration_feedback_persists_row(tmp_path):
    db_file = tmp_path / "shield_kb.db"
    knowledge_db.init_db(db_file)

    row_id = knowledge_db.record_calibration_feedback(
        code_snippet='TEST_TOKEN = "dummy-value"',
        file_path="tests/fixtures.py",
        deployment_target="internal_tool",
        data_sensitivity="low_public_static",
        expected_verdict="PASS",
        rationale="Dummy fixture token in tests.",
        db_path=db_file,
    )
    assert row_id > 0

    kb = knowledge_db.get_relevant_knowledge([], "internal_tool", "low_public_static", db_path=db_file)
    assert any(item["id"] == row_id and item["expected_verdict"] == "PASS" for item in kb["calibration_examples"])


def test_calibrate_endpoint_persists_feedback(tmp_path, monkeypatch):
    db_file = tmp_path / "shield_kb.db"
    knowledge_db.init_db(db_file)
    monkeypatch.setattr(knowledge_db, "DEFAULT_DB_PATH", db_file)

    with TestClient(main.app) as client:
        response = client.post(
            "/api/calibrate",
            json={
                "code_snippet": 'API_KEY = "example-only"',
                "file_path": "docs/sample.py",
                "deployment_target": "hackathon_mvp",
                "data_sensitivity": "low_public_static",
                "classification": "false_positive",
                "rationale": "Documentation placeholder.",
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "recorded"
    assert payload["expected_verdict"] == "PASS"
    assert payload["id"] > 0
