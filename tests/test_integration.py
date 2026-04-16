"""End-to-end integration tests (three-board architecture).

Both Semgrep and Monday.com HTTP calls are intercepted by pytest-httpx.
"""

import json
from datetime import date
from pathlib import Path

import pytest

import sync

TODAY = str(date.today())

SEMGREP_FINDINGS_URL = "https://semgrep.dev/api/v1/deployments/acme-corp/findings"
SEMGREP_SECRETS_URL = "https://semgrep.dev/api/v1/deployments/20169/secrets"
MONDAY_URL = "https://api.monday.com/v2"


def _columns_resp(titles):
    return {
        "data": {
            "boards": [{
                "columns": [{"id": f"col_{i}", "title": t} for i, t in enumerate(titles)]
            }]
        }
    }


SAST_COLUMNS_RESP = _columns_resp([
    "Finding ID", "Severity", "Confidence", "Rule", "File", "Repo",
    "AI Verdict", "CWE", "Message",
])
SCA_COLUMNS_RESP = _columns_resp([
    "Finding ID", "Severity", "Rule", "File", "Repo",
    "CVE", "Reachability", "Package", "Version",
])
SECRETS_COLUMNS_RESP = _columns_resp([
    "Finding ID", "Severity", "Rule", "File", "Repo", "Validation State",
])


def _create_item_resp(item_id):
    return {"data": {"create_item": {"id": item_id}}}


def _sast_finding(fid, severity="HIGH"):
    return {
        "id": fid, "rule_name": f"rule.{fid}", "severity": severity,
        "location": {"file_path": f"src/{fid}.py", "line": 1},
        "repository": {"name": "acme"},
        "confidence": "high", "triage_state": "untriaged",
        "rule": {"cwe_names": ["CWE-79"]},
        "assistant": {"autotriage": {"verdict": "true_positive", "reason": ""}},
    }


def _sca_finding(fid, severity="HIGH"):
    return {
        "id": fid, "rule_name": f"ssc.{fid}", "severity": severity,
        "location": {"file_path": "package-lock.json", "line": 1},
        "repository": {"name": "acme"},
        "vulnerability_identifier": "CVE-2021-1234",
        "reachability": "reachable",
        "found_dependency": {"package": "lodash", "version": "4.17.20", "ecosystem": "npm"},
    }


def _secret_finding(fid, severity="CRITICAL"):
    return {
        "id": fid, "rule_name": f"secret.{fid}", "severity": severity,
        "location": {"file_path": ".env", "line": 1},
        "repository": {"name": "acme"},
        "validation_state": "confirmed_valid",
    }


@pytest.fixture()
def env_vars(monkeypatch):
    monkeypatch.setattr("sync.load_dotenv", lambda **kw: None)
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "tok")
    monkeypatch.setenv("SEMGREP_DEPLOYMENT_SLUG", "acme-corp")
    monkeypatch.setenv("SEMGREP_DEPLOYMENT_ID", "20169")
    monkeypatch.setenv("MONDAY_API_TOKEN", "mon-tok")
    monkeypatch.setenv("MONDAY_BOARD_ID_SAST", "1001")
    monkeypatch.setenv("MONDAY_BOARD_ID_SCA", "1002")
    monkeypatch.setenv("MONDAY_BOARD_ID_SECRETS", "1003")


@pytest.fixture()
def state_file(tmp_path) -> Path:
    return tmp_path / "state.json"


def _add_semgrep_pages(httpx_mock, issue_type, findings):
    httpx_mock.add_response(
        url=f"{SEMGREP_FINDINGS_URL}?page=0&page_size=100&status=open&issue_type={issue_type}",
        json={"findings": findings},
    )
    if findings:
        httpx_mock.add_response(
            url=f"{SEMGREP_FINDINGS_URL}?page=1&page_size=100&status=open&issue_type={issue_type}",
            json={"findings": []},
        )


def _add_secrets(httpx_mock, secrets):
    httpx_mock.add_response(
        url=f"{SEMGREP_SECRETS_URL}?limit=100",
        json={"secrets": secrets, "cursor": ""},
    )


def _add_monday_responses(httpx_mock, n_sast=0, n_sca=0, n_secrets=0):
    """Register Monday responses in actual call order: col query → creates per board."""
    counter = [0]

    def next_id():
        counter[0] += 1
        return f"m{counter[0]}"

    # SAST board: column query then creates
    if n_sast > 0:
        httpx_mock.add_response(url=MONDAY_URL, json=SAST_COLUMNS_RESP)
        for _ in range(n_sast):
            httpx_mock.add_response(url=MONDAY_URL, json=_create_item_resp(next_id()))

    # SCA board: column query then creates
    if n_sca > 0:
        httpx_mock.add_response(url=MONDAY_URL, json=SCA_COLUMNS_RESP)
        for _ in range(n_sca):
            httpx_mock.add_response(url=MONDAY_URL, json=_create_item_resp(next_id()))

    # Secrets board: column query then creates
    if n_secrets > 0:
        httpx_mock.add_response(url=MONDAY_URL, json=SECRETS_COLUMNS_RESP)
        for _ in range(n_secrets):
            httpx_mock.add_response(url=MONDAY_URL, json=_create_item_resp(next_id()))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_full_sync_run(httpx_mock, env_vars, state_file):
    _add_semgrep_pages(httpx_mock, "sast", [_sast_finding("f1"), _sast_finding("f2")])
    _add_semgrep_pages(httpx_mock, "sca", [_sca_finding("f3")])
    _add_secrets(httpx_mock, [_secret_finding("s1")])
    _add_monday_responses(httpx_mock, n_sast=2, n_sca=1, n_secrets=1)

    sync.run(state_path=state_file)

    state = json.loads(state_file.read_text())
    assert len(state["synced"]) == 4
    assert state["synced"]["f1"]["board"] == "SAST"
    assert state["synced"]["f3"]["board"] == "SCA"
    assert state["synced"]["s1"]["board"] == "Secrets"
    assert state["daily"][TODAY] == 4


def test_idempotent_second_run(httpx_mock, env_vars, state_file):
    # First run
    _add_semgrep_pages(httpx_mock, "sast", [_sast_finding("f1")])
    _add_semgrep_pages(httpx_mock, "sca", [])
    _add_secrets(httpx_mock, [])
    _add_monday_responses(httpx_mock, n_sast=1)
    sync.run(state_path=state_file)

    # Second run — same finding, should be skipped
    _add_semgrep_pages(httpx_mock, "sast", [_sast_finding("f1")])
    _add_semgrep_pages(httpx_mock, "sca", [])
    _add_secrets(httpx_mock, [])
    sync.run(state_path=state_file)

    state = json.loads(state_file.read_text())
    assert len(state["synced"]) == 1
    assert state["daily"][TODAY] == 1


@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
def test_partial_failure_recovery(httpx_mock, env_vars, state_file):
    from unittest.mock import patch, MagicMock
    from monday_client import MondayAPIError

    findings = [_sast_finding(str(i)) for i in range(1, 4)]
    _add_semgrep_pages(httpx_mock, "sast", findings)
    _add_semgrep_pages(httpx_mock, "sca", [])
    _add_secrets(httpx_mock, [])

    monday = MagicMock()
    monday.get_column_map.return_value = {"Finding ID": "c0", "Severity": "c1", "Rule": "c2", "File": "c3", "Repo": "c4"}
    monday.create_item.side_effect = [
        ("m1", 0), ("m2", 0), MondayAPIError("fail"),
    ]

    board_map = {1001: monday, 1002: MagicMock(), 1003: MagicMock()}
    with patch("sync.MondayClient", side_effect=lambda token, board_id: board_map[board_id]):
        sync.run(state_path=state_file)

    state = json.loads(state_file.read_text())
    assert "1" in state["synced"]
    assert "2" in state["synced"]
    assert "3" not in state["synced"]


@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
def test_secrets_cursor_exhausted(httpx_mock, env_vars, state_file):
    _add_semgrep_pages(httpx_mock, "sast", [])
    _add_semgrep_pages(httpx_mock, "sca", [])

    httpx_mock.add_response(
        url=f"{SEMGREP_SECRETS_URL}?limit=100",
        json={"secrets": [_secret_finding("s1")], "cursor": "abc"},
    )
    httpx_mock.add_response(
        url=f"{SEMGREP_SECRETS_URL}?limit=100&cursor=abc",
        json={"secrets": [_secret_finding("s2")], "cursor": ""},
    )

    _add_monday_responses(httpx_mock, n_secrets=2)

    sync.run(state_path=state_file)

    state = json.loads(state_file.read_text())
    assert set(state["synced"].keys()) == {"s1", "s2"}
    assert all(s["board"] == "Secrets" for s in state["synced"].values())
