"""Unit tests for sync.py orchestration logic (three-board architecture).

Both SemgrepClient and MondayClient are mocked — no HTTP traffic.
"""

import json
import os
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from semgrep_client import Finding
from monday_client import MondayAPIError
import sync

TODAY = str(date.today())

# Column maps per board type (subset — just enough for tests)
SAST_COL_MAP = {
    "Finding ID": "text_fid", "Severity": "text_sev", "Rule": "text_rule",
    "File": "text_file", "Repo": "text_repo", "AI Verdict": "text_aiv",
    "CWE": "text_cwe", "Semgrep URL": "text_semgrep_url",
}
SCA_COL_MAP = {
    "Finding ID": "text_fid", "Severity": "text_sev", "Rule": "text_rule",
    "File": "text_file", "Repo": "text_repo", "CVE": "text_cve",
    "Reachability": "text_reach", "Package": "text_pkg",
    "Semgrep URL": "text_semgrep_url",
}
SECRETS_COL_MAP = {
    "Finding ID": "text_fid", "Severity": "text_sev", "Rule": "text_rule",
    "File": "text_file", "Repo": "text_repo", "Validation State": "text_val",
    "Semgrep URL": "text_semgrep_url",
}

SAST_FINDING = Finding(
    id="1001", rule_name="js.xss", severity="HIGH",
    file_path="src/app.js", line=42, repo="my-repo", finding_type="SAST",
    raw={
        "confidence": "high", "triage_state": "untriaged",
        "rule": {"cwe_names": ["CWE-79"], "owasp_names": ["A03:2021"]},
        "assistant": {"autotriage": {"verdict": "true_positive", "reason": ""}},
    },
)

SCA_FINDING = Finding(
    id="3001", rule_name="ssc.lodash", severity="HIGH",
    file_path="package-lock.json", line=1, repo="my-repo", finding_type="SCA",
    raw={
        "vulnerability_identifier": "CVE-2021-23337",
        "reachability": "reachable",
        "found_dependency": {"package": "lodash", "version": "4.17.20", "ecosystem": "npm"},
        "epss_score": {"score": 0.5, "percentile": 0.9},
    },
)

SECRET_FINDING = Finding(
    id="s-2001", rule_name="generic.aws-key", severity="CRITICAL",
    file_path=".env", line=3, repo="my-repo", finding_type="Secrets",
    raw={"validationState": "VALIDATION_STATE_CONFIRMED_VALID", "findingPathUrl": "https://github.com/org/repo/blob/abc/.env#L3"},
)


@pytest.fixture()
def env_vars(monkeypatch):
    monkeypatch.setattr("sync.load_dotenv", lambda **kw: None)
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "tok")
    monkeypatch.setenv("SEMGREP_DEPLOYMENT_SLUG", "acme")

    monkeypatch.setenv("MONDAY_API_TOKEN", "mon-tok")
    monkeypatch.setenv("MONDAY_BOARD_ID_SAST", "1001")
    monkeypatch.setenv("MONDAY_BOARD_ID_SCA", "1002")
    monkeypatch.setenv("MONDAY_BOARD_ID_SECRETS", "1003")


@pytest.fixture()
def state_file(tmp_path) -> Path:
    return tmp_path / "state.json"


def _mock_clients(sast=None, sca=None, secrets=None):
    """Return (mock_semgrep, {board_type: mock_monday}) with sensible defaults."""
    semgrep = MagicMock()
    semgrep.fetch_findings.side_effect = lambda issue_type, **kw: (
        sast if issue_type == "sast" else sca
    ) or []
    semgrep.fetch_secrets.return_value = secrets or []

    monday_mocks = {}
    for board_type, col_map in [("SAST", SAST_COL_MAP), ("SCA", SCA_COL_MAP), ("Secrets", SECRETS_COL_MAP)]:
        m = MagicMock()
        m.get_column_map.return_value = col_map
        m.create_item.return_value = (f"m-{board_type}", 0)
        m.create_update.return_value = f"u-{board_type}"
        monday_mocks[board_type] = m

    return semgrep, monday_mocks


def _patch_clients(semgrep, monday_mocks):
    """Return context managers that patch SemgrepClient and MondayClient."""
    board_id_to_mock = {
        1001: monday_mocks["SAST"],
        1002: monday_mocks["SCA"],
        1003: monday_mocks["Secrets"],
    }

    def monday_factory(token, board_id):
        return board_id_to_mock[board_id]

    return (
        patch("sync.SemgrepClient", return_value=semgrep),
        patch("sync.MondayClient", side_effect=monday_factory),
    )


# ---------------------------------------------------------------------------
# Core sync behaviour
# ---------------------------------------------------------------------------

def test_new_finding_creates_item(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    mondays["SAST"].create_item.assert_called_once()
    mondays["SCA"].create_item.assert_not_called()
    state = json.loads(state_file.read_text())
    assert "1001" in state["synced"]
    assert state["synced"]["1001"]["board"] == "SAST"


def test_existing_finding_skipped(env_vars, state_file):
    state_file.write_text(json.dumps({
        "version": 2,
        "synced": {"1001": {"monday_item_id": "existing", "board": "SAST"}},
        "daily": {TODAY: 1},
    }))
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    mondays["SAST"].create_item.assert_not_called()


def test_state_persisted_on_success(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    state = json.loads(state_file.read_text())
    assert state["synced"]["1001"]["monday_item_id"] == "m-SAST"
    assert state["daily"][TODAY] == 1
    assert state["version"] == 2


def test_state_not_mutated_on_error(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    mondays["SAST"].create_item.side_effect = MondayAPIError("fail")
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    state = json.loads(state_file.read_text())
    assert "1001" not in state.get("synced", {})


# ---------------------------------------------------------------------------
# Multi-board routing
# ---------------------------------------------------------------------------

def test_all_three_types_routed_to_correct_boards(env_vars, state_file):
    semgrep, mondays = _mock_clients(
        sast=[SAST_FINDING], sca=[SCA_FINDING], secrets=[SECRET_FINDING],
    )
    mondays["SAST"].create_item.return_value = ("m1", 0)
    mondays["SCA"].create_item.return_value = ("m2", 0)
    mondays["Secrets"].create_item.return_value = ("m3", 0)
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    mondays["SAST"].create_item.assert_called_once()
    mondays["SCA"].create_item.assert_called_once()
    mondays["Secrets"].create_item.assert_called_once()

    state = json.loads(state_file.read_text())
    assert state["synced"]["1001"]["board"] == "SAST"
    assert state["synced"]["3001"]["board"] == "SCA"
    assert state["synced"]["s-2001"]["board"] == "Secrets"


# ---------------------------------------------------------------------------
# Mapper-specific field extraction
# ---------------------------------------------------------------------------

def test_sast_mapper_extracts_ai_verdict():
    _, col_vals = sync.sast_finding_to_item(SAST_FINDING, SAST_COL_MAP)
    assert col_vals[SAST_COL_MAP["AI Verdict"]] == {"label": "True Positive"}
    assert col_vals[SAST_COL_MAP["CWE"]] == "CWE-79"


def test_sca_mapper_extracts_reachability():
    _, col_vals = sync.sca_finding_to_item(SCA_FINDING, SCA_COL_MAP)
    assert col_vals[SCA_COL_MAP["CVE"]] == "CVE-2021-23337"
    assert col_vals[SCA_COL_MAP["Reachability"]] == {"label": "Reachable"}
    assert col_vals[SCA_COL_MAP["Package"]] == "lodash"


def test_secrets_mapper_extracts_validation():
    _, col_vals = sync.secrets_finding_to_item(SECRET_FINDING, SECRETS_COL_MAP)
    assert col_vals[SECRETS_COL_MAP["Validation State"]] == {"label": "Valid"}


# ---------------------------------------------------------------------------
# State migration v1 → v2
# ---------------------------------------------------------------------------

def test_state_v1_migrated_to_v2(tmp_path):
    v1_state = {"synced": {"old-id": "monday-123"}, "daily": {}}
    path = tmp_path / "state.json"
    path.write_text(json.dumps(v1_state))

    state = sync.load_state(path)
    assert state["version"] == 2
    assert state["synced"]["old-id"]["monday_item_id"] == "monday-123"
    assert state["synced"]["old-id"]["board"] == "unknown"


# ---------------------------------------------------------------------------
# Missing env vars
# ---------------------------------------------------------------------------

def test_missing_env_var_exits_early(tmp_path, monkeypatch):
    monkeypatch.setattr("sync.load_dotenv", lambda **kw: None)
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "tok")
    monkeypatch.setenv("SEMGREP_DEPLOYMENT_SLUG", "acme")

    monkeypatch.setenv("MONDAY_API_TOKEN", "mon-tok")
    monkeypatch.delenv("MONDAY_BOARD_ID_SAST", raising=False)
    monkeypatch.delenv("MONDAY_BOARD_ID_SCA", raising=False)
    monkeypatch.delenv("MONDAY_BOARD_ID_SECRETS", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        sync.load_config()
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# create_update and Semgrep URL
# ---------------------------------------------------------------------------

def test_create_update_called_after_new_item(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    mondays["SAST"].create_update.assert_called_once()
    item_id_arg, body_arg = mondays["SAST"].create_update.call_args[0]
    assert item_id_arg == "m-SAST"
    # Header is always present
    assert "[HIGH]" in body_arg
    assert "js.xss" in body_arg
    assert "src/app.js:42" in body_arg
    # AI fields present when in raw
    assert "<b>AI Verdict:</b>" in body_arg


def test_create_update_failure_does_not_remove_from_state(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    mondays["SAST"].create_update.side_effect = MondayAPIError("update failed")
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    # create_update failure must not prevent the finding from being saved to state
    state = json.loads(state_file.read_text())
    assert "1001" in state["synced"]
    assert state["synced"]["1001"]["monday_item_id"] == "m-SAST"


def test_semgrep_url_injected_into_column_values(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    _, col_vals = mondays["SAST"].create_item.call_args[0]
    link = col_vals.get("text_semgrep_url", {})
    assert isinstance(link, dict)
    assert link.get("url", "").startswith("https://semgrep.dev/orgs/acme/findings/")
    assert "1001" in link["url"]
