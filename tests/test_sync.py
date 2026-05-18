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
    id="s-2001", rule_name="secrets.generic.aws-key", severity="CRITICAL",
    file_path=".env", line=3, repo="my-repo", finding_type="Secrets",
    raw={
        "triageState": "FINDING_TRIAGE_STATE_UNTRIAGED",
        "confidence": "CONFIDENCE_HIGH",
        "lineOfCodeUrl": "https://github.com/org/repo/blob/abc/.env#L3",
        "message": "AWS key found in source code",
        "secretsAttributes": {
            "validationState": "VALIDATION_STATE_CONFIRMED_VALID",
            "secretType": "AWS Key",
        },
        "ruleCweNames": ["CWE-798: Use of Hard-coded Credentials"],
        "ruleOwaspNames": ["A07:2021 - Identification and Authentication Failures"],
    },
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
        m.get_account_slug.return_value = "acme-test"
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
    assert state["monday_items_created"]["SAST"]["m-SAST"] == ["1001"]


def test_existing_finding_skipped(env_vars, state_file):
    state_file.write_text(json.dumps({
        "version": 4,
        "monday_items_created": {"SAST": {"existing": ["1001"]}, "SCA": {}, "Secrets": {}},
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
    assert state["monday_items_created"]["SAST"]["m-SAST"] == ["1001"]
    assert state["daily"][TODAY] == 1
    assert state["version"] == 4


def test_state_not_mutated_on_error(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    mondays["SAST"].create_item.side_effect = MondayAPIError("fail")
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    state = json.loads(state_file.read_text())
    assert "1001" not in sync.synced_finding_ids(state, "SAST")


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
    assert state["monday_items_created"]["SAST"]["m1"] == ["1001"]
    assert state["monday_items_created"]["SCA"]["m2"] == ["3001"]
    assert state["monday_items_created"]["Secrets"]["m3"] == ["s-2001"]


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
    assert col_vals[SECRETS_COL_MAP["Validation State"]] == {"label": "Valid Secret"}


# ---------------------------------------------------------------------------
# State migration v1 → v2
# ---------------------------------------------------------------------------

def test_state_v1_migrated_to_v3(tmp_path):
    v1_state = {"synced": {"old-id": "monday-123"}, "daily": {}}
    path = tmp_path / "state.json"
    path.write_text(json.dumps(v1_state))

    state = sync.load_state(path)
    assert state["version"] == 4
    assert "synced" not in state
    assert state["monday_items_created"]["unknown"]["monday-123"] == ["old-id"]


def test_state_v2_migrated_to_v4(tmp_path):
    v2_state = {
        "version": 2,
        "synced": {
            "f1": {"monday_item_id": "m100", "board": "SCA"},
            "f2": {"monday_item_id": "m100", "board": "SCA"},
            "f3": {"monday_item_id": "m200", "board": "SAST"},
        },
        "daily": {},
    }
    path = tmp_path / "state.json"
    path.write_text(json.dumps(v2_state))

    state = sync.load_state(path)
    assert state["version"] == 4
    assert "synced" not in state
    assert sorted(state["monday_items_created"]["SCA"]["m100"]) == ["f1", "f2"]
    assert state["monday_items_created"]["SAST"]["m200"] == ["f3"]


def test_state_v3_migrated_to_v4(tmp_path):
    v3_state = {
        "version": 3,
        "monday_items_created": {
            "m100": {"board": "SCA", "finding_ids": ["f1", "f2"]},
            "m200": {"board": "SAST", "finding_ids": ["f3"]},
        },
        "daily": {},
    }
    path = tmp_path / "state.json"
    path.write_text(json.dumps(v3_state))

    state = sync.load_state(path)
    assert state["version"] == 4
    assert sorted(state["monday_items_created"]["SCA"]["m100"]) == ["f1", "f2"]
    assert state["monday_items_created"]["SAST"]["m200"] == ["f3"]
    assert state["monday_items_created"]["Secrets"] == {}


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
    assert state["monday_items_created"]["SAST"]["m-SAST"] == ["1001"]


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


# ---------------------------------------------------------------------------
# Finding grouping
# ---------------------------------------------------------------------------

def _sca_finding(fid, cve, severity="HIGH", pkg="lodash", ver="4.17.20", repo="my-repo",
                 reachability="reachable", confidence="high"):
    return Finding(
        id=fid, rule_name=f"ssc.{fid}", severity=severity,
        file_path="package-lock.json", line=1, repo=repo, finding_type="SCA",
        raw={
            "vulnerability_identifier": cve,
            "reachability": reachability,
            "confidence": confidence,
            "found_dependency": {"package": pkg, "version": ver, "ecosystem": "npm"},
        },
    )


def _sast_finding(fid, rule, severity="HIGH", repo="my-repo", file="src/app.js",
                  end_line=10, end_col=5, confidence="high", verdict="true_positive"):
    raw = {
        "confidence": confidence,
        "location": {"file_path": file, "line": 1, "end_line": end_line, "end_column": end_col},
        "repository": {"name": repo},
        "rule": {"cwe_names": [f"CWE-{fid}"], "owasp_names": [f"A0{fid}"], "vulnerability_classes": [f"Class-{fid}"]},
    }
    if verdict:
        raw["assistant"] = {"autotriage": {"verdict": verdict}}
    return Finding(
        id=fid, rule_name=rule, severity=severity,
        file_path=file, line=1, repo=repo, finding_type="SAST", raw=raw,
    )


def test_sca_grouping_same_repo_pkg_version():
    f1 = _sca_finding("1", "CVE-2024-001", severity="CRITICAL")
    f2 = _sca_finding("2", "CVE-2024-002", severity="HIGH")
    f3 = _sca_finding("3", "CVE-2024-003", severity="HIGH", pkg="express", ver="4.0.0")

    groups = sync.group_findings([f1, f2, f3], "SCA")
    assert len(groups) == 2

    lodash_group = next(g for g in groups if g.representative.raw["found_dependency"]["package"] == "lodash")
    assert len(lodash_group.members) == 2
    assert lodash_group.representative.id == "1"  # CRITICAL wins


def test_sca_merged_fields():
    f1 = _sca_finding("1", "CVE-2024-001", severity="CRITICAL")
    f2 = _sca_finding("2", "CVE-2024-002", severity="HIGH")
    group = sync.FindingGroup(representative=f1, members=[f1, f2])

    _, cv = sync.sca_finding_to_item(f1, SCA_COL_MAP)
    sync._apply_sca_merged_fields(cv, SCA_COL_MAP, group)

    assert cv[SCA_COL_MAP["Finding ID"]] == "1, 2"
    assert cv[SCA_COL_MAP["CVE"]] == "CVE-2024-001, CVE-2024-002"


def test_sca_single_finding_no_merge():
    f1 = _sca_finding("1", "CVE-2024-001")
    group = sync.FindingGroup(representative=f1, members=[f1])

    _, cv = sync.sca_finding_to_item(f1, SCA_COL_MAP)
    sync._apply_sca_merged_fields(cv, SCA_COL_MAP, group)

    assert cv[SCA_COL_MAP["Finding ID"]] == "1"
    assert cv[SCA_COL_MAP["CVE"]] == "CVE-2024-001"


def test_sast_grouping_same_repo_file_endloc():
    f1 = _sast_finding("1", "sql-injection", severity="CRITICAL")
    f2 = _sast_finding("2", "xss", severity="HIGH")
    f3 = _sast_finding("3", "other", severity="HIGH", file="src/other.js")

    groups = sync.group_findings([f1, f2, f3], "SAST")
    assert len(groups) == 2

    app_group = next(g for g in groups if g.representative.file_path == "src/app.js")
    assert len(app_group.members) == 2
    assert app_group.representative.id == "1"  # CRITICAL wins


SAST_COL_MAP_FULL = {
    **SAST_COL_MAP,
    "OWASP": "text_owasp", "Vuln Classes": "text_vuln",
    "Confidence": "text_conf", "End Location": "text_endloc",
}


def test_sast_merged_fields():
    f1 = _sast_finding("1", "sql-injection", severity="CRITICAL")
    f2 = _sast_finding("2", "xss", severity="HIGH")
    group = sync.FindingGroup(representative=f1, members=[f1, f2])

    _, cv = sync.sast_finding_to_item(f1, SAST_COL_MAP_FULL)
    sync._apply_sast_merged_fields(cv, SAST_COL_MAP_FULL, group)

    assert cv[SAST_COL_MAP_FULL["Finding ID"]] == "1, 2"
    assert "sql-injection" in cv[SAST_COL_MAP_FULL["Rule"]]
    assert "xss" in cv[SAST_COL_MAP_FULL["Rule"]]
    assert "CWE-1" in cv[SAST_COL_MAP_FULL["CWE"]]
    assert "CWE-2" in cv[SAST_COL_MAP_FULL["CWE"]]


def test_sca_representative_prefers_reachable():
    f1 = _sca_finding("1", "CVE-001", severity="HIGH", reachability="unreachable")
    f2 = _sca_finding("2", "CVE-002", severity="HIGH", reachability="reachable")
    groups = sync.group_findings([f1, f2], "SCA")
    assert groups[0].representative.id == "2"


def test_sast_representative_prefers_true_positive():
    f1 = _sast_finding("1", "rule-a", severity="HIGH", verdict="false_positive")
    f2 = _sast_finding("2", "rule-b", severity="HIGH", verdict="true_positive")
    groups = sync.group_findings([f1, f2], "SAST")
    assert groups[0].representative.id == "2"


def test_sca_group_update_body_contains_all_cves():
    f1 = _sca_finding("1", "CVE-2024-001", severity="CRITICAL")
    f2 = _sca_finding("2", "CVE-2024-002", severity="HIGH")
    group = sync.FindingGroup(representative=f1, members=[f1, f2])
    body = sync.format_update_body_sca_group(group, "acme")
    assert "CVE-2024-001" in body
    assert "CVE-2024-002" in body
    assert "2 CVEs" in body
    assert "semgrep.dev/orgs/acme/findings/1" in body
    assert "semgrep.dev/orgs/acme/findings/2" in body


def test_sast_group_update_body_contains_all_rules():
    f1 = _sast_finding("1", "sql-injection", severity="CRITICAL")
    f2 = _sast_finding("2", "xss", severity="HIGH")
    group = sync.FindingGroup(representative=f1, members=[f1, f2])
    body = sync.format_update_body_sast_group(group, "acme")
    assert "sql-injection" in body
    assert "xss" in body
    assert "2 findings" in body
    assert "semgrep.dev/orgs/acme/findings/1" in body
    assert "semgrep.dev/orgs/acme/findings/2" in body


def test_grouped_findings_all_tracked_in_state(env_vars, state_file):
    f1 = _sca_finding("g1", "CVE-001", severity="CRITICAL")
    f2 = _sca_finding("g2", "CVE-002", severity="HIGH")

    semgrep, mondays = _mock_clients(sca=[f1, f2])
    mondays["SCA"].create_item.return_value = ("m-grouped", 0)
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    state = json.loads(state_file.read_text())
    assert "m-grouped" in state["monday_items_created"]["SCA"]
    assert sorted(state["monday_items_created"]["SCA"]["m-grouped"]) == ["g1", "g2"]
    mondays["SCA"].create_item.assert_called_once()


# ---------------------------------------------------------------------------
# Triage-on-sync
# ---------------------------------------------------------------------------

def test_triage_not_called_by_default(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file)

    semgrep.triage_findings.assert_not_called()


def test_triage_called_after_sast_item_creation(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    mondays["SAST"].create_item.return_value = ("m99", 0)
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file, set_triage_reviewing=True)

    semgrep.triage_findings.assert_called_once()
    call_args = semgrep.triage_findings.call_args
    assert call_args[0][0] == ["1001"]
    assert call_args[0][1] == "reviewing"
    assert "m99" in call_args[0][2]
    assert call_args[0][3] == "sast"


def test_triage_called_after_secrets_item_creation(env_vars, state_file):
    semgrep, mondays = _mock_clients(secrets=[SECRET_FINDING])
    mondays["Secrets"].create_item.return_value = ("m77", 0)
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file, set_triage_reviewing=True)

    semgrep.triage_findings.assert_called_once()
    call_args = semgrep.triage_findings.call_args
    assert call_args[0][0] == ["s-2001"]
    assert call_args[0][1] == "reviewing"
    assert "m77" in call_args[0][2]
    assert call_args[0][3] == "secrets"


def test_triage_called_with_grouped_finding_ids(env_vars, state_file):
    f1 = _sca_finding("g10", "CVE-001", severity="CRITICAL")
    f2 = _sca_finding("g20", "CVE-002", severity="HIGH")

    semgrep, mondays = _mock_clients(sca=[f1, f2])
    mondays["SCA"].create_item.return_value = ("m-grp", 0)
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file, set_triage_reviewing=True)

    semgrep.triage_findings.assert_called_once()
    call_args = semgrep.triage_findings.call_args
    assert sorted(call_args[0][0]) == ["g10", "g20"]
    assert call_args[0][1] == "reviewing"
    assert call_args[0][3] == "sca"


def test_triage_failure_does_not_remove_from_state(env_vars, state_file):
    from semgrep_client import SemgrepAPIError
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    semgrep.triage_findings.side_effect = SemgrepAPIError("triage failed")
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file, set_triage_reviewing=True)

    state = json.loads(state_file.read_text())
    assert state["monday_items_created"]["SAST"]["m-SAST"] == ["1001"]


def test_monday_item_url_in_triage_note(env_vars, state_file):
    semgrep, mondays = _mock_clients(sast=[SAST_FINDING])
    mondays["SAST"].create_item.return_value = ("m-url-test", 0)
    mondays["SAST"].board_id = 1001
    p1, p2 = _patch_clients(semgrep, mondays)
    with p1, p2:
        sync.run(state_path=state_file, set_triage_reviewing=True)

    note = semgrep.triage_findings.call_args[0][2]
    assert "Created monday item:" in note
    assert "acme-test.monday.com/boards/" in note
    assert "m-url-test" in note
