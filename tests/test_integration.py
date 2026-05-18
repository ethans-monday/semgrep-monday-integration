"""End-to-end integration tests (three-board architecture).

Both Semgrep and monday.com HTTP calls are intercepted by pytest-httpx.
"""

import json
import re
from datetime import date
from pathlib import Path

import pytest

import sync

TODAY = str(date.today())

SEMGREP_FINDINGS_URL = "https://semgrep.dev/api/v1/deployments/acme-corp/findings"
SEMGREP_DEPLOYMENTS_URL = "https://semgrep.dev/api/v1/deployments"
SEMGREP_SECRETS_V2_URL = "https://semgrep.dev/api/agent/deployments/20169/issues"
SEMGREP_TRIAGE_URL = "https://semgrep.dev/api/v1/deployments/acme-corp/triage"
MONDAY_URL = "https://api.monday.com/v2"

ACCOUNT_SLUG_RESP = {"data": {"account": {"slug": "acme-test"}}}

DEPLOYMENTS_RESP = {"deployments": [{"id": 20169, "slug": "acme-corp", "name": "Acme Corp"}]}


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
    "AI Verdict", "CWE", "Message", "Semgrep URL",
])
SCA_COLUMNS_RESP = _columns_resp([
    "Finding ID", "Severity", "Rule", "File", "Repo",
    "CVE", "Reachability", "Package", "Version", "Semgrep URL",
])
SECRETS_COLUMNS_RESP = _columns_resp([
    "Finding ID", "Severity", "Rule", "File", "Repo", "Validation State", "Semgrep URL",
])


def _create_item_resp(item_id):
    return {"data": {"create_item": {"id": item_id}}}


def _create_update_resp():
    return {"data": {"create_update": {"id": "u1"}}}


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


def _secret_finding(fid, severity="SEVERITY_CRITICAL"):
    return {
        "id": fid, "rulePath": f"secrets.generic.{fid}", "severity": severity,
        "confidence": "CONFIDENCE_HIGH",
        "filePath": ".env", "line": 1,
        "lineOfCodeUrl": f"https://github.com/org/repo/blob/abc/.env#L1",
        "repository": {"name": "acme"},
        "triageState": "FINDING_TRIAGE_STATE_UNTRIAGED",
        "secretsAttributes": {"validationState": "VALIDATION_STATE_CONFIRMED_VALID", "secretType": "API Key"},
    }


@pytest.fixture()
def env_vars(monkeypatch):
    monkeypatch.setattr("sync.load_dotenv", lambda **kw: None)
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "tok")
    monkeypatch.setenv("SEMGREP_DEPLOYMENT_SLUG", "acme-corp")
    monkeypatch.setenv("MONDAY_API_TOKEN", "mon-tok")
    monkeypatch.setenv("MONDAY_BOARD_ID_SAST", "1001")
    monkeypatch.setenv("MONDAY_BOARD_ID_SCA", "1002")
    monkeypatch.setenv("MONDAY_BOARD_ID_SECRETS", "1003")


@pytest.fixture()
def state_file(tmp_path) -> Path:
    return tmp_path / "state.json"


def _add_semgrep_pages(httpx_mock, issue_type, findings):
    url_re = re.compile(rf"^{re.escape(SEMGREP_FINDINGS_URL)}\?.*issue_type={issue_type}")
    httpx_mock.add_response(url=url_re, json={"findings": findings})
    if findings:
        httpx_mock.add_response(url=url_re, json={"findings": []})


def _add_secrets(httpx_mock, secrets):
    httpx_mock.add_response(url=SEMGREP_DEPLOYMENTS_URL, json=DEPLOYMENTS_RESP)
    issues = [{"issue": s, "reviewCount": 0, "allRefs": []} for s in secrets]
    httpx_mock.add_response(
        url=SEMGREP_SECRETS_V2_URL, method="POST",
        json={"issues": issues, "cursor": ""},
    )


def _add_triage_responses(httpx_mock, n):
    """Register Semgrep triage POST responses (one per item created)."""
    for _ in range(n):
        httpx_mock.add_response(url=SEMGREP_TRIAGE_URL, method="POST", json={})


def _add_monday_responses(httpx_mock, n_sast=0, n_sca=0, n_secrets=0, with_triage=False):
    """Register monday responses in actual call order: col query → creates per board."""
    counter = [0]

    def next_id():
        counter[0] += 1
        return f"m{counter[0]}"

    if with_triage:
        httpx_mock.add_response(url=MONDAY_URL, json=ACCOUNT_SLUG_RESP)

    # SAST board: column query then interleaved create_item + create_update per finding
    if n_sast > 0:
        httpx_mock.add_response(url=MONDAY_URL, json=SAST_COLUMNS_RESP)
        for _ in range(n_sast):
            httpx_mock.add_response(url=MONDAY_URL, json=_create_item_resp(next_id()))
            httpx_mock.add_response(url=MONDAY_URL, json=_create_update_resp())

    # SCA board: column query then interleaved create_item + create_update per finding
    if n_sca > 0:
        httpx_mock.add_response(url=MONDAY_URL, json=SCA_COLUMNS_RESP)
        for _ in range(n_sca):
            httpx_mock.add_response(url=MONDAY_URL, json=_create_item_resp(next_id()))
            httpx_mock.add_response(url=MONDAY_URL, json=_create_update_resp())

    # Secrets board: column query then interleaved create_item + create_update per finding
    if n_secrets > 0:
        httpx_mock.add_response(url=MONDAY_URL, json=SECRETS_COLUMNS_RESP)
        for _ in range(n_secrets):
            httpx_mock.add_response(url=MONDAY_URL, json=_create_item_resp(next_id()))
            httpx_mock.add_response(url=MONDAY_URL, json=_create_update_resp())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_full_sync_run(httpx_mock, env_vars, state_file):
    _add_semgrep_pages(httpx_mock, "sast", [_sast_finding("101"), _sast_finding("102")])
    _add_semgrep_pages(httpx_mock, "sca", [_sca_finding("201")])
    _add_secrets(httpx_mock, [_secret_finding("301")])
    _add_monday_responses(httpx_mock, n_sast=2, n_sca=1, n_secrets=1)

    sync.run(state_path=state_file, filters_path=None)

    state = json.loads(state_file.read_text())
    all_fids = (
        sync.synced_finding_ids(state, "SAST")
        | sync.synced_finding_ids(state, "SCA")
        | sync.synced_finding_ids(state, "Secrets")
    )
    assert {"101", "102", "201", "301"} == all_fids
    # 4 items: 2 SAST (different files) + 1 SCA + 1 Secrets
    items = state["monday_items_created"]
    assert len(items["SAST"]) + len(items["SCA"]) + len(items["Secrets"]) == 4
    assert state["daily"][TODAY] == 4


def test_idempotent_second_run(httpx_mock, env_vars, state_file):
    # First run
    _add_semgrep_pages(httpx_mock, "sast", [_sast_finding("101")])
    _add_semgrep_pages(httpx_mock, "sca", [])
    _add_secrets(httpx_mock, [])
    _add_monday_responses(httpx_mock, n_sast=1)
    sync.run(state_path=state_file, filters_path=None)

    # Second run — same finding, should be skipped
    _add_semgrep_pages(httpx_mock, "sast", [_sast_finding("101")])
    _add_semgrep_pages(httpx_mock, "sca", [])
    _add_secrets(httpx_mock, [])
    _add_monday_responses(httpx_mock)
    sync.run(state_path=state_file, filters_path=None)

    state = json.loads(state_file.read_text())
    assert sync.synced_finding_ids(state, "SAST") == {"101"}
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
    monday.get_account_slug.return_value = "acme-test"
    monday.create_item.side_effect = [
        ("m1", 0), ("m2", 0), MondayAPIError("fail"),
    ]
    board_map = {1001: monday, 1002: MagicMock(), 1003: MagicMock()}
    with patch("sync.MondayClient", side_effect=lambda token, board_id: board_map[board_id]):
        sync.run(state_path=state_file, filters_path=None)

    state = json.loads(state_file.read_text())
    sast_fids = sync.synced_finding_ids(state, "SAST")
    assert "1" in sast_fids
    assert "2" in sast_fids
    assert "3" not in sast_fids


@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
def test_secrets_cursor_exhausted(httpx_mock, env_vars, state_file):
    _add_semgrep_pages(httpx_mock, "sast", [])
    _add_semgrep_pages(httpx_mock, "sca", [])

    httpx_mock.add_response(url=SEMGREP_DEPLOYMENTS_URL, json=DEPLOYMENTS_RESP)
    httpx_mock.add_response(
        url=SEMGREP_SECRETS_V2_URL, method="POST",
        json={"issues": [{"issue": _secret_finding("301"), "reviewCount": 0, "allRefs": []}], "cursor": "abc"},
    )
    httpx_mock.add_response(
        url=SEMGREP_SECRETS_V2_URL, method="POST",
        json={"issues": [{"issue": _secret_finding("302"), "reviewCount": 0, "allRefs": []}], "cursor": ""},
    )

    _add_monday_responses(httpx_mock, n_secrets=2)

    sync.run(state_path=state_file, filters_path=None)

    state = json.loads(state_file.read_text())
    assert sync.synced_finding_ids(state, "Secrets") == {"301", "302"}
    assert len(state["monday_items_created"]["Secrets"]) == 2


def test_sca_grouping_creates_single_item(httpx_mock, env_vars, state_file):
    """Two SCA findings with same {repo, package, version} produce one monday item."""
    sca1 = _sca_finding("201", severity="CRITICAL")
    sca1["vulnerability_identifier"] = "CVE-2024-001"
    sca2 = _sca_finding("202", severity="HIGH")
    sca2["vulnerability_identifier"] = "CVE-2024-002"

    _add_semgrep_pages(httpx_mock, "sast", [])
    _add_semgrep_pages(httpx_mock, "sca", [sca1, sca2])
    _add_secrets(httpx_mock, [])
    # Only 1 SCA item should be created (grouped)
    _add_monday_responses(httpx_mock, n_sca=1)

    sync.run(state_path=state_file, filters_path=None)

    state = json.loads(state_file.read_text())
    assert sync.synced_finding_ids(state, "SCA") == {"201", "202"}
    assert len(state["monday_items_created"]["SCA"]) == 1
    item_fids = list(state["monday_items_created"]["SCA"].values())[0]
    assert sorted(item_fids) == ["201", "202"]


def test_set_triage_reviewing_flag(httpx_mock, env_vars, state_file):
    _add_semgrep_pages(httpx_mock, "sast", [_sast_finding("101")])
    _add_semgrep_pages(httpx_mock, "sca", [])
    _add_secrets(httpx_mock, [])
    _add_monday_responses(httpx_mock, n_sast=1, with_triage=True)
    _add_triage_responses(httpx_mock, 1)

    sync.run(state_path=state_file, filters_path=None, set_triage_reviewing=True)

    state = json.loads(state_file.read_text())
    assert sync.synced_finding_ids(state, "SAST") == {"101"}

    triage_reqs = [r for r in httpx_mock.get_requests() if "triage" in str(r.url)]
    assert len(triage_reqs) == 1
    import json as _json
    body = _json.loads(triage_reqs[0].content)
    assert body["new_triage_state"] == "reviewing"
    assert body["issue_ids"] == [101]
    assert "Created monday item:" in body["new_note"]
