"""Tests for filters.py — load_filters, to_query_params, and SemgrepClient integration."""

import re
import pytest
from pathlib import Path

from filters import load_filters, to_query_params, to_secrets_filter_body, to_malicious_query_params, has_malicious_filter, filter_findings, ALLOWED_FILTERS
from semgrep_client import SemgrepClient, Finding

TOKEN = "test-token"
SLUG = "acme-corp"
DEP_ID = "20169"

DEPLOYMENTS_URL = "https://semgrep.dev/api/v1/deployments"
FINDINGS_URL = f"https://semgrep.dev/api/v1/deployments/{SLUG}/findings"
SECRETS_V2_URL = f"https://semgrep.dev/api/agent/deployments/{DEP_ID}/issues"

DEPLOYMENTS_RESPONSE = {"deployments": [{"id": int(DEP_ID), "slug": SLUG}]}


def _write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "filters.yaml"
    p.write_text(content)
    return p


def _finding_raw(fid="1"):
    return {
        "id": fid,
        "rule_name": f"rule.{fid}",
        "severity": "HIGH",
        "location": {"file_path": f"src/file{fid}.py", "line": 1},
        "repository": {"name": "repo"},
    }


def _secret_raw(fid="s1"):
    return {
        "id": fid,
        "rulePath": f"secrets.type.{fid}",
        "severity": "SEVERITY_HIGH",
        "confidence": "CONFIDENCE_HIGH",
        "filePath": f"src/file{fid}.py",
        "line": 10,
        "lineOfCodeUrl": f"https://github.com/org/repo/blob/abc/src/file{fid}.py#L10",
        "repository": {"name": "repo"},
        "triageState": "FINDING_TRIAGE_STATE_UNTRIAGED",
        "secretsAttributes": {"validationState": "VALIDATION_STATE_NO_VALIDATOR", "secretType": "API Key"},
    }


def _v2_issue_wrapper(raw: dict) -> dict:
    return {"issue": raw, "reviewCount": 0, "allRefs": []}


# ---------------------------------------------------------------------------
# load_filters — happy path
# ---------------------------------------------------------------------------

def test_load_filters_full(tmp_path):
    yaml_content = """
sast:
  severity: [CRITICAL, HIGH]
  confidence: [high]
  ai_verdict: [true_positive]
sca:
  severity: [HIGH]
  reachability: [reachable]
secrets:
  severity: [SEVERITY_HIGH, SEVERITY_CRITICAL]
  validation_state: [VALIDATION_STATE_CONFIRMED_VALID]
  status: [ISSUE_TAB_OPEN]
"""
    path = _write_yaml(tmp_path, yaml_content)
    result = load_filters(path)

    assert result["sast"]["severity"] == ["CRITICAL", "HIGH"]
    assert result["sast"]["confidence"] == ["high"]
    assert result["sast"]["ai_verdict"] == ["true_positive"]
    assert result["sca"]["severity"] == ["HIGH"]
    assert result["sca"]["reachability"] == ["reachable"]
    assert result["secrets"]["severity"] == ["SEVERITY_HIGH", "SEVERITY_CRITICAL"]
    assert result["secrets"]["validation_state"] == ["VALIDATION_STATE_CONFIRMED_VALID"]
    assert result["secrets"]["status"] == ["ISSUE_TAB_OPEN"]


def test_load_filters_partial_block(tmp_path):
    path = _write_yaml(tmp_path, "sast:\n  severity: [CRITICAL]\n")
    result = load_filters(path)
    assert result == {"sast": {"severity": ["CRITICAL"]}}


# ---------------------------------------------------------------------------
# load_filters — no file / None path
# ---------------------------------------------------------------------------

def test_load_filters_none_path():
    assert load_filters(None) == {}


def test_load_filters_missing_file(tmp_path):
    assert load_filters(tmp_path / "nonexistent.yaml") == {}


def test_load_filters_empty_file(tmp_path):
    path = tmp_path / "filters.yaml"
    path.write_text("")
    assert load_filters(path) == {}


# ---------------------------------------------------------------------------
# load_filters — validation errors
# ---------------------------------------------------------------------------

def test_load_filters_unknown_board_type(tmp_path):
    path = _write_yaml(tmp_path, "oops:\n  severity: [HIGH]\n")
    with pytest.raises(ValueError, match="Unknown board type 'oops'"):
        load_filters(path)


def test_load_filters_unknown_filter_key(tmp_path):
    path = _write_yaml(tmp_path, "sast:\n  nonexistent_key: [HIGH]\n")
    with pytest.raises(ValueError, match="Unknown filter key 'nonexistent_key'"):
        load_filters(path)


def test_load_filters_non_list_value(tmp_path):
    path = _write_yaml(tmp_path, "sast:\n  severity: HIGH\n")
    with pytest.raises(ValueError, match=r"must be a list"):
        load_filters(path)


def test_load_filters_non_list_error_mentions_key(tmp_path):
    path = _write_yaml(tmp_path, "secrets:\n  validation_state: VALIDATION_STATE_CONFIRMED_VALID\n")
    with pytest.raises(ValueError, match="secrets.validation_state"):
        load_filters(path)


def test_load_filters_scalar_param_single_value_ok(tmp_path):
    path = _write_yaml(tmp_path, "sast:\n  confidence: [high]\n")
    result = load_filters(path)
    assert result["sast"]["confidence"] == ["high"]


def test_load_filters_scalar_param_multiple_values_errors(tmp_path):
    path = _write_yaml(tmp_path, "sast:\n  confidence: [high, medium]\n")
    with pytest.raises(ValueError, match="scalar"):
        load_filters(path)


def test_load_filters_ai_verdict_multiple_values_ok(tmp_path):
    path = _write_yaml(tmp_path, "sast:\n  ai_verdict: [true_positive, not_analyzed]\n")
    result = load_filters(path)
    assert result["sast"]["ai_verdict"] == ["true_positive", "not_analyzed"]


# ---------------------------------------------------------------------------
# to_query_params
# ---------------------------------------------------------------------------

def test_to_query_params_sast():
    filters = {
        "sast": {"severity": ["CRITICAL", "HIGH"], "ai_verdict": ["true_positive"]}
    }
    params = to_query_params("sast", filters)
    assert params["severities"] == ["CRITICAL", "HIGH"]
    # single server-side value — pushed as scalar string
    assert params["autotriage_verdict"] == "true_positive"


def test_to_query_params_ai_verdict_not_analyzed_skipped():
    """not_analyzed has no API equivalent — autotriage_verdict param must not be sent."""
    filters = {"sast": {"ai_verdict": ["not_analyzed"]}}
    params = to_query_params("sast", filters)
    assert "autotriage_verdict" not in params


def test_to_query_params_ai_verdict_mixed_skipped():
    """Mixed list including not_analyzed — skip server-side, leave to filter_findings."""
    filters = {"sast": {"ai_verdict": ["true_positive", "not_analyzed"]}}
    params = to_query_params("sast", filters)
    assert "autotriage_verdict" not in params


def test_to_query_params_sca():
    filters = {
        "sca": {"reachability": ["reachable"], "transitivity": ["direct"]}
    }
    params = to_query_params("sca", filters)
    assert params["exposures"] == ["reachable"]
    assert params["transitivities"] == ["direct"]


def test_to_secrets_filter_body():
    filters = {
        "secrets": {"validation_state": ["VALIDATION_STATE_CONFIRMED_VALID"]}
    }
    body = to_secrets_filter_body(filters)
    assert body["validationStates"] == ["VALIDATION_STATE_CONFIRMED_VALID"]


def test_to_secrets_filter_body_status():
    filters = {"secrets": {"status": ["ISSUE_TAB_OPEN"]}}
    body = to_secrets_filter_body(filters)
    assert body["tab"] == "ISSUE_TAB_OPEN"


def test_to_secrets_filter_body_empty():
    assert to_secrets_filter_body({}) == {}
    assert to_secrets_filter_body({"sast": {"severity": ["HIGH"]}}) == {}


def test_to_query_params_no_block():
    assert to_query_params("sast", {}) == {}
    assert to_query_params("sca", {"sast": {"severity": ["HIGH"]}}) == {}


# ---------------------------------------------------------------------------
# filter_findings — client-side ai_verdict filtering
# ---------------------------------------------------------------------------

def _sast_finding(fid: str, verdict: str | None) -> Finding:
    raw = _finding_raw(fid)
    if verdict is not None:
        raw["assistant"] = {"autotriage": {"verdict": verdict}}
    return Finding(id=fid, rule_name="rule", severity="HIGH", file_path="f.py",
                   line=1, repo="r", finding_type="SAST", raw=raw)


def test_filter_findings_no_filters():
    findings = [_sast_finding("1", "true_positive"), _sast_finding("2", None)]
    assert filter_findings(findings, "sast", {}) == findings


def test_filter_findings_single_server_side_value_no_client_filter():
    """Single true_positive — pushed server-side, filter_findings is a no-op."""
    findings = [_sast_finding("1", "true_positive"), _sast_finding("2", None)]
    filters = {"sast": {"ai_verdict": ["true_positive"]}}
    # server-side already filtered; filter_findings should not further reduce
    result = filter_findings(findings, "sast", filters)
    assert result == findings


def test_filter_findings_not_analyzed_only():
    findings = [_sast_finding("1", "true_positive"), _sast_finding("2", None)]
    filters = {"sast": {"ai_verdict": ["not_analyzed"]}}
    result = filter_findings(findings, "sast", filters)
    assert [f.id for f in result] == ["2"]


def test_filter_findings_true_positive_and_not_analyzed():
    findings = [
        _sast_finding("1", "true_positive"),
        _sast_finding("2", "false_positive"),
        _sast_finding("3", None),
    ]
    filters = {"sast": {"ai_verdict": ["true_positive", "not_analyzed"]}}
    result = filter_findings(findings, "sast", filters)
    assert [f.id for f in result] == ["1", "3"]


def test_filter_findings_not_applicable_to_sca():
    """ai_verdict client filter only applies to sast board type."""
    findings = [_sast_finding("1", "true_positive"), _sast_finding("2", None)]
    filters = {"sca": {"ai_verdict": ["not_analyzed"]}}
    result = filter_findings(findings, "sca", filters)
    assert result == findings


# ---------------------------------------------------------------------------
# SemgrepClient.fetch_findings — extra_params passthrough
# ---------------------------------------------------------------------------

def test_fetch_findings_extra_params_sent(httpx_mock):
    """extra_params are forwarded as query params to the Semgrep API."""
    findings_re = re.compile(rf"^{re.escape(FINDINGS_URL)}")
    httpx_mock.add_response(url=findings_re, json={"findings": [_finding_raw("1")], "total": 1})
    httpx_mock.add_response(url=findings_re, json={"findings": [], "total": 1})

    client = SemgrepClient(token=TOKEN, deployment_slug=SLUG)
    findings = client.fetch_findings("sast", extra_params={"severities": ["CRITICAL", "HIGH"]})

    assert len(findings) == 1
    req = httpx_mock.get_requests()[0]
    assert req.url.params.get_list("severities") == ["CRITICAL", "HIGH"]


def test_fetch_findings_pagination_not_overridden(httpx_mock):
    """Passing page/page_size in extra_params does not override pagination."""
    findings_re = re.compile(rf"^{re.escape(FINDINGS_URL)}")
    # max_findings=1, so loop stops after collecting 1 finding — only 1 request is made.
    httpx_mock.add_response(url=findings_re, json={"findings": [_finding_raw("1")], "total": 1})

    client = SemgrepClient(token=TOKEN, deployment_slug=SLUG)
    client.fetch_findings("sast", max_findings=1, extra_params={"page": 99, "page_size": 999})

    req = httpx_mock.get_requests()[0]
    assert req.url.params["page"] == "0"
    assert req.url.params["page_size"] == "1"


# ---------------------------------------------------------------------------
# SemgrepClient.fetch_secrets — filter_params passthrough (v2 POST body)
# ---------------------------------------------------------------------------

def test_fetch_secrets_filter_params_sent(httpx_mock):
    """filter_params are included in the POST body to the v2 issues endpoint."""
    httpx_mock.add_response(url=DEPLOYMENTS_URL, json=DEPLOYMENTS_RESPONSE)
    httpx_mock.add_response(
        url=SECRETS_V2_URL, method="POST",
        json={"issues": [_v2_issue_wrapper(_secret_raw("s1"))], "cursor": ""},
    )

    client = SemgrepClient(token=TOKEN, deployment_slug=SLUG)
    findings = client.fetch_secrets(filter_params={"validationStates": ["VALIDATION_STATE_CONFIRMED_VALID"]})

    assert len(findings) == 1
    import json as json_mod
    req = httpx_mock.get_requests()[1]
    body = json_mod.loads(req.content)
    assert body["filter"]["validationStates"] == ["VALIDATION_STATE_CONFIRMED_VALID"]
    assert body["issueType"] == "ISSUE_TYPE_SECRETS"


def test_fetch_secrets_pagination_managed_internally(httpx_mock):
    """limit and cursor in the POST body are managed by the client."""
    httpx_mock.add_response(url=DEPLOYMENTS_URL, json=DEPLOYMENTS_RESPONSE)
    httpx_mock.add_response(
        url=SECRETS_V2_URL, method="POST",
        json={"issues": [_v2_issue_wrapper(_secret_raw("s1"))], "cursor": ""},
    )

    client = SemgrepClient(token=TOKEN, deployment_slug=SLUG)
    client.fetch_secrets(max_findings=5, filter_params={"tab": "ISSUE_TAB_OPEN", "severities": ["SEVERITY_HIGH"]})

    import json as json_mod
    req = httpx_mock.get_requests()[1]
    body = json_mod.loads(req.content)
    assert body["limit"] == 5
    assert "cursor" not in body
    assert body["filter"]["tab"] == "ISSUE_TAB_OPEN"
    assert body["filter"]["severities"] == ["SEVERITY_HIGH"]


# ---------------------------------------------------------------------------
# Status filter key
# ---------------------------------------------------------------------------

def test_load_filters_status_key_accepted(tmp_path):
    path = _write_yaml(tmp_path, "sast:\n  status: [open]\n")
    result = load_filters(path)
    assert result["sast"]["status"] == ["open"]


def test_to_query_params_status_sast():
    filters = {"sast": {"status": ["open"]}}
    params = to_query_params("sast", filters)
    assert params["status"] == ["open"]


def test_to_query_params_status_sca():
    filters = {"sca": {"status": ["open", "fixed"]}}
    params = to_query_params("sca", filters)
    assert params["status"] == ["open", "fixed"]


# ---------------------------------------------------------------------------
# Malicious filter
# ---------------------------------------------------------------------------

def test_load_filters_malicious_true(tmp_path):
    path = _write_yaml(tmp_path, "sca:\n  malicious: [true]\n")
    result = load_filters(path)
    assert result["sca"]["malicious"] == ["True"]


def test_load_filters_malicious_false_rejected(tmp_path):
    path = _write_yaml(tmp_path, "sca:\n  malicious: [false]\n")
    with pytest.raises(ValueError, match="malicious.*must be.*true"):
        load_filters(path)


def test_load_filters_malicious_multiple_rejected(tmp_path):
    path = _write_yaml(tmp_path, "sca:\n  malicious: [true, false]\n")
    with pytest.raises(ValueError, match="malicious.*must be.*true"):
        load_filters(path)


def test_to_query_params_excludes_malicious():
    """malicious is not sent as a regular query param — it triggers a separate fetch."""
    filters = {"sca": {"severity": ["HIGH"], "malicious": ["true"]}}
    params = to_query_params("sca", filters)
    assert "is_malicious" not in params
    assert "_malicious" not in params
    assert "malicious" not in params
    assert params["severities"] == ["HIGH"]


def test_has_malicious_filter_true():
    assert has_malicious_filter({"sca": {"malicious": ["true"], "severity": ["HIGH"]}})


def test_has_malicious_filter_false():
    assert not has_malicious_filter({"sca": {"severity": ["HIGH"]}})
    assert not has_malicious_filter({})


def test_to_malicious_query_params_standalone():
    """Malicious query params contain only is_malicious — no other filters."""
    params = to_malicious_query_params()
    assert params == {"is_malicious": "true"}


def test_secrets_status_accepted(tmp_path):
    """secrets supports 'status' (maps to v2 tab param)."""
    path = _write_yaml(tmp_path, "secrets:\n  status: [ISSUE_TAB_OPEN]\n")
    result = load_filters(path)
    assert result["secrets"]["status"] == ["ISSUE_TAB_OPEN"]


def test_secrets_status_scalar(tmp_path):
    """secrets status maps to tab (scalar) — only one value allowed."""
    path = _write_yaml(tmp_path, "secrets:\n  status: [ISSUE_TAB_OPEN, ISSUE_TAB_REVIEWING]\n")
    with pytest.raises(ValueError, match="scalar"):
        load_filters(path)


# ---------------------------------------------------------------------------
# SemgrepClient.triage_findings
# ---------------------------------------------------------------------------

TRIAGE_URL = f"https://semgrep.dev/api/v1/deployments/{SLUG}/triage"


def test_triage_findings_sends_correct_payload(httpx_mock):
    httpx_mock.add_response(url=TRIAGE_URL, method="POST", json={})

    client = SemgrepClient(token=TOKEN, deployment_slug=SLUG)
    client.triage_findings(["100", "200"], "reviewing", "test note", "sast")

    req = httpx_mock.get_requests()[0]
    import json
    body = json.loads(req.content)
    assert body["issue_type"] == "sast"
    assert body["issue_ids"] == [100, 200]
    assert body["new_triage_state"] == "reviewing"
    assert body["new_note"] == "test note"


def test_triage_findings_auth_header(httpx_mock):
    httpx_mock.add_response(url=TRIAGE_URL, method="POST", json={})

    client = SemgrepClient(token=TOKEN, deployment_slug=SLUG)
    client.triage_findings(["100"], "reviewing", "note", "sca")

    req = httpx_mock.get_requests()[0]
    assert req.headers["authorization"] == f"Bearer {TOKEN}"
