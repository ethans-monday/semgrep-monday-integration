"""Tests for filters.py — load_filters, to_query_params, and SemgrepClient integration."""

import re
import pytest
from pathlib import Path

from filters import load_filters, to_query_params, filter_findings, ALLOWED_FILTERS
from semgrep_client import SemgrepClient, Finding

TOKEN = "test-token"
SLUG = "acme-corp"
DEP_ID = "20169"

DEPLOYMENTS_URL = "https://semgrep.dev/api/v1/deployments"
FINDINGS_URL = f"https://semgrep.dev/api/v1/deployments/{SLUG}/findings"
SECRETS_URL = f"https://semgrep.dev/api/v1/deployments/{DEP_ID}/secrets"

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
        "type": f"SecretType.{fid}",
        "severity": "HIGH",
        "findingPath": f"src/file{fid}.py:10",
        "findingPathUrl": f"https://github.com/org/repo/blob/abc/src/file{fid}.py#L10",
        "repository": {"name": "repo"},
    }


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


def test_to_query_params_secrets():
    filters = {
        "secrets": {"validation_state": ["VALIDATION_STATE_CONFIRMED_VALID"]}
    }
    params = to_query_params("secrets", filters)
    assert params["validationState"] == ["VALIDATION_STATE_CONFIRMED_VALID"]


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
# SemgrepClient.fetch_secrets — extra_params passthrough
# ---------------------------------------------------------------------------

def test_fetch_secrets_extra_params_sent(httpx_mock):
    """extra_params are forwarded to the secrets endpoint."""
    secrets_re = re.compile(rf"^{re.escape(SECRETS_URL)}")
    httpx_mock.add_response(url=DEPLOYMENTS_URL, json=DEPLOYMENTS_RESPONSE)
    httpx_mock.add_response(url=secrets_re, json={"findings": [_secret_raw("s1")], "cursor": ""})

    client = SemgrepClient(token=TOKEN, deployment_slug=SLUG)
    findings = client.fetch_secrets(extra_params={"validationState": ["VALIDATION_STATE_CONFIRMED_VALID"]})

    assert len(findings) == 1
    req = httpx_mock.get_requests()[1]
    assert req.url.params.get_list("validationState") == ["VALIDATION_STATE_CONFIRMED_VALID"]


def test_fetch_secrets_pagination_not_overridden(httpx_mock):
    """limit/cursor in extra_params do not override pagination."""
    secrets_re = re.compile(rf"^{re.escape(SECRETS_URL)}")
    httpx_mock.add_response(url=DEPLOYMENTS_URL, json=DEPLOYMENTS_RESPONSE)
    httpx_mock.add_response(url=secrets_re, json={"findings": [_secret_raw("s1")], "cursor": ""})

    client = SemgrepClient(token=TOKEN, deployment_slug=SLUG)
    client.fetch_secrets(max_findings=5, extra_params={"limit": 9999, "cursor": "bad-cursor"})

    req = httpx_mock.get_requests()[1]
    assert req.url.params["limit"] == "5"
    assert "cursor" not in req.url.params
