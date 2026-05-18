"""Unit tests for SemgrepClient.

All HTTP calls are intercepted by pytest-httpx so no real network traffic occurs.
"""

import pytest
import httpx

from semgrep_client import SemgrepClient, SemgrepAPIError, Finding

TOKEN = "test-token"
SLUG = "acme-corp"
DEP_ID = "20169"

DEPLOYMENTS_URL = "https://semgrep.dev/api/v1/deployments"
FINDINGS_URL = f"https://semgrep.dev/api/v1/deployments/{SLUG}/findings"
SECRETS_V2_URL = f"https://semgrep.dev/api/agent/deployments/{DEP_ID}/issues"

DEPLOYMENTS_RESPONSE = {"deployments": [{"id": int(DEP_ID), "slug": SLUG, "name": "Acme Corp"}]}


def make_client() -> SemgrepClient:
    return SemgrepClient(token=TOKEN, deployment_slug=SLUG)


def _finding_raw(fid="1", severity="HIGH", issue_type="sast"):
    return {
        "id": fid,
        "rule_name": f"rule.{fid}",
        "severity": severity,
        "location": {"file_path": f"src/file{fid}.py", "line": 1},
        "repository": {"name": "repo"},
    }


def _secret_raw(fid="s1", severity="HIGH"):
    return {
        "id": fid,
        "rulePath": f"secrets.type.{fid}",
        "severity": severity,
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
# fetch_findings — SAST
# ---------------------------------------------------------------------------

def test_fetch_sast_single_page(httpx_mock):
    httpx_mock.add_response(
        url=f"{FINDINGS_URL}?page=0&page_size=100&status=open&issue_type=sast",
        json={"findings": [_finding_raw("1")], "total": 1},
    )
    httpx_mock.add_response(
        url=f"{FINDINGS_URL}?page=1&page_size=100&status=open&issue_type=sast",
        json={"findings": [], "total": 1},
    )

    findings = make_client().fetch_findings("sast")
    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].id == "1"
    assert findings[0].finding_type == "SAST"


def test_fetch_sast_pagination(httpx_mock):
    """Follows offset pages until an empty batch is returned."""
    httpx_mock.add_response(
        url=f"{FINDINGS_URL}?page=0&page_size=100&status=open&issue_type=sast",
        json={"findings": [_finding_raw("1"), _finding_raw("2")], "total": 3},
    )
    httpx_mock.add_response(
        url=f"{FINDINGS_URL}?page=1&page_size=100&status=open&issue_type=sast",
        json={"findings": [_finding_raw("3")], "total": 3},
    )
    httpx_mock.add_response(
        url=f"{FINDINGS_URL}?page=2&page_size=100&status=open&issue_type=sast",
        json={"findings": [], "total": 3},
    )

    findings = make_client().fetch_findings("sast")
    assert len(findings) == 3
    assert [f.id for f in findings] == ["1", "2", "3"]


def test_fetch_sca_passes_scan_type(httpx_mock):
    """issue_type=sca must be sent and findings labelled SCA."""
    httpx_mock.add_response(
        url=f"{FINDINGS_URL}?page=0&page_size=100&status=open&issue_type=sca",
        json={"findings": [_finding_raw("10")], "total": 1},
    )
    httpx_mock.add_response(
        url=f"{FINDINGS_URL}?page=1&page_size=100&status=open&issue_type=sca",
        json={"findings": [], "total": 1},
    )

    findings = make_client().fetch_findings("sca")
    assert len(findings) == 1
    assert findings[0].finding_type == "SCA"


# ---------------------------------------------------------------------------
# fetch_secrets — v2 Issues API (POST, cursor pagination)
# ---------------------------------------------------------------------------

def test_fetch_secrets_cursor_pagination(httpx_mock):
    """Follows cursor chain across two pages via POST."""
    httpx_mock.add_response(url=DEPLOYMENTS_URL, json=DEPLOYMENTS_RESPONSE)
    httpx_mock.add_response(
        url=SECRETS_V2_URL, method="POST",
        json={"issues": [_v2_issue_wrapper(_secret_raw("s1"))], "cursor": "cursor-abc"},
    )
    httpx_mock.add_response(
        url=SECRETS_V2_URL, method="POST",
        json={"issues": [_v2_issue_wrapper(_secret_raw("s2"))], "cursor": ""},
    )

    findings = make_client().fetch_secrets()
    assert len(findings) == 2
    assert findings[0].id == "s1"
    assert findings[1].id == "s2"
    assert findings[0].rule_name == "secrets.type.s1"
    assert findings[0].file_path == "src/files1.py"
    assert findings[0].line == 10
    assert findings[0].repo == "repo"
    assert all(f.finding_type == "Secrets" for f in findings)


def test_fetch_secrets_severity_normalization(httpx_mock):
    """SEVERITY_MEDIUM prefix is stripped and uppercased."""
    httpx_mock.add_response(url=DEPLOYMENTS_URL, json=DEPLOYMENTS_RESPONSE)
    httpx_mock.add_response(
        url=SECRETS_V2_URL, method="POST",
        json={"issues": [_v2_issue_wrapper(_secret_raw("s1", severity="SEVERITY_MEDIUM"))], "cursor": ""},
    )

    findings = make_client().fetch_secrets()
    assert findings[0].severity == "MEDIUM"


def test_fetch_secrets_stops_on_empty_results(httpx_mock):
    """Stops immediately if the first page returns an empty issues array."""
    httpx_mock.add_response(url=DEPLOYMENTS_URL, json=DEPLOYMENTS_RESPONSE)
    httpx_mock.add_response(
        url=SECRETS_V2_URL, method="POST",
        json={"issues": [], "cursor": "some-cursor"},
    )

    findings = make_client().fetch_secrets()
    assert findings == []


# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------

def test_auth_header_sent(httpx_mock):
    httpx_mock.add_response(
        url=f"{FINDINGS_URL}?page=0&page_size=100&status=open&issue_type=sast",
        json={"findings": [], "total": 0},
    )

    make_client().fetch_findings("sast")

    request = httpx_mock.get_requests()[0]
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_http_error_raises(httpx_mock):
    httpx_mock.add_response(
        url=f"{FINDINGS_URL}?page=0&page_size=100&status=open&issue_type=sast",
        status_code=403,
        text="Forbidden",
    )

    with pytest.raises(SemgrepAPIError, match="403"):
        make_client().fetch_findings("sast")
