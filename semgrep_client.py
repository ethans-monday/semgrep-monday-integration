"""Semgrep Cloud Platform API client.

Handles two distinct endpoints with different pagination schemes:
  - /findings  (SAST + SCA)  — offset-based pagination (page / page_size)
  - /issues v2 (Secrets)     — POST with cursor pagination

Secrets use the v2 Issues API:
  - POST https://semgrep.dev/api/agent/deployments/{id}/issues
  - Response: {"issues": [{"issue": {...}}, ...], "cursor": "..."}
  - Triage: PATCH https://semgrep.dev/api/agent/deployments/{id}/findings/v2
"""

from dataclasses import dataclass
from urllib.parse import urlencode

import time

import httpx

SEMGREP_BASE = "https://semgrep.dev/api/v1"
SEMGREP_V2_BASE = "https://semgrep.dev/api/agent"
_TIMEOUT = 120
_MAX_RETRIES = 3
_RETRY_BACKOFF = 5  # seconds


class SemgrepAPIError(Exception):
    pass


@dataclass
class Finding:
    id: str
    rule_name: str
    severity: str
    file_path: str
    line: int
    repo: str
    finding_type: str  # "SAST" | "SCA" | "Secrets"
    raw: dict          # Full API response — mappers extract type-specific fields


class SemgrepClient:
    def __init__(self, token: str, deployment_slug: str, deployment_id: str | None = None) -> None:
        self._slug = deployment_slug
        self._dep_id = deployment_id
        self._headers = {"Authorization": f"Bearer {token}"}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, url: str, params: dict | None = None) -> dict:
        for attempt in range(_MAX_RETRIES):
            try:
                print(f"  [semgrep] GET {url}" + (f"?{urlencode(params, doseq=True)}" if params else ""))
                response = httpx.get(url, headers=self._headers, params=params, timeout=_TIMEOUT)
                if response.status_code != 200:
                    raise SemgrepAPIError(
                        f"HTTP {response.status_code} from {url}: {response.text[:300]}"
                    )
                return response.json()
            except httpx.TimeoutException:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF * (attempt + 1))
                    continue
                raise

    def _post(self, url: str, body: dict) -> dict:
        for attempt in range(_MAX_RETRIES):
            try:
                print(f"  [semgrep] POST {url} body={body}")
                response = httpx.post(
                    url, headers={**self._headers, "Content-Type": "application/json"},
                    json=body, timeout=_TIMEOUT,
                )
                if response.status_code != 200:
                    raise SemgrepAPIError(
                        f"HTTP {response.status_code} from {url}: {response.text[:300]}"
                    )
                return response.json()
            except httpx.TimeoutException:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF * (attempt + 1))
                    continue
                raise

    def _patch(self, url: str, body: dict) -> dict:
        for attempt in range(_MAX_RETRIES):
            try:
                print(f"  [semgrep] PATCH {url} body={body}")
                response = httpx.patch(
                    url, headers={**self._headers, "Content-Type": "application/json"},
                    json=body, timeout=_TIMEOUT,
                )
                if response.status_code != 200:
                    raise SemgrepAPIError(
                        f"HTTP {response.status_code} from {url}: {response.text[:300]}"
                    )
                return response.json()
            except httpx.TimeoutException:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF * (attempt + 1))
                    continue
                raise

    def _fetch_deployment_id(self) -> str:
        """Discover the numeric deployment ID for the configured slug."""
        url = f"{SEMGREP_BASE}/deployments"
        data = self._get(url)
        for dep in data.get("deployments", []):
            if dep.get("slug") == self._slug:
                return str(dep["id"])
        raise SemgrepAPIError(f"No deployment found with slug '{self._slug}'")

    @staticmethod
    def _parse_finding(raw: dict, finding_type: str) -> Finding:
        location = raw.get("location") or {}
        repository = raw.get("repository") or {}
        return Finding(
            id=str(raw["id"]),
            rule_name=raw.get("rule_name", ""),
            severity=(raw.get("severity") or "UNKNOWN").upper(),
            file_path=location.get("file_path", ""),
            line=location.get("line", 0),
            repo=repository.get("name", ""),
            finding_type=finding_type,
            raw=raw,
        )

    @staticmethod
    def _parse_secret_issue(raw: dict) -> Finding:
        """Parse a secret from the v2 Issues API response."""
        raw_sev = (raw.get("severity") or "UNKNOWN").upper()
        if raw_sev.startswith("SEVERITY_"):
            raw_sev = raw_sev[len("SEVERITY_"):]

        return Finding(
            id=str(raw["id"]),
            rule_name=raw.get("rulePath", ""),
            severity=raw_sev,
            file_path=raw.get("filePath", ""),
            line=raw.get("line", 0),
            repo=(raw.get("repository") or {}).get("name", ""),
            finding_type="Secrets",
            raw=raw,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_projects(self) -> list[dict]:
        """Fetch all projects for this deployment.

        Returns list of project dicts with keys: name, tags, id, url, etc.
        """
        url = f"{SEMGREP_BASE}/deployments/{self._slug}/projects"
        data = self._get(url)
        return data.get("projects", [])

    def fetch_project(self, project_name: str) -> dict | None:
        """Fetch a single project by name.

        Returns project dict or None if not found.
        """
        url = f"{SEMGREP_BASE}/deployments/{self._slug}/projects/{project_name}"
        try:
            data = self._get(url)
            return data.get("project")
        except SemgrepAPIError:
            return None

    def fetch_findings(
        self,
        issue_type: str,
        max_findings: int = 10_000,
        extra_params: dict | None = None,
    ) -> list[Finding]:
        """Fetch SAST or SCA findings using offset pagination.

        Args:
            issue_type: ``"sast"`` or ``"sca"``
            max_findings: Stop after collecting this many findings.
            extra_params: Additional query params (e.g. filter pushdowns). Pagination
                          params ``page`` and ``page_size`` always take precedence.
        """
        url = f"{SEMGREP_BASE}/deployments/{self._slug}/findings"
        label = "SCA" if issue_type == "sca" else "SAST"
        results: list[Finding] = []
        page = 0

        while len(results) < max_findings:
            remaining = max_findings - len(results)
            page_size = min(100, remaining)
            params: dict = {"status": "open", "issue_type": issue_type}
            if extra_params:
                for k, v in extra_params.items():
                    if k not in ("page", "page_size"):
                        params[k] = v
            params["page"] = page
            params["page_size"] = page_size
            data = self._get(url, params)
            batch = data.get("findings", [])
            if not batch:
                break
            results.extend(self._parse_finding(f, label) for f in batch)
            page += 1

        return results[:max_findings]

    _V2_ISSUE_TYPE_MAP = {
        "sast": "ISSUE_TYPE_SAST",
        "sca": "ISSUE_TYPE_SCA",
        "secrets": "ISSUE_TYPE_SECRETS",
    }

    _V2_FINDING_TYPE_MAP = {"sast": "SAST", "sca": "SCA", "secrets": "Secrets"}

    def _fetch_v2_issues(
        self,
        issue_type: str,
        max_findings: int,
        filter_params: dict | None,
    ) -> list[Finding]:
        """Common v2 /issues loop. Cursor-paginated.

        Args:
            issue_type: ``"sast"``, ``"sca"``, or ``"secrets"``.
            max_findings: Stop after collecting this many.
            filter_params: dict for the v2 ``filter`` body field.
        """
        v2_type = self._V2_ISSUE_TYPE_MAP.get(issue_type)
        if v2_type is None:
            raise SemgrepAPIError(f"Unknown issue_type '{issue_type}'")
        finding_type = self._V2_FINDING_TYPE_MAP[issue_type]

        if not self._dep_id:
            self._dep_id = self._fetch_deployment_id()
        url = f"{SEMGREP_V2_BASE}/deployments/{self._dep_id}/issues"
        results: list[Finding] = []
        cursor: str = ""

        while len(results) < max_findings:
            remaining = max_findings - len(results)
            page_size = min(100, remaining)
            body: dict = {
                "deploymentId": self._dep_id,
                "issueType": v2_type,
                "limit": page_size,
            }
            if filter_params:
                body["filter"] = filter_params
            if cursor:
                body["cursor"] = cursor

            data = self._post(url, body)
            issues = data.get("issues", [])
            if not issues:
                break

            for item in issues:
                issue = item.get("issue") or item
                results.append(self._parse_v2_issue(issue, finding_type))

            cursor = data.get("cursor", "")
            if not cursor:
                break

        return results[:max_findings]

    @staticmethod
    def _parse_v2_issue(raw: dict, finding_type: str) -> Finding:
        """Parse a v2 issue (SAST/SCA/Secrets) into a Finding.

        v2 uses camelCase and prefixed severity enums. This is a minimal
        parser sufficient for mark_fixed matching (id + repo). Full v2
        parsing lives on the dedicated v2 migration branch.
        """
        raw_sev = (raw.get("severity") or "UNKNOWN").upper()
        if raw_sev.startswith("SEVERITY_"):
            raw_sev = raw_sev[len("SEVERITY_"):]
        return Finding(
            id=str(raw["id"]),
            rule_name=raw.get("rulePath", ""),
            severity=raw_sev,
            file_path=raw.get("filePath", ""),
            line=raw.get("line", 0),
            repo=(raw.get("repository") or {}).get("name", ""),
            finding_type=finding_type,
            raw=raw,
        )

    def fetch_secrets(
        self,
        max_findings: int = 10_000,
        filter_params: dict | None = None,
    ) -> list[Finding]:
        """Fetch Secrets issues using the v2 Issues API (POST, cursor pagination)."""
        # Keep the legacy _parse_secret_issue parser for Secrets since it's
        # exercised by the existing sync path. Only the v2 caller for
        # SAST/SCA (mark_fixed) uses the generic _parse_v2_issue.
        v2_type = self._V2_ISSUE_TYPE_MAP["secrets"]
        if not self._dep_id:
            self._dep_id = self._fetch_deployment_id()
        url = f"{SEMGREP_V2_BASE}/deployments/{self._dep_id}/issues"
        results: list[Finding] = []
        cursor: str = ""

        while len(results) < max_findings:
            remaining = max_findings - len(results)
            page_size = min(100, remaining)
            body: dict = {
                "deploymentId": self._dep_id,
                "issueType": v2_type,
                "limit": page_size,
            }
            if filter_params:
                body["filter"] = filter_params
            if cursor:
                body["cursor"] = cursor

            data = self._post(url, body)
            issues = data.get("issues", [])
            if not issues:
                break

            for item in issues:
                issue = item.get("issue") or item
                results.append(self._parse_secret_issue(issue))

            cursor = data.get("cursor", "")
            if not cursor:
                break

        return results[:max_findings]

    def fetch_fixed_issues_v2(
        self,
        issue_type: str,
        since: str | None = None,
        max_findings: int = 1_000_000,
    ) -> list[Finding]:
        """Fetch fixed issues on the primary branch via the v2 Issues API.

        Server-side filters: aggregateIssueStates = FIXED, onPrimaryBranch = true.
        Optionally ``since`` (ISO 8601) narrows to findings fixed after that time.

        Args:
            issue_type: ``"sast"`` or ``"sca"``.
            since: ISO 8601 timestamp; if set, filters by TIME_FILTER_FIXED_AT >= since.
            max_findings: Safety cap; defaults to 1M (effectively unbounded).

        Returns:
            List of Finding objects (id + repo minimally populated).
        """
        if issue_type not in ("sast", "sca"):
            raise SemgrepAPIError(f"fetch_fixed_issues_v2 supports sast/sca; got '{issue_type}'")
        filter_params: dict = {
            "aggregateIssueStates": ["AGGREGATE_ISSUE_STATE_FIXED"],
            "onPrimaryBranch": True,
        }
        if since:
            filter_params["timeFilter"] = "TIME_FILTER_FIXED_AT"
            filter_params["since"] = since
        return self._fetch_v2_issues(issue_type, max_findings, filter_params)

    def triage_findings(
        self,
        finding_ids: list[str],
        triage_state: str,
        note: str,
        issue_type: str,
    ) -> None:
        """Triage one or more findings in Semgrep (set state + note).

        Args:
            finding_ids: Semgrep finding IDs (strings).
            triage_state: New triage state (e.g. ``"reviewing"``).
            note: Note text (e.g. ``"Created monday item: https://..."``).
            issue_type: ``"sast"``, ``"sca"``, or ``"secrets"``.
        """
        if issue_type == "secrets":
            self._triage_secrets_v2(finding_ids, triage_state, note)
        else:
            self._triage_v1(finding_ids, triage_state, note, issue_type)

    def _triage_v1(
        self, finding_ids: list[str], triage_state: str, note: str, issue_type: str,
    ) -> None:
        url = f"{SEMGREP_BASE}/deployments/{self._slug}/triage"
        batch_size = 3000
        for i in range(0, len(finding_ids), batch_size):
            batch = finding_ids[i : i + batch_size]
            body = {
                "issue_type": issue_type,
                "issue_ids": [int(fid) for fid in batch],
                "new_triage_state": triage_state,
                "new_note": note,
            }
            self._post(url, body)

    def _triage_secrets_v2(
        self, finding_ids: list[str], triage_state: str, note: str,
    ) -> None:
        if not self._dep_id:
            self._dep_id = self._fetch_deployment_id()
        url = f"{SEMGREP_V2_BASE}/deployments/{self._dep_id}/findings/v2"
        state_map = {
            "reviewing": "FINDING_TRIAGE_STATE_REVIEWING",
            "ignored": "FINDING_TRIAGE_STATE_IGNORED",
            "reopened": "FINDING_TRIAGE_STATE_REOPENED",
            "fixing": "FINDING_TRIAGE_STATE_FIXING",
        }
        v2_state = state_map.get(triage_state, f"FINDING_TRIAGE_STATE_{triage_state.upper()}")
        body: dict = {
            "deploymentId": self._dep_id,
            "issueType": "ISSUE_TYPE_SECRETS",
            "filter": {"ids": finding_ids},
            "params": {"triageState": v2_state, "note": note},
        }
        self._patch(url, body)
