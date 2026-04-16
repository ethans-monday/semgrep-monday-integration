"""Semgrep Cloud Platform API client.

Handles two distinct endpoints with different pagination schemes:
  - /findings  (SAST + SCA)  — offset-based pagination (page / page_size)
  - /secrets                  — cursor-based pagination (cursor / limit)
"""

from dataclasses import dataclass

import httpx

SEMGREP_BASE = "https://semgrep.dev/api/v1"


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
    def __init__(self, token: str, deployment_slug: str, deployment_id: str) -> None:
        self._slug = deployment_slug
        self._dep_id = deployment_id
        self._headers = {"Authorization": f"Bearer {token}"}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, url: str, params: dict | None = None) -> dict:
        response = httpx.get(url, headers=self._headers, params=params, timeout=30)
        if response.status_code != 200:
            raise SemgrepAPIError(
                f"HTTP {response.status_code} from {url}: {response.text[:300]}"
            )
        return response.json()

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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_findings(self, issue_type: str, max_findings: int = 10_000) -> list[Finding]:
        """Fetch SAST or SCA findings using offset pagination.

        Args:
            issue_type: ``"sast"`` or ``"sca"``
            max_findings: Stop after collecting this many findings (default 100).
                          Keeps each run within Monday.com free-tier call budget.
        """
        url = f"{SEMGREP_BASE}/deployments/{self._slug}/findings"
        label = "SAST" if issue_type == "sast" else "SCA"
        results: list[Finding] = []
        page = 0

        while len(results) < max_findings:
            remaining = max_findings - len(results)
            page_size = min(100, remaining)
            data = self._get(url, {"page": page, "page_size": page_size, "status": "open", "issue_type": issue_type})
            batch = data.get("findings", [])
            if not batch:
                break
            results.extend(self._parse_finding(f, label) for f in batch)
            page += 1

        return results[:max_findings]

    def fetch_secrets(self) -> list[Finding]:
        """Fetch Secrets findings using cursor pagination.

        Uses the numeric deployment ID (not the slug).
        """
        url = f"{SEMGREP_BASE}/deployments/{self._dep_id}/secrets"
        results: list[Finding] = []
        cursor: str | None = None

        while True:
            params: dict = {"limit": 100}
            if cursor:
                params["cursor"] = cursor

            data = self._get(url, params)
            batch = data.get("secrets", [])
            if not batch:
                break

            results.extend(self._parse_finding(f, "Secrets") for f in batch)

            cursor = data.get("cursor", "")
            if not cursor:
                break

        return results
