# TODO (deferred — not supported in v1):
#   - negation:    !severity: [LOW]
#   - numeric:     epss_score_min: 0.5, epss_score_max: 0.9
#   - substring:   rule_name_contains: [sql, xss]
#   - boolean:     has_fix: true
#   - not_analyzed AI verdict: findings where assistant.autotriage_verdict is absent entirely
#     (confirmed: finding 784612867 returns assistant: {} with no autotriage_verdict field).
#     The Semgrep API autotriage_verdict param only accepts true_positive / false_positive —
#     there is no server-side way to filter for "not analyzed". Requires client-side post-filter.
#   - file_risk_level: maps to raw.assistant.component.risk (high/low/neutral).
#     No server-side param exists — silently ignored by v1 API. Client-side post-filter only.

from pathlib import Path

import yaml

# Single source of truth: which filter keys are supported per board type,
# and what Semgrep API query param each maps to.
# Verified against the /deployments/<slug>/findings API docs (2025-05).
# Secrets endpoint params are unverified — update when /secrets docs are available.
ALLOWED_FILTERS: dict[str, dict[str, str]] = {
    "sast": {
        "severity": "severities",          # Array of strings: low, medium, high, critical
        "confidence": "confidence",         # Scalar string: low, medium, high
        "repo": "repos",                    # Array of strings: org/repo
        "rule": "rules",                    # Array of strings: rule IDs
        "ai_verdict": "autotriage_verdict", # Scalar string: true_positive, false_positive
        "status": "status",                # Array: open, fixed, ignored, reviewing, fixing, provisionally_ignored
        "file_risk_level": "_file_risk_level",  # Client-side only: high, low, unknown
    },
    "sca": {
        "severity": "severities",           # Array of strings: low, medium, high, critical
        "confidence": "confidence",         # Scalar string: low, medium, high
        "repo": "repos",                    # Array of strings: org/repo
        "reachability": "exposures",        # Array: reachable, always_reachable, conditionally_reachable, unreachable, unknown
        "transitivity": "transitivities",   # Array: direct, transitive, unknown
        "status": "status",                # Array: open, fixed, ignored, reviewing, fixing, provisionally_ignored
        "malicious": "_malicious",          # Boolean trigger: [true] → second fetch with is_malicious=true
    },
    "secrets": {
        # v2 Issues API (POST /api/agent/deployments/{id}/issues) filter body fields.
        "severity": "severities",              # Array: SEVERITY_HIGH, SEVERITY_CRITICAL, etc.
        "confidence": "confidences",           # Array: CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW
        "repo": "repositoryNames",             # Array of strings: org/repo
        "validation_state": "validationStates", # Array: VALIDATION_STATE_CONFIRMED_VALID, etc.
        "secret_type": "secretTypes",          # Array of strings
        "repo_visibility": "repoVisibilities", # Array: REPOSITORY_VISIBILITY_PUBLIC, etc.
        "exclude_historical": "_exclude_historical",  # Boolean trigger (handled specially)
        "status": "tab",                        # String: ISSUE_TAB_OPEN, ISSUE_TAB_REVIEWING, etc.
    },
}

# Semgrep API params that accept a single string value (not repeatable).
# load_filters enforces exactly 1 value for these; to_query_params passes a string, not a list.
# Note: autotriage_verdict is NOT here — ai_verdict has special handling because
# not_analyzed has no API equivalent and is applied client-side by filter_findings().
SCALAR_PARAMS: frozenset[str] = frozenset({"confidence"})

# Secrets v2 API params that accept a single string value.
_SECRETS_SCALAR_PARAMS: frozenset[str] = frozenset({"tab"})


def load_filters(path: Path | None) -> dict:
    """Parse a filters YAML file and return {board_type: {filter_key: [values]}}.

    Also handles the top-level ``ignore_repos`` key (list of repo names to
    exclude from all finding types after fetching).

    Returns {} if path is None or the file does not exist.
    Raises ValueError on unknown board types, unknown filter keys, non-list values,
    or multiple values for a scalar API param.
    """
    if path is None or not path.exists():
        return {}

    raw = yaml.safe_load(path.read_text()) or {}
    result: dict = {}

    ignore_repos = raw.pop("ignore_repos", None)
    if ignore_repos is not None:
        if not isinstance(ignore_repos, list):
            raise ValueError("'ignore_repos' must be a list of repo name strings.")
        result["ignore_repos"] = [str(r) for r in ignore_repos]

    for board_type, block in raw.items():
        if board_type not in ALLOWED_FILTERS:
            raise ValueError(
                f"Unknown board type '{board_type}' in filters file. "
                f"Allowed: {list(ALLOWED_FILTERS)}"
            )
        if not isinstance(block, dict):
            raise ValueError(f"Filter block for '{board_type}' must be a mapping, got {type(block).__name__}")

        allowed_keys = ALLOWED_FILTERS[board_type]
        result[board_type] = {}

        for key, values in block.items():
            if key not in allowed_keys:
                raise ValueError(
                    f"Unknown filter key '{key}' for board type '{board_type}'. "
                    f"Allowed: {list(allowed_keys)}"
                )
            if not isinstance(values, list):
                raise ValueError(
                    f"Filter value for '{board_type}.{key}' must be a list, "
                    f"got {type(values).__name__}. Wrap scalar values in [ ]."
                )
            api_param = allowed_keys[key]
            if api_param in SCALAR_PARAMS and len(values) != 1:
                raise ValueError(
                    f"Filter '{board_type}.{key}' maps to a scalar Semgrep API param "
                    f"and must contain exactly 1 value, got {len(values)}."
                )
            if api_param in _SECRETS_SCALAR_PARAMS and len(values) != 1:
                raise ValueError(
                    f"Filter '{board_type}.{key}' maps to a scalar API param "
                    f"and must contain exactly 1 value, got {len(values)}."
                )
            if key == "malicious":
                val = str(values[0]).lower()
                if val != "true" or len(values) != 1:
                    raise ValueError(
                        f"Filter '{board_type}.malicious' must be [true], got {values}."
                    )
            if key == "exclude_historical":
                val = str(values[0]).lower()
                if val != "true" or len(values) != 1:
                    raise ValueError(
                        f"Filter '{board_type}.exclude_historical' must be [true], got {values}."
                    )
            if key == "file_risk_level":
                allowed_risk = {"high", "low", "unknown"}
                bad = [v for v in values if str(v).lower() not in allowed_risk]
                if bad:
                    raise ValueError(
                        f"Filter 'sast.file_risk_level' values must be in {sorted(allowed_risk)}, got {bad}."
                    )
            if key == "file_risk_level":
                result[board_type][key] = [str(v).lower() for v in values]
            else:
                result[board_type][key] = [str(v) for v in values]

    return result


def to_query_params(board_type: str, filters: dict) -> dict:
    """Convert a board's filter block to Semgrep API query params (SAST/SCA only).

    Returns {} if no filters are configured for this board type.
    Array params are passed as lists (httpx serializes as repeated keys).
    Scalar params (SCALAR_PARAMS) are passed as a plain string.

    ai_verdict special case: not_analyzed has no Semgrep API equivalent.
    Only pushes autotriage_verdict when there is exactly one value and it is not not_analyzed.
    Otherwise the filter is skipped here and applied client-side by filter_findings().

    For secrets, use ``to_secrets_filter_body()`` instead.
    """
    block = filters.get(board_type, {})
    if not block:
        return {}

    param_map = ALLOWED_FILTERS[board_type]
    result = {}
    for key, values in block.items():
        api_param = param_map[key]

        if key in ("malicious", "file_risk_level"):
            continue

        if key == "ai_verdict":
            server_values = [v for v in values if v != "not_analyzed"]
            if len(values) == 1 and server_values:
                result[api_param] = server_values[0]
            # else: mixed or not_analyzed-only — client-side only, skip here
            continue

        result[api_param] = values[0] if api_param in SCALAR_PARAMS else values
    return result


def to_secrets_filter_body(filters: dict) -> dict:
    """Convert secrets filter block to a v2 Issues API ``filter`` dict.

    Returns {} if no secrets filters are configured.
    """
    block = filters.get("secrets", {})
    if not block:
        return {}

    param_map = ALLOWED_FILTERS["secrets"]
    result: dict = {}
    for key, values in block.items():
        api_param = param_map[key]

        if key == "exclude_historical":
            val = str(values[0]).lower()
            if val == "true":
                result["excludeHistorical"] = True
            continue

        result[api_param] = values[0] if api_param in _SECRETS_SCALAR_PARAMS else values
    return result


def get_ignored_repos(filters: dict) -> set[str]:
    """Return the set of repo names to exclude from all finding types."""
    return set(filters.get("ignore_repos", []))


def has_malicious_filter(filters: dict) -> bool:
    """Return True if the SCA filter block enables the malicious second-pass fetch."""
    return "malicious" in filters.get("sca", {})


def to_malicious_query_params() -> dict:
    """Return query params for the malicious-dependency SCA fetch.

    This is a standalone query — no other filters (severity, reachability, etc.)
    are carried over. Only is_malicious=true is sent, so we catch all malicious
    findings regardless of severity or reachability.
    """
    return {"is_malicious": "true"}


def _get_ai_verdict(finding) -> str:
    """Return a finding's AI autotriage verdict, or 'not_analyzed' if absent."""
    assistant = finding.raw.get("assistant") or {}
    autotriage = assistant.get("autotriage") or {}
    verdict = autotriage.get("verdict") or ""
    return verdict if verdict else "not_analyzed"


# Maps user-facing file_risk_level values to assistant.component.risk API values.
# "unknown" covers both absent component data and the explicit "neutral" risk tag.
_FILE_RISK_API_VALUES: dict[str, set[str]] = {
    "high": {"high"},
    "low": {"low"},
    "unknown": {"neutral", "unknown", ""},
}


def _get_file_risk_level(finding) -> str:
    """Return the file risk level for a SAST finding: 'high', 'low', or 'unknown'."""
    assistant = finding.raw.get("assistant") or {}
    risk = (assistant.get("component") or {}).get("risk") or ""
    if risk == "high":
        return "high"
    if risk == "low":
        return "low"
    return "unknown"


def filter_findings(findings: list, board_type: str, filters: dict) -> list:
    """Apply client-side filters that cannot be pushed server-side to the Semgrep API.

    Handles:
      - ai_verdict when the list contains not_analyzed or multiple values (SAST)
      - file_risk_level: high / low / unknown, mapped from assistant.component.risk (SAST)

    Returns the input list unchanged when no client-side filtering is needed.
    """
    block = filters.get(board_type, {})
    if not block:
        return findings

    result = findings

    if board_type == "sast":
        ai_verdict_values = block.get("ai_verdict")
        if ai_verdict_values:
            needs_client = "not_analyzed" in ai_verdict_values or len(ai_verdict_values) > 1
            if needs_client:
                verdict_set = set(ai_verdict_values)
                result = [f for f in result if _get_ai_verdict(f) in verdict_set]

        file_risk_values = block.get("file_risk_level")
        if file_risk_values:
            wanted = set(file_risk_values)
            result = [f for f in result if _get_file_risk_level(f) in wanted]

    return result
