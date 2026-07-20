"""Semgrep → monday.com sync script (three-board architecture).

Usage:
    python setup_boards.py             # one-time: create boards + columns
    cp .env.example .env               # fill in credentials + board IDs
    python sync.py                     # sync all findings
    python sync.py --limit 50          # sync up to 50 per type
    python sync.py --filters my.yaml              # apply custom filters file
    python sync.py --no-filters                   # skip filtering even if filters.yaml exists
    python sync.py --set-triage-reviewing         # triage synced findings to 'reviewing' in Semgrep
    python sync.py --dry-run                      # fetch and print finding IDs without side effects
    python sync.py --mark-fixed                   # after sync, reconcile items: mark Fixed / Not scanned by Semgrep (SAST + SCA)

State is persisted in state.json. Re-running is safe — findings already synced
are skipped (deduplication by Semgrep finding ID).
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from dotenv import load_dotenv

from filters import filter_findings, get_ignored_repos, has_malicious_filter, load_filters, to_malicious_query_params, to_query_params, to_secrets_filter_body
from monday_client import MondayAPIError, MondayClient
from semgrep_client import Finding, SemgrepAPIError, SemgrepClient

DEFAULT_STATE_FILE = Path(__file__).parent / "state.json"
DEFAULT_FIXED_SYNCED_FILE = Path(__file__).parent / "fixed_state.json"
DEFAULT_FILTERS_FILE = Path(__file__).parent / "filters.yaml"
STATE_VERSION = 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_get(d: dict, *keys, default: str = "") -> str:
    """Safely traverse nested dicts. Returns str(value) or default."""
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key)
        if d is None:
            return default
    return str(d) if d is not None else default


def _truncate(text: str, max_len: int = 500) -> str:
    if not text or len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _join_list(items) -> str:
    """Join a list of strings, or return empty string if not a list."""
    if isinstance(items, list):
        return ", ".join(str(i) for i in items)
    return ""


def _snake_to_title(s: str) -> str:
    return " ".join(w.capitalize() for w in s.split("_")) if s else ""


def _set_col(col_vals: dict, col_map: dict[str, str], title: str, value: str) -> None:
    """Set a text column value."""
    if title in col_map and value:
        col_vals[col_map[title]] = value


def _set_status_col(col_vals: dict, col_map: dict[str, str], title: str, value: str) -> None:
    """Set a status column value using monday.com's {"label": "..."} format."""
    if title in col_map and value:
        col_vals[col_map[title]] = {"label": value}


def _set_link_col(col_vals: dict, col_map: dict[str, str], title: str, url: str) -> None:
    """Set a link column value using monday.com's {"url": "...", "text": "..."} format."""
    if title in col_map and url:
        col_vals[col_map[title]] = {"url": url, "text": "Open"}


def _set_dropdown_col(col_vals: dict, col_map: dict[str, str], title: str, items: list | None) -> None:
    """Set a dropdown column value using monday.com's {"labels": [...]} format."""
    if title not in col_map or not items:
        return
    labels = [str(i) for i in items if i]
    if labels:
        col_vals[col_map[title]] = {"labels": labels}


def _fmt_field(label: str, value: str) -> str | None:
    """Return an HTML-formatted '<b>Label:</b> value' line, or None if value is empty."""
    return f"<b>{label}:</b> {value}" if value else None


@dataclass
class FindingGroup:
    representative: Finding
    members: list[Finding]


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


_VALIDATION_RANK = {
    "VALIDATION_STATE_CONFIRMED_VALID": 3,
    "VALIDATION_STATE_VALIDATION_ERROR": 2,
    "VALIDATION_STATE_NO_VALIDATOR": 1,
    "VALIDATION_STATE_CONFIRMED_INVALID": 0,
}


def _finding_score(finding: Finding, board_type: str) -> tuple:
    sev = _SEVERITY_RANK.get(finding.severity.upper(), 0)
    raw = finding.raw
    conf_str = _safe_get(raw, "confidence").upper()
    if conf_str.startswith("CONFIDENCE_"):
        conf_str = conf_str[len("CONFIDENCE_"):]
    conf = _CONFIDENCE_RANK.get(conf_str, 0)
    if board_type == "SCA":
        reach = _safe_get(raw, "reachability").lower()
        reach_score = 2 if reach in ("reachable", "always_reachable", "conditionally_reachable") else (1 if reach == "unknown" else 0)
        return (sev, reach_score, conf)
    if board_type == "Secrets":
        val_state = (raw.get("secretsAttributes") or {}).get("validationState", "")
        val_score = _VALIDATION_RANK.get(val_state, 1)
        return (sev, val_score, conf)
    verdict = _safe_get(raw, "assistant", "autotriage", "verdict")
    verdict_score = 2 if verdict == "true_positive" else (0 if verdict == "false_positive" else 1)
    return (sev, verdict_score, conf)


def _sca_group_key(finding: Finding) -> tuple:
    dep = finding.raw.get("found_dependency") or {}
    return (finding.repo, dep.get("package", ""), finding.file_path)


def _sast_group_key(finding: Finding) -> tuple:
    loc = finding.raw.get("location") or {}
    end_loc = f"{loc.get('end_line', '')}:{loc.get('end_column', '')}"
    return (finding.repo, finding.file_path, end_loc)


def _secrets_group_key(finding: Finding) -> tuple:
    return (finding.repo, finding.file_path, str(finding.line))


def group_findings(findings: list[Finding], board_type: str) -> list[FindingGroup]:
    key_fn = {"SCA": _sca_group_key, "SAST": _sast_group_key, "Secrets": _secrets_group_key}[board_type]
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        groups.setdefault(key_fn(f), []).append(f)
    result = []
    for members in groups.values():
        members.sort(key=lambda f: _finding_score(f, board_type), reverse=True)
        result.append(FindingGroup(representative=members[0], members=members))
    return result


def _apply_sca_merged_fields(cv: dict, col_map: dict[str, str], group: FindingGroup) -> None:
    if len(group.members) <= 1:
        return
    _set_col(cv, col_map, "Finding ID", ", ".join(f.id for f in group.members))
    cves = [_safe_get(f.raw, "vulnerability_identifier") for f in group.members]
    _set_col(cv, col_map, "CVE", ", ".join(c for c in cves if c))


def _apply_sast_merged_fields(cv: dict, col_map: dict[str, str], group: FindingGroup) -> None:
    if len(group.members) <= 1:
        return
    _set_col(cv, col_map, "Finding ID", ", ".join(f.id for f in group.members))
    rules = list(dict.fromkeys(f.rule_name for f in group.members))
    _set_col(cv, col_map, "Rule", ", ".join(rules))
    all_cwes = []
    all_owasp = []
    all_vuln_classes = []
    for f in group.members:
        rule = f.raw.get("rule") or {}
        for c in (rule.get("cwe_names") or []):
            if c not in all_cwes:
                all_cwes.append(c)
        for o in (rule.get("owasp_names") or []):
            if o not in all_owasp:
                all_owasp.append(o)
        for v in (rule.get("vulnerability_classes") or []):
            if v not in all_vuln_classes:
                all_vuln_classes.append(v)
    all_components = []
    for f in group.members:
        tag = _safe_get(f.raw, "assistant", "component", "tag")
        risk = _safe_get(f.raw, "assistant", "component", "risk")
        label = f"{tag} ({risk})" if tag else None
        if label and label not in all_components:
            all_components.append(label)
    _set_col(cv, col_map, "CWE", _join_list(all_cwes))
    _set_dropdown_col(cv, col_map, "OWASP", all_owasp)
    _set_dropdown_col(cv, col_map, "Vuln Classes", all_vuln_classes)
    _set_dropdown_col(cv, col_map, "Component", all_components)


def _apply_secrets_merged_fields(cv: dict, col_map: dict[str, str], group: FindingGroup) -> None:
    if len(group.members) <= 1:
        return
    _set_col(cv, col_map, "Finding ID", ", ".join(f.id for f in group.members))
    rules = list(dict.fromkeys(f.rule_name for f in group.members))
    _set_col(cv, col_map, "Rule", ", ".join(rules))
    all_cwes = []
    all_owasp = []
    all_secret_types = []
    for f in group.members:
        for c in (f.raw.get("ruleCweNames") or []):
            if c not in all_cwes:
                all_cwes.append(c)
        for o in (f.raw.get("ruleOwaspNames") or []):
            if o not in all_owasp:
                all_owasp.append(o)
        st = (f.raw.get("secretsAttributes") or {}).get("secretType")
        if st and st not in all_secret_types:
            all_secret_types.append(st)
    _set_col(cv, col_map, "CWE", _join_list(all_cwes))
    _set_dropdown_col(cv, col_map, "OWASP", all_owasp)
    _set_dropdown_col(cv, col_map, "Secret Type", all_secret_types if all_secret_types else None)


def _semgrep_finding_url(slug: str, finding: Finding) -> str:
    """Construct the Semgrep Cloud UI deep-link URL for a finding."""
    if not slug:
        return ""
    base = f"https://semgrep.dev/orgs/{slug}"
    if finding.finding_type == "Secrets":
        return f"{base}/secrets/{finding.id}"
    return f"{base}/findings/{finding.id}"


def _monday_item_url(account_slug: str, board_id: int, item_id: str) -> str:
    if not account_slug:
        return ""
    return f"https://{account_slug}.monday.com/boards/{board_id}/pulses/{item_id}"


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------

def _empty_items() -> dict:
    return {"SAST": {}, "SCA": {}, "Secrets": {}}


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"monday_items_created": _empty_items(), "daily": {}, "version": STATE_VERSION}
    state = json.loads(path.read_text())
    version = state.get("version", 1)
    # v1 and v2 used the key "synced"
    old_key = "synced" if version < 3 else "monday_items_created"
    # Migrate v1 → v2 (finding_id → {monday_item_id, board})
    if version < 2:
        old_synced = state.get(old_key, {})
        state[old_key] = {
            fid: {"monday_item_id": mid, "board": "unknown"}
            for fid, mid in old_synced.items()
        }
        version = 2
    # Migrate v2 → v3 (invert: key by monday_item_id, collect finding_ids; rename key)
    if version < 3:
        v2_synced = state.get(old_key, {})
        v3: dict[str, dict] = {}
        for fid, entry in v2_synced.items():
            mid = str(entry["monday_item_id"])
            if mid in v3:
                v3[mid]["finding_ids"].append(str(fid))
            else:
                v3[mid] = {
                    "board": entry.get("board", "unknown"),
                    "finding_ids": [str(fid)],
                }
        state.pop("synced", None)
        state["monday_items_created"] = v3
        version = 3
    # Migrate v3 → v4 (nest by board type)
    if version < 4:
        v3_items = state.get("monday_items_created", {})
        v4 = _empty_items()
        for mid, entry in v3_items.items():
            board = entry.get("board", "unknown")
            if board in v4:
                v4[board][mid] = entry.get("finding_ids", [])
            else:
                v4.setdefault(board, {})[mid] = entry.get("finding_ids", [])
        state["monday_items_created"] = v4
        version = 4
    # Migrate v4 → v5 (nest each item entry as {"repo": "", "finding_ids": [...]})
    # repo is left empty; mark_fixed() backfills it lazily via monday's Repo column.
    if version < 5:
        v4_items = state.get("monday_items_created", {})
        v5 = _empty_items()
        for board, items in v4_items.items():
            v5.setdefault(board, {})
            for mid, entry in items.items():
                v5[board][mid] = _upgrade_item_entry(entry)
        state["monday_items_created"] = v5
    state["version"] = STATE_VERSION
    for key in _empty_items():
        state["monday_items_created"].setdefault(key, {})
    return state


def _upgrade_item_entry(entry) -> dict:
    """Normalize a per-item state entry to the v5 shape.

    Accepts either a legacy list `[fid, ...]` or an already-v5 dict.
    """
    if isinstance(entry, dict):
        entry.setdefault("repo", "")
        entry.setdefault("finding_ids", [])
        entry["finding_ids"] = [str(f) for f in entry["finding_ids"]]
        return entry
    return {"repo": "", "finding_ids": [str(f) for f in (entry or [])]}


def item_finding_ids(entry) -> list[str]:
    """Return the finding IDs from a v5 (or legacy) state entry."""
    if isinstance(entry, dict):
        return list(entry.get("finding_ids") or [])
    return list(entry or [])


def item_repo(entry) -> str:
    """Return the repo from a v5 state entry (or empty string for legacy)."""
    if isinstance(entry, dict):
        return entry.get("repo") or ""
    return ""


FIXED_STATE_VERSION = 3


def _empty_fixed_state() -> dict:
    return {"version": FIXED_STATE_VERSION, "SECRETS": [], "SAST": {}, "SCA": {}}


def load_fixed_state(path: Path) -> dict:
    """Load fixed_state.json. Auto-migrates older versions on read.

    v1 format: {"version": 1, "SECRETS": [fid, ...]}
    v2 format: {"version": 2, "SECRETS": [fid, ...],
                "SAST": {item_id: [fid, ...]}, "SCA": {item_id: [fid, ...]}}
    v3 format: {"version": 3, "SECRETS": [fid, ...],
                "SAST": {item_id: {"repo": "...", "finding_ids": [fid, ...]}},
                "SCA":  {item_id: {"repo": "...", "finding_ids": [fid, ...]}}}
    """
    if not path.exists():
        return _empty_fixed_state()
    data = json.loads(path.read_text())
    version = data.get("version", 1)
    if version < 2:
        # v1 → v2: preserve SECRETS list; add empty SAST/SCA dicts
        data = {
            "version": 2,
            "SECRETS": data.get("SECRETS", []),
            "SAST": {},
            "SCA": {},
        }
        version = 2
    if version < 3:
        # v2 → v3: nest SAST/SCA entries as {"repo": "", "finding_ids": [...]}
        for board in ("SAST", "SCA"):
            board_data = data.get(board, {}) or {}
            data[board] = {mid: _upgrade_item_entry(v) for mid, v in board_data.items()}
    data.setdefault("SECRETS", [])
    data.setdefault("SAST", {})
    data.setdefault("SCA", {})
    data["version"] = FIXED_STATE_VERSION
    return data


def save_fixed_state(fixed_state: dict, path: Path) -> None:
    # Normalize SECRETS to a sorted list for deterministic output
    out = {
        "version": FIXED_STATE_VERSION,
        "SECRETS": sorted(fixed_state.get("SECRETS", [])),
        "SAST": fixed_state.get("SAST", {}),
        "SCA": fixed_state.get("SCA", {}),
    }
    path.write_text(json.dumps(out, indent=2))


def synced_secrets_ids(fixed_state: dict) -> set[str]:
    return set(fixed_state.get("SECRETS", []))


NOT_SCANNED_STATE_VERSION = 1


def _empty_not_scanned_state() -> dict:
    return {"version": NOT_SCANNED_STATE_VERSION, "SAST": {}, "SCA": {}}


def load_not_scanned_state(path: Path) -> dict:
    """Load not_scanned_state.json.

    Shape mirrors fixed_state.json's SAST/SCA sections:
        {"version": 1,
         "SAST": {item_id: {"repo": "...", "finding_ids": [...]}},
         "SCA":  {item_id: {"repo": "...", "finding_ids": [...]}}}
    Entries land here when their repo is 404 in Semgrep (archived / deleted /
    permissions changed).
    """
    if not path.exists():
        return _empty_not_scanned_state()
    data = json.loads(path.read_text())
    for board in ("SAST", "SCA"):
        board_data = data.get(board, {}) or {}
        data[board] = {mid: _upgrade_item_entry(v) for mid, v in board_data.items()}
    data["version"] = NOT_SCANNED_STATE_VERSION
    return data


def save_not_scanned_state(data: dict, path: Path) -> None:
    out = {
        "version": NOT_SCANNED_STATE_VERSION,
        "SAST": data.get("SAST", {}),
        "SCA": data.get("SCA", {}),
    }
    path.write_text(json.dumps(out, indent=2))


def synced_finding_ids(state: dict, board_type: str) -> set[str]:
    ids: set[str] = set()
    for entry in state.get("monday_items_created", {}).get(board_type, {}).values():
        ids.update(item_finding_ids(entry))
    return ids


def save_state(state: dict, path: Path) -> None:
    path.write_text(json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REQUIRED_ENV_VARS = [
    "SEMGREP_APP_TOKEN",
    "SEMGREP_DEPLOYMENT_SLUG",
    "MONDAY_API_TOKEN",
    "MONDAY_BOARD_ID_SAST",
    "MONDAY_BOARD_ID_SCA",
    "MONDAY_BOARD_ID_SECRETS",
]


def load_config() -> dict:
    load_dotenv(override=True)
    missing = [k for k in REQUIRED_ENV_VARS if not os.getenv(k)]
    if missing:
        print(f"Error: missing required environment variables: {', '.join(missing)}")
        print("Copy .env.example to .env and fill in the values.")
        sys.exit(1)
    return {k: os.getenv(k) for k in REQUIRED_ENV_VARS}


_SEVERITY_LABELS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}

_VALIDATION_STATE_LABELS = {
    "VALIDATION_STATE_NO_VALIDATOR":    "No Validator",
    "VALIDATION_STATE_CONFIRMED_INVALID": "Invalid Secret",
    "VALIDATION_STATE_CONFIRMED_VALID":   "Valid Secret",
    "VALIDATION_STATE_VALIDATION_ERROR":  "Validation Error",
}


# ---------------------------------------------------------------------------
# SAST mapper
# ---------------------------------------------------------------------------

def sast_finding_to_item(finding: Finding, col_map: dict[str, str]) -> tuple[str, dict]:
    raw = finding.raw
    rule = raw.get("rule") or {}
    assistant = raw.get("assistant") or {}
    loc = raw.get("location") or {}

    short_name = finding.rule_name.split(".")[-1]
    item_name = f"{short_name} - {finding.repo} - {finding.file_path}:{finding.line}"
    cv: dict = {}

    _set_col(cv, col_map, "Finding ID", finding.id)
    _set_status_col(cv, col_map, "Severity", _SEVERITY_LABELS.get(finding.severity, finding.severity.capitalize()))
    _set_status_col(cv, col_map, "Confidence", _safe_get(raw, "confidence").capitalize())
    _set_col(cv, col_map, "Rule", finding.rule_name)
    _set_status_col(cv, col_map, "Triage State", _snake_to_title(_safe_get(raw, "triage_state")))
    _set_col(cv, col_map, "File", f"{finding.file_path}:{finding.line}")
    _set_col(cv, col_map, "End Location", f"{loc.get('end_line', '')}:{loc.get('end_column', '')}")
    _set_col(cv, col_map, "Repo", finding.repo)
    _set_dropdown_col(cv, col_map, "Categories", raw.get("categories"))
    _set_col(cv, col_map, "CWE", _join_list(rule.get("cwe_names")))
    _set_dropdown_col(cv, col_map, "OWASP", rule.get("owasp_names"))
    _set_dropdown_col(cv, col_map, "Vuln Classes", rule.get("vulnerability_classes"))
    _set_col(cv, col_map, "Message", _truncate(_safe_get(raw, "rule_message")))
    _set_status_col(cv, col_map, "AI Verdict", _snake_to_title(_safe_get(assistant, "autotriage", "verdict")) or "Not analyzed")
    _set_col(cv, col_map, "AI Reason", _truncate(_safe_get(assistant, "autotriage", "reason")))
    _set_col(cv, col_map, "AI Guidance", _truncate(_safe_get(assistant, "guidance", "summary")))
    autofix = _safe_get(assistant, "autofix", "fix_code")
    _set_status_col(cv, col_map, "Has Autofix", "Yes" if autofix else "No")
    comp_tag = _safe_get(assistant, "component", "tag")
    comp_risk = _safe_get(assistant, "component", "risk")
    comp_label = f"{comp_tag} ({comp_risk})" if comp_tag else None
    _set_dropdown_col(cv, col_map, "Component", [comp_label] if comp_label else None)
    _set_link_col(cv, col_map, "Code URL", _safe_get(raw, "line_of_code_url"))
    _set_status_col(cv, col_map, "Sourcing Policy", _safe_get(raw, "sourcing_policy", "name"))
    _set_col(cv, col_map, "External Ticket", _safe_get(raw, "external_ticket"))
    _set_col(cv, col_map, "Rule Explanation", _truncate(_safe_get(assistant, "rule_explanation", "summary")))
    # Semgrep URL is injected by run() which has access to the deployment slug

    return item_name, cv


# ---------------------------------------------------------------------------
# SCA mapper
# ---------------------------------------------------------------------------

def sca_finding_to_item(finding: Finding, col_map: dict[str, str]) -> tuple[str, dict]:
    raw = finding.raw
    dep = raw.get("found_dependency") or {}
    epss = raw.get("epss_score") or {}

    rule_obj = raw.get("rule") or {}
    dep_name = _safe_get(dep, "package")
    vuln_classes = rule_obj.get("vulnerability_classes") or []
    vuln_class = vuln_classes[0] if vuln_classes else ""
    sca_title = f"{dep_name}: {vuln_class}" if vuln_class else dep_name
    item_name = f"{sca_title} - {finding.repo} - {finding.file_path}:{finding.line}"
    cv: dict = {}

    _set_col(cv, col_map, "Finding ID", finding.id)
    _set_status_col(cv, col_map, "Severity", _SEVERITY_LABELS.get(finding.severity, finding.severity.capitalize()))
    _set_status_col(cv, col_map, "Confidence", _safe_get(raw, "confidence").capitalize())
    _set_col(cv, col_map, "Rule", finding.rule_name)
    _set_status_col(cv, col_map, "Triage State", _snake_to_title(_safe_get(raw, "triage_state")))
    _set_col(cv, col_map, "File", f"{finding.file_path}:{finding.line}")
    _set_col(cv, col_map, "Repo", finding.repo)
    _set_col(cv, col_map, "CVE", _safe_get(raw, "vulnerability_identifier"))
    _set_status_col(cv, col_map, "Reachability", _safe_get(raw, "reachability").capitalize())
    _set_col(cv, col_map, "Reachable Condition", _truncate(_safe_get(raw, "reachable_condition")))
    _set_col(cv, col_map, "EPSS Score", str(epss.get("score", "")) if epss.get("score") is not None else "")
    _set_col(cv, col_map, "EPSS Percentile", str(epss.get("percentile", "")) if epss.get("percentile") is not None else "")
    _set_col(cv, col_map, "Package", _safe_get(dep, "package"))
    _set_col(cv, col_map, "Version", _safe_get(dep, "version"))
    _set_status_col(cv, col_map, "Ecosystem", _safe_get(dep, "ecosystem"))
    _set_status_col(cv, col_map, "Transitivity", _safe_get(dep, "transitivity").capitalize())
    fix_recs = raw.get("fix_recommendations") or []
    _set_col(cv, col_map, "Fix Recommendation", ", ".join(f"{r['package']}@{r['version']}" for r in fix_recs if isinstance(r, dict)))
    _set_status_col(cv, col_map, "Is Malicious", "Yes" if raw.get("is_malicious") else "No")
    _set_col(cv, col_map, "Lockfile URL", _safe_get(dep, "lockfile_line_url"))
    _set_col(cv, col_map, "Message", _truncate(_safe_get(raw, "rule_message")))
    _set_dropdown_col(cv, col_map, "Categories", raw.get("categories"))
    _set_link_col(cv, col_map, "Code URL", _safe_get(raw, "line_of_code_url"))
    # Semgrep URL is injected by run() which has access to the deployment slug

    return item_name, cv


# ---------------------------------------------------------------------------
# Secrets mapper
# ---------------------------------------------------------------------------

def secrets_finding_to_item(finding: Finding, col_map: dict[str, str]) -> tuple[str, dict]:
    raw = finding.raw
    secrets_attrs = raw.get("secretsAttributes") or {}

    short_rule = finding.rule_name.split(".")[-1] if finding.rule_name else ""
    item_name = f"{short_rule} - {finding.repo} - {finding.file_path}:{finding.line}"
    cv: dict = {}

    _set_col(cv, col_map, "Finding ID", finding.id)
    _set_status_col(cv, col_map, "Severity", _SEVERITY_LABELS.get(finding.severity, finding.severity.capitalize()))
    _set_col(cv, col_map, "Rule", finding.rule_name)
    triage_raw = _safe_get(raw, "triageState")
    if triage_raw.startswith("FINDING_TRIAGE_STATE_"):
        triage_raw = triage_raw[len("FINDING_TRIAGE_STATE_"):]
    _set_status_col(cv, col_map, "Triage State", triage_raw.replace("_", " ").title())
    raw_val_state = secrets_attrs.get("validationState", "")
    _set_status_col(cv, col_map, "Validation State", _VALIDATION_STATE_LABELS.get(raw_val_state, raw_val_state))
    _set_col(cv, col_map, "File", f"{finding.file_path}:{finding.line}")
    _set_col(cv, col_map, "Repo", finding.repo)
    raw_conf = (_safe_get(raw, "confidence") or "").upper()
    if raw_conf.startswith("CONFIDENCE_"):
        raw_conf = raw_conf[len("CONFIDENCE_"):]
    _set_status_col(cv, col_map, "Confidence", raw_conf.capitalize())
    _set_dropdown_col(cv, col_map, "Secret Type", [secrets_attrs.get("secretType")] if secrets_attrs.get("secretType") else None)
    _set_link_col(cv, col_map, "Code URL", _safe_get(raw, "lineOfCodeUrl"))
    _set_col(cv, col_map, "Message", _truncate(_safe_get(raw, "message")))
    _set_col(cv, col_map, "CWE", _join_list(raw.get("ruleCweNames")))
    _set_dropdown_col(cv, col_map, "OWASP", raw.get("ruleOwaspNames"))

    return item_name, cv


# ---------------------------------------------------------------------------
# Update body formatters (posted to monday.com Updates feed after item creation)
# ---------------------------------------------------------------------------

def format_update_body_sast(finding: Finding) -> str:
    """HTML update body for a SAST finding — posted to the monday.com Updates feed."""
    raw = finding.raw
    rule = raw.get("rule") or {}
    assistant = raw.get("assistant") or {}

    sections = []

    # --- Header ---
    sections.append(
        f"<b>[{finding.severity}]</b> {finding.rule_name} — "
        f"{finding.file_path}:{finding.line} ({finding.repo})"
    )

    # --- Dynamically generated finding description (instance-specific narrative) ---
    explanation = _safe_get(assistant, "rule_explanation", "explanation")
    if explanation:
        sections.append(f"<b>Finding Description</b><br>{explanation}")

    # --- AI triage + taxonomy ---
    comp_tag = _safe_get(assistant, "component", "tag")
    comp_risk = _safe_get(assistant, "component", "risk")
    comp_str = f"{comp_tag} (risk: {comp_risk})" if comp_tag else ""
    meta = [
        _fmt_field("AI Verdict", _snake_to_title(_safe_get(assistant, "autotriage", "verdict")) or "Not analyzed"),
        _fmt_field("AI Reason", _safe_get(assistant, "autotriage", "reason")),
        _fmt_field("CWE", _join_list(rule.get("cwe_names"))),
        _fmt_field("OWASP", _join_list(rule.get("owasp_names"))),
        _fmt_field("Vulnerability Classes", _join_list(rule.get("vulnerability_classes"))),
        _fmt_field("Component", comp_str),
        _fmt_field("Triage State", _snake_to_title(_safe_get(raw, "triage_state"))),
        _fmt_field("Confidence", _safe_get(raw, "confidence")),
        _fmt_field("Categories", _join_list(raw.get("categories"))),
        _fmt_field("Sourcing Policy", _safe_get(raw, "sourcing_policy", "name")),
    ]
    meta_block = "<br>".join(f for f in meta if f)
    if meta_block:
        sections.append(meta_block)

    # --- Remediation ---
    guidance_summary = _safe_get(assistant, "guidance", "summary")
    guidance_instructions = _safe_get(assistant, "guidance", "instructions")
    fix_code = _safe_get(assistant, "autofix", "fix_code")
    if guidance_summary or guidance_instructions or fix_code:
        remediation = ["<b>Remediation</b>"]
        if guidance_summary:
            remediation.append(_fmt_field("Summary", guidance_summary))
        if guidance_instructions:
            remediation.append(f"<b>Instructions:</b><br>{guidance_instructions}")
        if fix_code:
            remediation.append(f"<b>Suggested Fix:</b><br><pre>{fix_code}</pre>")
        sections.append("<br>".join(remediation))

    return "<br><br>".join(s for s in sections if s)


def format_update_body_sca(finding: Finding) -> str:
    """HTML update body for an SCA finding — posted to the monday.com Updates feed."""
    raw = finding.raw
    dep = raw.get("found_dependency") or {}
    epss = raw.get("epss_score") or {}

    # --- Header ---
    pkg = _safe_get(dep, "package")
    ver = _safe_get(dep, "version")
    eco = _safe_get(dep, "ecosystem")
    cve = _safe_get(raw, "vulnerability_identifier")
    pkg_str = f"{pkg}@{ver} ({eco})" if pkg else ""
    header_parts = [f"<b>[{finding.severity}]</b>", cve, pkg_str, f"({finding.repo})"]
    sections = [" — ".join(p for p in header_parts if p)]

    # --- Details ---
    fix_recs = raw.get("fix_recommendations") or []
    fix_str = ", ".join(
        f"{r['package']}@{r['version']}" for r in fix_recs if isinstance(r, dict)
    )
    epss_score = epss.get("score")
    epss_pct = epss.get("percentile")
    epss_str = (
        f"{epss_score} (percentile: {epss_pct})"
        if epss_score is not None and epss_pct is not None
        else str(epss_score) if epss_score is not None else ""
    )
    fields = [
        _fmt_field("Reachability", _safe_get(raw, "reachability").capitalize()),
        _fmt_field("Reachable Condition", _safe_get(raw, "reachable_condition")),
        _fmt_field("EPSS Score", epss_str),
        _fmt_field("Package", pkg),
        _fmt_field("Version", ver),
        _fmt_field("Ecosystem", eco),
        _fmt_field("Transitivity", _safe_get(dep, "transitivity").capitalize()),
        _fmt_field("Fix Recommendation", fix_str),
        _fmt_field("Is Malicious", "Yes" if raw.get("is_malicious") else "No"),
        _fmt_field("Lockfile URL", _safe_get(dep, "lockfile_line_url")),
        _fmt_field("Triage State", _snake_to_title(_safe_get(raw, "triage_state"))),
        _fmt_field("Confidence", _safe_get(raw, "confidence")),
        _fmt_field("Categories", _join_list(raw.get("categories"))),
    ]
    detail_block = "<br>".join(f for f in fields if f)
    if detail_block:
        sections.append(detail_block)

    return "<br><br>".join(s for s in sections if s)


def format_update_body_secrets(finding: Finding) -> str:
    """HTML update body for a Secrets finding — posted to the monday.com Updates feed."""
    raw = finding.raw
    secrets_attrs = raw.get("secretsAttributes") or {}

    # --- Header ---
    sections = [
        f"<b>[{finding.severity}]</b> {finding.rule_name} — "
        f"{finding.file_path}:{finding.line} ({finding.repo})"
    ]

    # --- Details ---
    raw_vs = secrets_attrs.get("validationState", "")
    raw_conf = (_safe_get(raw, "confidence") or "").upper()
    if raw_conf.startswith("CONFIDENCE_"):
        raw_conf = raw_conf[len("CONFIDENCE_"):]
    triage_raw = _safe_get(raw, "triageState")
    if triage_raw.startswith("FINDING_TRIAGE_STATE_"):
        triage_raw = triage_raw[len("FINDING_TRIAGE_STATE_"):]
    fields = [
        _fmt_field("Validation State", _VALIDATION_STATE_LABELS.get(raw_vs, raw_vs)),
        _fmt_field("Confidence", raw_conf.capitalize()),
        _fmt_field("Secret Type", secrets_attrs.get("secretType", "")),
        _fmt_field("Triage State", triage_raw.replace("_", " ").title()),
        _fmt_field("CWE", _join_list(raw.get("ruleCweNames"))),
        _fmt_field("OWASP", _join_list(raw.get("ruleOwaspNames"))),
        _fmt_field("Message", _truncate(_safe_get(raw, "message"))),
        _fmt_field("Code URL", _safe_get(raw, "lineOfCodeUrl")),
    ]
    detail_block = "<br>".join(f for f in fields if f)
    if detail_block:
        sections.append(detail_block)

    return "<br><br>".join(s for s in sections if s)


# ---------------------------------------------------------------------------
# Group-aware update body formatters
# ---------------------------------------------------------------------------

def format_update_body_sca_group(group: FindingGroup, slug: str) -> str:
    rep = group.representative
    dep = rep.raw.get("found_dependency") or {}
    pkg = _safe_get(dep, "package")
    ver = _safe_get(dep, "version")
    eco = _safe_get(dep, "ecosystem")
    pkg_str = f"{pkg}@{ver} ({eco})" if pkg else ""
    n = len(group.members)
    header = f"<b>[{rep.severity}]</b> {pkg_str} — {rep.repo} — {n} CVE{'s' if n > 1 else ''}"
    sections = [header]

    for f in group.members:
        raw = f.raw
        fdep = raw.get("found_dependency") or {}
        epss = raw.get("epss_score") or {}
        cve = _safe_get(raw, "vulnerability_identifier")
        sev_label = _SEVERITY_LABELS.get(f.severity, f.severity.capitalize())
        entry_header = f"<b>{cve}</b> ({sev_label})" if cve else f"<b>{f.rule_name}</b> ({sev_label})"
        fields = [
            entry_header,
            _fmt_field("Reachability", _safe_get(raw, "reachability").capitalize()),
            _fmt_field("Reachable Condition", _safe_get(raw, "reachable_condition")),
        ]
        epss_score = epss.get("score")
        epss_pct = epss.get("percentile")
        if epss_score is not None:
            epss_str = f"{epss_score} (percentile: {epss_pct})" if epss_pct is not None else str(epss_score)
            fields.append(_fmt_field("EPSS", epss_str))
        fix_recs = raw.get("fix_recommendations") or []
        fix_str = ", ".join(f"{r['package']}@{r['version']}" for r in fix_recs if isinstance(r, dict))
        fields.append(_fmt_field("Fix", fix_str))
        fields.append(_fmt_field("Semgrep URL", _semgrep_finding_url(slug, f)))
        sections.append("<br>".join(x for x in fields if x))

    common = [
        _fmt_field("Package", f"{pkg}@{ver}" if pkg else ""),
        _fmt_field("Ecosystem", eco),
        _fmt_field("Transitivity", _safe_get(dep, "transitivity").capitalize()),
        _fmt_field("Is Malicious", "Yes" if rep.raw.get("is_malicious") else "No"),
        _fmt_field("Lockfile URL", _safe_get(dep, "lockfile_line_url")),
        _fmt_field("Triage State", _snake_to_title(_safe_get(rep.raw, "triage_state"))),
    ]
    common_block = "<br>".join(x for x in common if x)
    if common_block:
        sections.append(common_block)

    return "<br><br>".join(sections)


def format_update_body_sast_group(group: FindingGroup, slug: str) -> str:
    rep = group.representative
    n = len(group.members)
    header = (
        f"<b>[{rep.severity}]</b> {rep.repo} — "
        f"{rep.file_path}:{rep.line} — {n} finding{'s' if n > 1 else ''}"
    )
    sections = [header]

    for f in group.members:
        raw = f.raw
        rule = raw.get("rule") or {}
        assistant = raw.get("assistant") or {}
        sev_label = _SEVERITY_LABELS.get(f.severity, f.severity.capitalize())
        entry_header = f"<b>{f.rule_name}</b> ({sev_label})"
        fields = [
            entry_header,
            _fmt_field("AI Verdict", _snake_to_title(_safe_get(assistant, "autotriage", "verdict")) or "Not analyzed"),
            _fmt_field("AI Reason", _safe_get(assistant, "autotriage", "reason")),
            _fmt_field("CWE", _join_list(rule.get("cwe_names"))),
            _fmt_field("OWASP", _join_list(rule.get("owasp_names"))),
            _fmt_field("Vuln Classes", _join_list(rule.get("vulnerability_classes"))),
            _fmt_field("Component", _safe_get(assistant, "component", "tag")),
        ]
        explanation = _safe_get(assistant, "rule_explanation", "explanation")
        if explanation:
            fields.append(f"<b>Description:</b> {_truncate(explanation, 300)}")
        guidance = _safe_get(assistant, "guidance", "summary")
        if guidance:
            fields.append(_fmt_field("Remediation", guidance))
        fix_code = _safe_get(assistant, "autofix", "fix_code")
        if fix_code:
            fields.append(f"<b>Fix:</b><br><pre>{fix_code}</pre>")
        fields.append(_fmt_field("Semgrep URL", _semgrep_finding_url(slug, f)))
        sections.append("<br>".join(x for x in fields if x))

    common = [
        _fmt_field("File", f"{rep.file_path}:{rep.line}"),
        _fmt_field("Repo", rep.repo),
        _fmt_field("Triage State", _snake_to_title(_safe_get(rep.raw, "triage_state"))),
        _fmt_field("Confidence", _safe_get(rep.raw, "confidence")),
    ]
    common_block = "<br>".join(x for x in common if x)
    if common_block:
        sections.append(common_block)

    return "<br><br>".join(sections)


def format_update_body_secrets_group(group: FindingGroup, slug: str) -> str:
    rep = group.representative
    n = len(group.members)
    header = (
        f"<b>[{rep.severity}]</b> {rep.repo} — "
        f"{rep.file_path}:{rep.line} — {n} secret{'s' if n > 1 else ''}"
    )
    sections = [header]

    for f in group.members:
        raw = f.raw
        secrets_attrs = raw.get("secretsAttributes") or {}
        sev_label = _SEVERITY_LABELS.get(f.severity, f.severity.capitalize())
        short_rule = f.rule_name.split(".")[-1] if f.rule_name else ""
        entry_header = f"<b>{short_rule}</b> ({sev_label})"
        raw_vs = secrets_attrs.get("validationState", "")
        raw_conf = (_safe_get(raw, "confidence") or "").upper()
        if raw_conf.startswith("CONFIDENCE_"):
            raw_conf = raw_conf[len("CONFIDENCE_"):]
        fields = [
            entry_header,
            _fmt_field("Validation State", _VALIDATION_STATE_LABELS.get(raw_vs, raw_vs)),
            _fmt_field("Confidence", raw_conf.capitalize()),
            _fmt_field("Secret Type", secrets_attrs.get("secretType", "")),
            _fmt_field("Message", _truncate(_safe_get(raw, "message"))),
            _fmt_field("Semgrep URL", _semgrep_finding_url(slug, f)),
        ]
        sections.append("<br>".join(x for x in fields if x))

    triage_raw = _safe_get(rep.raw, "triageState")
    if triage_raw.startswith("FINDING_TRIAGE_STATE_"):
        triage_raw = triage_raw[len("FINDING_TRIAGE_STATE_"):]
    common = [
        _fmt_field("File", f"{rep.file_path}:{rep.line}"),
        _fmt_field("Repo", rep.repo),
        _fmt_field("Triage State", triage_raw.replace("_", " ").title()),
        _fmt_field("CWE", _join_list(rep.raw.get("ruleCweNames"))),
        _fmt_field("OWASP", _join_list(rep.raw.get("ruleOwaspNames"))),
    ]
    common_block = "<br>".join(x for x in common if x)
    if common_block:
        sections.append(common_block)

    return "<br><br>".join(sections)


# ---------------------------------------------------------------------------
# Board routing config
# ---------------------------------------------------------------------------

BOARD_CONFIG = {
    "SAST": {
        "env_var": "MONDAY_BOARD_ID_SAST",
        "mapper": sast_finding_to_item,
        "body_formatter": format_update_body_sast,
    },
    "SCA": {
        "env_var": "MONDAY_BOARD_ID_SCA",
        "mapper": sca_finding_to_item,
        "body_formatter": format_update_body_sca,
    },
    "Secrets": {
        "env_var": "MONDAY_BOARD_ID_SECRETS",
        "mapper": secrets_finding_to_item,
        "body_formatter": format_update_body_secrets,
    },
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _filter_log(board_type: str, fetched: int, kept: int, filters: dict) -> str:
    block = filters.get(board_type, {})
    if not block:
        return f"{board_type.upper()}: {fetched} fetched (no filter)"
    parts = ", ".join(f"{k}=[{','.join(v)}]" for k, v in block.items())
    msg = f"{board_type.upper()}: {fetched} fetched (filters: {parts})"
    if kept != fetched:
        msg += f" → {kept} after client-side filter"
    return msg


def run(
    state_path: Path = DEFAULT_STATE_FILE,
    limit: int | None = None,
    filters_path: Path | None = DEFAULT_FILTERS_FILE,
    types: set[str] | None = None,
    set_triage_reviewing: bool = False,
    dry_run: bool = False,
    no_dedup: bool = False,
) -> None:
    # types=None means all; validate against known board keys
    active_types = types if types is not None else set(BOARD_CONFIG)
    cfg = load_config()
    state = load_state(state_path)
    fixed_synced_path = state_path.parent / "fixed_state.json"
    fixed_state = load_fixed_state(fixed_synced_path)
    fixed_synced_ids: set[str] = synced_secrets_ids(fixed_state)

    today = str(date.today())
    state.setdefault("daily", {})
    state["daily"].setdefault(today, 0)

    # --- Load filters ---
    filters = load_filters(filters_path)

    # --- Build clients ---
    slug = cfg["SEMGREP_DEPLOYMENT_SLUG"]
    semgrep = SemgrepClient(
        token=cfg["SEMGREP_APP_TOKEN"],
        deployment_slug=slug,
    )

    boards: dict[str, dict] = {}
    for board_type, bc in BOARD_CONFIG.items():
        if board_type not in active_types:
            continue
        board_id = int(cfg[bc["env_var"]])
        client = MondayClient(token=cfg["MONDAY_API_TOKEN"], board_id=board_id)
        boards[board_type] = {
            "client": client,
            "board_id": board_id,
            "mapper": bc["mapper"],
            "body_formatter": bc["body_formatter"],
        }

    # --- monday.com account slug (for triage note URLs) ---
    account_slug = ""
    if set_triage_reviewing and boards:
        first_client = next(iter(boards.values()))["client"]
        account_slug = first_client.get_account_slug()

    # --- Fetch findings ---
    fetch_kwargs = {} if limit is None else {"max_findings": limit}
    dedup_params = {} if no_dedup else {"dedup": "true"}
    sast_raw: list[Finding] = []
    sca_raw: list[Finding] = []
    secrets_raw: list[Finding] = []
    try:
        if "SAST" in active_types:
            print("\n=== Fetching SAST findings from Semgrep ===")
            sast_raw = semgrep.fetch_findings("sast", extra_params={**to_query_params("sast", filters), **dedup_params}, **fetch_kwargs)
        if "SCA" in active_types:
            print("\n=== Fetching SCA findings from Semgrep ===")
            sca_raw = semgrep.fetch_findings("sca", extra_params={**to_query_params("sca", filters), **dedup_params}, **fetch_kwargs)
            if has_malicious_filter(filters):
                print("\n=== Fetching SCA malicious findings (second pass) ===")
                malicious_raw = semgrep.fetch_findings("sca", extra_params={**to_malicious_query_params(), **dedup_params}, **fetch_kwargs)
                seen_ids = {f.id for f in sca_raw}
                sca_raw.extend(f for f in malicious_raw if f.id not in seen_ids)
                print(f"  SCA malicious second-pass: {len(malicious_raw)} fetched, {len(sca_raw) - len(seen_ids)} new")
        if "Secrets" in active_types:
            print("\n=== Fetching open Secrets findings from Semgrep ===")
            secrets_raw = semgrep.fetch_secrets(filter_params=to_secrets_filter_body(filters), **fetch_kwargs)
            print("\n=== Fetching fixed Secrets findings from Semgrep ===")
            fixed_filter = {k: v for k, v in to_secrets_filter_body(filters).items() if k != "tab"}
            fixed_filter["aggregateIssueStates"] = ["AGGREGATE_ISSUE_STATE_FIXED"]
            fixed_raw = semgrep.fetch_secrets(filter_params=fixed_filter, **{k: v for k, v in fetch_kwargs.items() if k != "max_findings"})
            seen_ids = {f.id for f in secrets_raw}
            new_fixed = [f for f in fixed_raw if f.id not in seen_ids and "monday.com" not in (f.raw.get("note") or "") and f.id not in fixed_synced_ids]
            secrets_raw.extend(new_fixed)
            skipped_note = sum(1 for f in fixed_raw if "monday.com" in (f.raw.get("note") or ""))
            skipped_state = sum(1 for f in fixed_raw if f.id in fixed_synced_ids and "monday.com" not in (f.raw.get("note") or ""))
            print(f"  Secrets fixed second-pass: {len(fixed_raw)} fetched, {skipped_note} skipped (monday note), {skipped_state} skipped (fixed_state.json), {len(new_fixed)} new")
    except SemgrepAPIError as exc:
        print(f"Semgrep API error: {exc}")
        sys.exit(1)

    print("\n=== Summary ===")
    ignored_repos = get_ignored_repos(filters)
    sast = [f for f in filter_findings(sast_raw, "sast", filters) if f.repo not in ignored_repos]
    sca = [f for f in filter_findings(sca_raw, "sca", filters) if f.repo not in ignored_repos]
    secrets = [f for f in secrets_raw if f.repo not in ignored_repos]

    findings_by_type = {"SAST": sast, "SCA": sca, "Secrets": secrets}
    if "SAST" in active_types:
        print(f"  {_filter_log('sast', len(sast_raw), len(sast), filters)}")
    if "SCA" in active_types:
        print(f"  {_filter_log('sca', len(sca_raw), len(sca), filters)}")
    if "Secrets" in active_types:
        print(f"  {_filter_log('secrets', len(secrets_raw), len(secrets), filters)}")
    total = sum(len(v) for v in findings_by_type.values())
    print(f"  Total: {total}")

    if dry_run:
        print("\n[DRY RUN] New finding IDs by type (would be synced):")
        total_new = 0
        for board_type in ("SAST", "SCA", "Secrets"):
            type_findings = findings_by_type.get(board_type, [])
            already_synced = synced_finding_ids(state, board_type)
            new_findings = [f for f in type_findings if f.id not in already_synced]
            deduped = len(type_findings) - len(new_findings)
            total_new += len(new_findings)
            if not type_findings:
                continue
            print(f"  {board_type}: {len(new_findings)} new ({deduped} already in state.json)")
            for fid in (f.id for f in new_findings):
                print(f"    {fid}")
        print(f"\nTotal new: {total_new}. No state changes, no monday items created, no Semgrep triage updates.")
        return

    # --- Fetch column maps (one per board, only if that board has new findings) ---
    col_maps: dict[str, dict] = {}

    # --- Project tags cache (repo → list of tags) ---
    project_tags_cache: dict[str, list[str]] = {}

    def _get_project_tags(repo: str) -> list[str]:
        if repo not in project_tags_cache:
            project = semgrep.fetch_project(repo)
            project_tags_cache[repo] = project.get("tags", []) if project else []
        return project_tags_cache[repo]

    # --- Route and create ---
    created = 0
    total_new_findings = 0

    _MERGED_FIELDS_FN = {
        "SCA": _apply_sca_merged_fields,
        "SAST": _apply_sast_merged_fields,
        "Secrets": _apply_secrets_merged_fields,
    }
    _GROUP_FORMATTER = {
        "SCA": format_update_body_sca_group,
        "SAST": format_update_body_sast_group,
        "Secrets": format_update_body_secrets_group,
    }

    print("\n=== Creating monday.com items ===")
    for board_type in ("SAST", "SCA", "Secrets"):
        type_findings = findings_by_type.get(board_type, [])
        already_synced = synced_finding_ids(state, board_type)
        new = [f for f in type_findings if f.id not in already_synced]
        total_new_findings += len(new)
        if not new:
            continue

        board = boards[board_type]
        if board_type not in col_maps:
            col_maps[board_type] = board["client"].get_column_map()
        col_map = col_maps[board_type]
        mapper = board["mapper"]

        groups = group_findings(new, board_type)
        grouped_count = len(new) - len(groups)
        if grouped_count > 0:
            print(f"  [{board_type}] {len(new)} findings → {len(groups)} items ({grouped_count} grouped)")

        for group in groups:
            finding = group.representative
            item_name, col_vals = mapper(finding, col_map)
            _MERGED_FIELDS_FN[board_type](col_vals, col_map, group)
            _set_link_col(col_vals, col_map, "Semgrep URL", _semgrep_finding_url(slug, finding))
            _set_dropdown_col(col_vals, col_map, "Project Tags", _get_project_tags(finding.repo))
            try:
                monday_id, _ = board["client"].create_item(item_name, col_vals)
                state["monday_items_created"][board_type][monday_id] = {
                    "repo": finding.repo,
                    "finding_ids": [f.id for f in group.members],
                }
                if board_type == "Secrets":
                    for f in group.members:
                        if f.raw.get("aggregateState") == "AGGREGATE_ISSUE_STATE_FIXED":
                            fixed_synced_ids.add(f.id)
                state["daily"][today] += 1
                created += 1
                member_ids = ", ".join(f.id for f in group.members)
                print(f"  [{board_type}] {member_ids} → monday item {monday_id}")
                try:
                    if len(group.members) > 1:
                        body = _GROUP_FORMATTER[board_type](group, slug)
                    else:
                        body = board["body_formatter"](finding)
                    board["client"].create_update(monday_id, body)
                except Exception as exc:
                    print(f"  [{board_type}] Warning: update post failed for {monday_id}: {exc}")
                if set_triage_reviewing:
                    try:
                        item_url = _monday_item_url(account_slug, board["board_id"], monday_id)
                        note = f"Created monday item: {item_url}" if item_url else "Created monday item"
                        semgrep.triage_findings(
                            [f.id for f in group.members], "reviewing", note, board_type.lower(),
                        )
                    except Exception as exc:
                        print(f"  [{board_type}] Warning: triage failed for {monday_id}: {exc}")
            except Exception as exc:
                member_ids = ", ".join(f.id for f in group.members)
                print(f"  [{board_type}] Failed for {member_ids}: {exc}")

    save_state(state, state_path)
    fixed_state["SECRETS"] = sorted(fixed_synced_ids)
    save_fixed_state(fixed_state, fixed_synced_path)
    print(f"\nDone: {created} items created, {total_new_findings} new findings processed.")


# ---------------------------------------------------------------------------
# Mark fixed
# ---------------------------------------------------------------------------

def _project_primary_branch(project: dict | None) -> str:
    """Return the project's primary branch, falling back to default_branch."""
    if not project:
        return ""
    return project.get("primary_branch") or project.get("default_branch") or ""


def _backfill_repos_from_monday(
    state: dict, board_type: str, client: MondayClient,
) -> int:
    """Populate empty "repo" fields on v5 state entries via monday's Repo column.

    Returns the count of items successfully backfilled.
    """
    entries = state["monday_items_created"].get(board_type, {})
    need_repo = [iid for iid, e in entries.items() if not item_repo(e)]
    if not need_repo:
        return 0
    col_map = client.get_column_map()
    repo_col_id = col_map.get("Repo")
    if not repo_col_id:
        print(f"  [{board_type}] backfill: 'Repo' column not found — leaving {len(need_repo)} entries without repo")
        return 0
    try:
        items = client.get_items_by_ids(need_repo, [repo_col_id])
    except Exception as exc:
        print(f"  [{board_type}] backfill: failed to fetch monday items: {exc}")
        return 0
    filled = 0
    for it in items:
        mid = str(it["id"])
        repo_val = ""
        for cv in it.get("column_values") or []:
            if cv.get("id") == repo_col_id:
                repo_val = (cv.get("text") or "").strip()
                break
        if repo_val and mid in entries:
            entries[mid]["repo"] = repo_val
            filled += 1
    return filled


def mark_fixed(
    state_path: Path = DEFAULT_STATE_FILE,
    filters_path: Path | None = DEFAULT_FILTERS_FILE,
    types: set[str] | None = None,
    dry_run: bool = False,
    fixed_since: str | None = None,
) -> None:
    """Reconcile monday items with fixed / not-scanned state in Semgrep (v2 API).

    Approach:
      1. Bulk-fetch `/projects` once. Semgrep's list-projects endpoint
         excludes archived repos, so absence-from-this-list is our
         signal for "not scanned anymore."
      2. Per board_type (SAST/SCA), call the v2 `/issues` endpoint with
         `aggregateIssueStates=[AGGREGATE_ISSUE_STATE_FIXED]` and
         `onPrimaryBranch=true`. Optionally add
         `timeFilter=TIME_FILTER_FIXED_AT` + `since=<fixed_since>` to
         narrow to recent transitions.
      3. Intersect the returned finding IDs with each state entry's
         `finding_ids`; on match, set "Triage State" -> "Fixed" and
         migrate the entry to `fixed_state.json`.
      4. For any state.json repo absent from the bulk projects list,
         mark all its items "Not scanned by Semgrep" and migrate to
         `not_scanned_state.json`.

    Backfill: pre-v5 entries with `repo=""` are backfilled once via
    monday's "Repo" column at the start of this pass.

    Only SAST and SCA. Secrets has its own fixed-pass in run().
    """
    print("\n\n############################################")
    print("### Reconciling fixed / not-scanned items ###")
    print("############################################")

    supported = {"SAST", "SCA"}
    active_types = (types & supported) if types is not None else supported
    if not active_types:
        print("No supported types selected (SAST, SCA). Nothing to do.")
        return

    cfg = load_config()
    state = load_state(state_path)
    fixed_path = state_path.parent / "fixed_state.json"
    not_scanned_path = state_path.parent / "not_scanned_state.json"
    fixed_state = load_fixed_state(fixed_path)
    not_scanned_state = load_not_scanned_state(not_scanned_path)

    filters = load_filters(filters_path)
    ignored_repos = get_ignored_repos(filters)

    semgrep = SemgrepClient(
        token=cfg["SEMGREP_APP_TOKEN"],
        deployment_slug=cfg["SEMGREP_DEPLOYMENT_SLUG"],
    )

    boards: dict[str, dict] = {}
    for board_type in active_types:
        bc = BOARD_CONFIG[board_type]
        board_id = int(cfg[bc["env_var"]])
        boards[board_type] = {
            "client": MondayClient(token=cfg["MONDAY_API_TOKEN"], board_id=board_id),
            "board_id": board_id,
        }

    # --- Backfill repo for any pre-v5 state entries that lack it ---
    need_backfill = any(
        not item_repo(e)
        for bt in active_types
        for e in state["monday_items_created"].get(bt, {}).values()
    )
    if need_backfill:
        print("\n=== Backfilling repo from monday.com (pre-v5 state entries) ===")
        for board_type in sorted(active_types):
            filled = _backfill_repos_from_monday(state, board_type, boards[board_type]["client"])
            if filled:
                print(f"  [{board_type}] backfilled repo for {filled} state entries")
        if not dry_run:
            save_state(state, state_path)

    # --- Bulk-fetch projects once. Excludes archived repos server-side. ---
    print("\n=== Fetching active projects from Semgrep ===")
    try:
        active_projects = semgrep.fetch_projects()
    except SemgrepAPIError as exc:
        print(f"Semgrep API error fetching /projects: {exc}")
        return
    active_repo_names: set[str] = {p["name"] for p in active_projects if p.get("name")}
    print(f"  {len(active_repo_names)} active projects returned by Semgrep")

    total_marked_fixed = 0
    total_marked_not_scanned = 0
    stats: dict[str, dict[str, int]] = {}
    not_scanned_repos_union: set[str] = set()

    for board_type in sorted(active_types):
        issue_type = board_type.lower()
        entries = state["monday_items_created"].get(board_type, {})
        if not entries:
            print(f"\n=== Reconciling {board_type} items: nothing tracked in state.json ===")
            continue
        print(f"\n=== Reconciling {board_type} items ({len(entries)} tracked) ===")
        s = stats[board_type] = {
            "tracked": len(entries),
            "no_repo_items": 0,
            "repos_tracked": 0,
            "repos_not_scanned": 0,
            "items_in_not_scanned_repos": 0,
            "fixed_findings_seen": 0,
            "items_marked_fixed": 0,
            "items_marked_not_scanned": 0,
        }

        client: MondayClient = boards[board_type]["client"]
        col_map = client.get_column_map()
        triage_col_id = col_map.get("Triage State")
        if not triage_col_id:
            print(f"  Warning: 'Triage State' column not found on {board_type} board. Skipping.")
            continue

        # Group entries by repo. Items lacking repo (backfill miss) are skipped.
        by_repo: dict[str, dict[str, dict]] = {}
        no_repo_items: list[str] = []
        for iid, entry in entries.items():
            repo = item_repo(entry)
            if not repo:
                no_repo_items.append(iid)
                continue
            if repo in ignored_repos:
                continue
            by_repo.setdefault(repo, {})[iid] = entry
        s["no_repo_items"] = len(no_repo_items)
        s["repos_tracked"] = len(by_repo)
        if no_repo_items:
            print(f"  Warning: {len(no_repo_items)} {board_type} items lack repo — skipping them")

        # --- Fetch fixed findings via v2 in one paginated stream ---
        print(f"\n=== Fetching fixed {board_type} findings from Semgrep (v2) ===")
        if fixed_since:
            print(f"  Filter: onPrimaryBranch=true, aggregateIssueStates=FIXED, since={fixed_since}")
        else:
            print(f"  Filter: onPrimaryBranch=true, aggregateIssueStates=FIXED (all time)")
        try:
            fixed = semgrep.fetch_fixed_issues_v2(issue_type=issue_type, since=fixed_since)
        except SemgrepAPIError as exc:
            print(f"  Semgrep API error: {exc}")
            continue
        s["fixed_findings_seen"] = len(fixed)
        print(f"  {len(fixed)} fixed findings on primary branches returned")
        fixed_ids = {f.id for f in fixed}

        # --- Case A: items in repos NOT in Semgrep's active-projects list ---
        not_scanned_this_type: set[str] = set()
        for repo in by_repo:
            if repo not in active_repo_names:
                not_scanned_this_type.add(repo)
        s["repos_not_scanned"] = len(not_scanned_this_type)
        s["items_in_not_scanned_repos"] = sum(len(by_repo[r]) for r in not_scanned_this_type)
        not_scanned_repos_union.update(not_scanned_this_type)

        if not_scanned_this_type:
            print(f"\n  {len(not_scanned_this_type)} tracked repos not in Semgrep's active projects list — marking their items 'Not scanned by Semgrep'")
            for repo in sorted(not_scanned_this_type):
                repo_items = by_repo[repo]
                print(f"    [{repo}] {len(repo_items)} items")
                for iid, entry in sorted(repo_items.items()):
                    if dry_run:
                        print(f"      [DRY RUN] {board_type} item {iid}: mark 'Not scanned by Semgrep' (findings: {item_finding_ids(entry)})")
                        s["items_marked_not_scanned"] += 1
                        total_marked_not_scanned += 1
                        continue
                    try:
                        client.change_column_values(iid, {triage_col_id: {"label": "Not scanned by Semgrep"}})
                        state["monday_items_created"][board_type].pop(iid, None)
                        not_scanned_state.setdefault(board_type, {})[iid] = entry
                        s["items_marked_not_scanned"] += 1
                        total_marked_not_scanned += 1
                        print(f"      [{board_type}] item {iid} → Not scanned by Semgrep")
                    except Exception as exc:
                        print(f"      [{board_type}] Failed to mark item {iid}: {exc}")

        # --- Case B: for active repos, mark items whose finding_ids match fixed_ids ---
        items_to_mark: list[tuple[str, str, dict]] = []  # (repo, iid, entry)
        for repo, repo_items in by_repo.items():
            if repo in not_scanned_this_type:
                continue
            for iid, entry in repo_items.items():
                my_fids = set(item_finding_ids(entry))
                if my_fids & fixed_ids:
                    items_to_mark.append((repo, iid, entry))

        if items_to_mark:
            print(f"\n  {len(items_to_mark)} {board_type} monday items to mark Fixed")
            for repo, iid, entry in sorted(items_to_mark):
                intersect = [fid for fid in item_finding_ids(entry) if fid in fixed_ids]
                if dry_run:
                    print(f"    [DRY RUN] {board_type} item {iid} ({repo}): findings {item_finding_ids(entry)} (fixed on main: {intersect})")
                    s["items_marked_fixed"] += 1
                    total_marked_fixed += 1
                    continue
                try:
                    client.change_column_values(iid, {triage_col_id: {"label": "Fixed"}})
                    state["monday_items_created"][board_type].pop(iid, None)
                    fixed_state.setdefault(board_type, {})[iid] = entry
                    s["items_marked_fixed"] += 1
                    total_marked_fixed += 1
                    print(f"    [{board_type}] item {iid} ({repo}) → Fixed (findings: {item_finding_ids(entry)})")
                except Exception as exc:
                    print(f"    [{board_type}] Failed to mark item {iid}: {exc}")

    # --- Summary ---
    print("\n=== Reconciliation summary ===")
    for board_type in sorted(stats):
        s = stats[board_type]
        prefix = "[DRY RUN] would " if dry_run else ""
        print(f"  {board_type}:")
        print(f"    Tracked items in state.json:                     {s['tracked']}")
        if s['no_repo_items']:
            print(f"    Items missing repo (skipped this run):           {s['no_repo_items']}")
        print(f"    Distinct tracked repos:                          {s['repos_tracked']}")
        print(f"    Fixed findings on primary branches (v2 fetch):   {s['fixed_findings_seen']}")
        print(f"    Repos not in active projects list:               {s['repos_not_scanned']} ({s['items_in_not_scanned_repos']} items)")
        print(f"    Items {prefix}marked Fixed:                        {s['items_marked_fixed']}")
        print(f"    Items {prefix}marked Not scanned by Semgrep:       {s['items_marked_not_scanned']}")
    if not_scanned_repos_union:
        print(f"\n  Not-scanned repos ({len(not_scanned_repos_union)}): {', '.join(sorted(not_scanned_repos_union))}")

    if dry_run:
        print(f"\n[DRY RUN] No monday items updated, no state files modified.")
        return

    save_state(state, state_path)
    save_fixed_state(fixed_state, fixed_path)
    save_not_scanned_state(not_scanned_state, not_scanned_path)
    print(f"\nDone: {total_marked_fixed} items marked Fixed, {total_marked_not_scanned} items marked Not scanned by Semgrep.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync Semgrep findings to monday.com")
    _VALID_TYPES = {"sast": "SAST", "sca": "SCA", "secrets": "Secrets"}
    parser.add_argument("--limit", type=int, default=None, metavar="N", help="Max findings per type")
    parser.add_argument("--filters", default=None, metavar="PATH", help="Path to filters YAML file (default: filters.yaml if it exists)")
    parser.add_argument("--no-filters", action="store_true", help="Bypass filtering even if filters.yaml exists")
    parser.add_argument("--type", default=None, metavar="TYPES",
                        help="Comma-separated list of types to sync: sast,sca,secrets (default: all)")
    parser.add_argument("--set-triage-reviewing", action="store_true",
                        help="Triage synced findings to 'reviewing' in Semgrep with a note linking to the monday item")
    parser.add_argument("--no-dedup", action="store_true",
                        help="Disable Semgrep server-side deduplication (omit dedup=true from API calls)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch findings and print IDs without creating monday items or updating state")
    parser.add_argument("--mark-fixed", action="store_true",
                        help="After the normal sync, reconcile existing monday items: mark items 'Fixed' when their finding is resolved on the repo's primary branch, and 'Not scanned by Semgrep' when the repo is no longer in Semgrep. SAST + SCA only.")
    parser.add_argument("--fixed-since-days", type=int, default=None, metavar="N",
                        help="With --mark-fixed: only consider findings fixed in the last N days (server-side filter via TIME_FILTER_FIXED_AT). Speeds up scheduled runs.")
    args = parser.parse_args()

    if args.type:
        raw_types = [t.strip().lower() for t in args.type.split(",")]
        unknown = [t for t in raw_types if t not in _VALID_TYPES]
        if unknown:
            parser.error(f"Unknown type(s): {', '.join(unknown)}. Valid: sast, sca, secrets")
        resolved_types = {_VALID_TYPES[t] for t in raw_types}
    else:
        resolved_types = None

    if args.no_filters:
        resolved_filters_path = None
    elif args.filters:
        resolved_filters_path = Path(args.filters)
    else:
        env_path = os.getenv("SEMGREP_FILTERS_FILE")
        resolved_filters_path = Path(env_path) if env_path else DEFAULT_FILTERS_FILE

    run(limit=args.limit, filters_path=resolved_filters_path, types=resolved_types,
        set_triage_reviewing=args.set_triage_reviewing, dry_run=args.dry_run,
        no_dedup=args.no_dedup)
    if args.mark_fixed:
        fixed_since_iso: str | None = None
        if args.fixed_since_days is not None:
            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(days=args.fixed_since_days)
            fixed_since_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        mark_fixed(filters_path=resolved_filters_path, types=resolved_types,
                   dry_run=args.dry_run, fixed_since=fixed_since_iso)
