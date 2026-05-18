"""Semgrep → monday.com sync script (three-board architecture).

Usage:
    python setup_boards.py             # one-time: create boards + columns
    cp .env.example .env               # fill in credentials + board IDs
    python sync.py                     # sync all findings
    python sync.py --limit 50          # sync up to 50 per type
    python sync.py --filters my.yaml              # apply custom filters file
    python sync.py --no-filters                   # skip filtering even if filters.yaml exists
    python sync.py --set-triage-reviewing         # triage synced findings to 'reviewing' in Semgrep

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

from filters import filter_findings, has_malicious_filter, load_filters, to_malicious_query_params, to_query_params, to_secrets_filter_body
from monday_client import MondayAPIError, MondayClient
from semgrep_client import Finding, SemgrepAPIError, SemgrepClient

DEFAULT_STATE_FILE = Path(__file__).parent / "state.json"
DEFAULT_FILTERS_FILE = Path(__file__).parent / "filters.yaml"
STATE_VERSION = 4


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
    verdict = _safe_get(raw, "assistant", "autotriage", "verdict")
    verdict_score = 2 if verdict == "true_positive" else (0 if verdict == "false_positive" else 1)
    return (sev, verdict_score, conf)


def _sca_group_key(finding: Finding) -> tuple:
    dep = finding.raw.get("found_dependency") or {}
    return (finding.repo, dep.get("package", ""), dep.get("version", ""))


def _sast_group_key(finding: Finding) -> tuple:
    loc = finding.raw.get("location") or {}
    end_loc = f"{loc.get('end_line', '')}:{loc.get('end_column', '')}"
    return (finding.repo, finding.file_path, end_loc)


def group_findings(findings: list[Finding], board_type: str) -> list[FindingGroup]:
    key_fn = _sca_group_key if board_type == "SCA" else _sast_group_key
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
    state["version"] = STATE_VERSION
    return state


def synced_finding_ids(state: dict, board_type: str) -> set[str]:
    ids: set[str] = set()
    for fids in state.get("monday_items_created", {}).get(board_type, {}).values():
        ids.update(fids)
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
) -> None:
    # types=None means all; validate against known board keys
    active_types = types if types is not None else set(BOARD_CONFIG)
    cfg = load_config()
    state = load_state(state_path)

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
    print("Fetching Semgrep findings…")
    fetch_kwargs = {} if limit is None else {"max_findings": limit}
    try:
        sast_raw = semgrep.fetch_findings("sast", extra_params={**to_query_params("sast", filters), "dedup": "true"}, **fetch_kwargs) if "SAST" in active_types else []
        sca_raw = semgrep.fetch_findings("sca", extra_params={**to_query_params("sca", filters), "dedup": "true"}, **fetch_kwargs) if "SCA" in active_types else []
        if "SCA" in active_types and has_malicious_filter(filters):
            malicious_raw = semgrep.fetch_findings("sca", extra_params={**to_malicious_query_params(), "dedup": "true"}, **fetch_kwargs)
            seen_ids = {f.id for f in sca_raw}
            sca_raw.extend(f for f in malicious_raw if f.id not in seen_ids)
            print(f"  SCA malicious second-pass: {len(malicious_raw)} fetched, {len(sca_raw) - len(seen_ids)} new")
        secrets_raw = semgrep.fetch_secrets(filter_params=to_secrets_filter_body(filters), **fetch_kwargs) if "Secrets" in active_types else []
    except SemgrepAPIError as exc:
        print(f"Semgrep API error: {exc}")
        sys.exit(1)

    sast = filter_findings(sast_raw, "sast", filters)
    sca = filter_findings(sca_raw, "sca", filters)
    secrets = secrets_raw  # v2 API handles all filtering server-side

    findings_by_type = {"SAST": sast, "SCA": sca, "Secrets": secrets}
    if "SAST" in active_types:
        print(f"  {_filter_log('sast', len(sast_raw), len(sast), filters)}")
    if "SCA" in active_types:
        print(f"  {_filter_log('sca', len(sca_raw), len(sca), filters)}")
    if "Secrets" in active_types:
        print(f"  {_filter_log('secrets', len(secrets_raw), len(secrets), filters)}")
    total = sum(len(v) for v in findings_by_type.values())
    print(f"  Total: {total}")

    # --- Fetch column maps (one per board, only if that board has new findings) ---
    col_maps: dict[str, dict] = {}

    # --- Route and create ---
    created = 0
    total_new_findings = 0

    # --- SAST and SCA: group findings, create one item per group ---
    for board_type in ("SAST", "SCA"):
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
            if board_type == "SCA":
                _apply_sca_merged_fields(col_vals, col_map, group)
            else:
                _apply_sast_merged_fields(col_vals, col_map, group)
            _set_link_col(col_vals, col_map, "Semgrep URL", _semgrep_finding_url(slug, finding))
            try:
                monday_id, _ = board["client"].create_item(item_name, col_vals)
                state["monday_items_created"][board_type][monday_id] = [
                    f.id for f in group.members
                ]
                state["daily"][today] += 1
                created += 1
                member_ids = ", ".join(f.id for f in group.members)
                print(f"  [{board_type}] {member_ids} → monday item {monday_id}")
                try:
                    if len(group.members) > 1:
                        if board_type == "SCA":
                            body = format_update_body_sca_group(group, slug)
                        else:
                            body = format_update_body_sast_group(group, slug)
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

    # --- Secrets: no grouping, one item per finding ---
    secrets_findings = findings_by_type.get("Secrets", [])
    already_synced_secrets = synced_finding_ids(state, "Secrets")
    new_secrets = [f for f in secrets_findings if f.id not in already_synced_secrets]
    total_new_findings += len(new_secrets)
    if new_secrets:
        board = boards["Secrets"]
        if "Secrets" not in col_maps:
            col_maps["Secrets"] = board["client"].get_column_map()
        col_map = col_maps["Secrets"]
        mapper = board["mapper"]
        body_formatter = board["body_formatter"]

        for finding in new_secrets:
            item_name, col_vals = mapper(finding, col_map)
            _set_link_col(col_vals, col_map, "Semgrep URL", _semgrep_finding_url(slug, finding))
            try:
                monday_id, _ = board["client"].create_item(item_name, col_vals)
                state["monday_items_created"]["Secrets"][monday_id] = [finding.id]
                state["daily"][today] += 1
                created += 1
                print(f"  [Secrets] {finding.id} → monday item {monday_id}")
                try:
                    body = body_formatter(finding)
                    board["client"].create_update(monday_id, body)
                except Exception as exc:
                    print(f"  [Secrets] Warning: update post failed for {monday_id}: {exc}")
                if set_triage_reviewing:
                    try:
                        item_url = _monday_item_url(account_slug, board["board_id"], monday_id)
                        note = f"Created monday item: {item_url}" if item_url else "Created monday item"
                        semgrep.triage_findings([finding.id], "reviewing", note, "secrets")
                    except Exception as exc:
                        print(f"  [Secrets] Warning: triage failed for {monday_id}: {exc}")
            except Exception as exc:
                print(f"  [Secrets] Failed for {finding.id}: {exc}")

    save_state(state, state_path)
    print(f"\nDone: {created} items created, {total_new_findings} new findings processed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync Semgrep findings to monday.com")
    _VALID_TYPES = {"sast": "SAST", "sca": "SCA", "secrets": "Secrets"}
    parser.add_argument("--limit", type=int, default=None, metavar="N", help="Max findings per type")
    parser.add_argument("--filters", default=None, metavar="PATH", help="Path to filters YAML file")
    parser.add_argument("--no-filters", action="store_true", help="Bypass filtering even if filters.yaml exists")
    parser.add_argument("--type", default=None, metavar="TYPES",
                        help="Comma-separated list of types to sync: sast,sca,secrets (default: all)")
    parser.add_argument("--set-triage-reviewing", action="store_true",
                        help="Triage synced findings to 'reviewing' in Semgrep with a note linking to the monday item")
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
        set_triage_reviewing=args.set_triage_reviewing)
