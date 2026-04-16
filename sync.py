"""Semgrep → Monday.com sync script (three-board architecture).

Usage:
    python setup_boards.py             # one-time: create boards + columns
    cp .env.example .env               # fill in credentials + board IDs
    python sync.py                     # sync all findings
    python sync.py --limit 50          # sync up to 50 per type

State is persisted in state.json. Re-running is safe — findings already synced
are skipped (deduplication by Semgrep finding ID).
"""

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from dotenv import load_dotenv

from monday_client import MondayAPIError, MondayClient
from semgrep_client import Finding, SemgrepAPIError, SemgrepClient

DEFAULT_STATE_FILE = Path(__file__).parent / "state.json"
STATE_VERSION = 2


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


def _set_col(col_vals: dict, col_map: dict[str, str], title: str, value: str) -> None:
    """Set a column value only if that column exists on the board."""
    if title in col_map and value:
        col_vals[col_map[title]] = value


# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    if not path.exists():
        return {"synced": {}, "daily": {}, "version": STATE_VERSION}
    state = json.loads(path.read_text())
    # Migrate v1 → v2
    if state.get("version", 1) < STATE_VERSION:
        old_synced = state.get("synced", {})
        state["synced"] = {
            fid: {"monday_item_id": mid, "board": "unknown"}
            for fid, mid in old_synced.items()
        }
        state["version"] = STATE_VERSION
    return state


def save_state(state: dict, path: Path) -> None:
    path.write_text(json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REQUIRED_ENV_VARS = [
    "SEMGREP_APP_TOKEN",
    "SEMGREP_DEPLOYMENT_SLUG",
    "SEMGREP_DEPLOYMENT_ID",
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


# ---------------------------------------------------------------------------
# SAST mapper
# ---------------------------------------------------------------------------

def sast_finding_to_item(finding: Finding, col_map: dict[str, str]) -> tuple[str, dict]:
    raw = finding.raw
    rule = raw.get("rule") or {}
    assistant = raw.get("assistant") or {}
    loc = raw.get("location") or {}

    item_name = f"[{finding.severity}] {finding.rule_name} — {finding.file_path}:{finding.line}"
    cv: dict = {}

    _set_col(cv, col_map, "Finding ID", finding.id)
    _set_col(cv, col_map, "Severity", _SEVERITY_LABELS.get(finding.severity, finding.severity.capitalize()))
    _set_col(cv, col_map, "Confidence", _safe_get(raw, "confidence"))
    _set_col(cv, col_map, "Rule", finding.rule_name)
    _set_col(cv, col_map, "Triage State", _safe_get(raw, "triage_state"))
    _set_col(cv, col_map, "File", f"{finding.file_path}:{finding.line}")
    _set_col(cv, col_map, "End Location", f"{loc.get('end_line', '')}:{loc.get('end_column', '')}")
    _set_col(cv, col_map, "Repo", finding.repo)
    _set_col(cv, col_map, "Categories", _join_list(raw.get("categories")))
    _set_col(cv, col_map, "CWE", _join_list(rule.get("cwe_names")))
    _set_col(cv, col_map, "OWASP", _join_list(rule.get("owasp_names")))
    _set_col(cv, col_map, "Vuln Classes", _join_list(rule.get("vulnerability_classes")))
    _set_col(cv, col_map, "Message", _truncate(_safe_get(raw, "rule_message")))
    _set_col(cv, col_map, "AI Verdict", _safe_get(assistant, "autotriage", "verdict"))
    _set_col(cv, col_map, "AI Reason", _truncate(_safe_get(assistant, "autotriage", "reason")))
    _set_col(cv, col_map, "AI Guidance", _truncate(_safe_get(assistant, "guidance", "summary")))
    autofix = _safe_get(assistant, "autofix", "fix_code")
    _set_col(cv, col_map, "Has Autofix", "Yes" if autofix else "No")
    comp_tag = _safe_get(assistant, "component", "tag")
    comp_risk = _safe_get(assistant, "component", "risk")
    _set_col(cv, col_map, "Component", f"{comp_tag} ({comp_risk})" if comp_tag else "")
    _set_col(cv, col_map, "Code URL", _safe_get(raw, "line_of_code_url"))
    _set_col(cv, col_map, "Sourcing Policy", _safe_get(raw, "sourcing_policy", "name"))
    _set_col(cv, col_map, "External Ticket", _safe_get(raw, "external_ticket"))
    _set_col(cv, col_map, "Rule Explanation", _truncate(_safe_get(assistant, "rule_explanation", "summary")))

    return item_name, cv


# ---------------------------------------------------------------------------
# SCA mapper
# ---------------------------------------------------------------------------

def sca_finding_to_item(finding: Finding, col_map: dict[str, str]) -> tuple[str, dict]:
    raw = finding.raw
    dep = raw.get("found_dependency") or {}
    epss = raw.get("epss_score") or {}

    item_name = f"[{finding.severity}] {finding.rule_name} — {finding.file_path}:{finding.line}"
    cv: dict = {}

    _set_col(cv, col_map, "Finding ID", finding.id)
    _set_col(cv, col_map, "Severity", _SEVERITY_LABELS.get(finding.severity, finding.severity.capitalize()))
    _set_col(cv, col_map, "Confidence", _safe_get(raw, "confidence"))
    _set_col(cv, col_map, "Rule", finding.rule_name)
    _set_col(cv, col_map, "Triage State", _safe_get(raw, "triage_state"))
    _set_col(cv, col_map, "File", f"{finding.file_path}:{finding.line}")
    _set_col(cv, col_map, "Repo", finding.repo)
    _set_col(cv, col_map, "CVE", _safe_get(raw, "vulnerability_identifier"))
    _set_col(cv, col_map, "Reachability", _safe_get(raw, "reachability"))
    _set_col(cv, col_map, "Reachable Condition", _truncate(_safe_get(raw, "reachable_condition")))
    _set_col(cv, col_map, "EPSS Score", str(epss.get("score", "")) if epss.get("score") is not None else "")
    _set_col(cv, col_map, "EPSS Percentile", str(epss.get("percentile", "")) if epss.get("percentile") is not None else "")
    _set_col(cv, col_map, "Package", _safe_get(dep, "package"))
    _set_col(cv, col_map, "Version", _safe_get(dep, "version"))
    _set_col(cv, col_map, "Ecosystem", _safe_get(dep, "ecosystem"))
    _set_col(cv, col_map, "Transitivity", _safe_get(dep, "transitivity"))
    fix_recs = raw.get("fix_recommendations") or []
    _set_col(cv, col_map, "Fix Recommendation", ", ".join(f"{r['package']}@{r['version']}" for r in fix_recs if isinstance(r, dict)))
    _set_col(cv, col_map, "Is Malicious", "Yes" if raw.get("is_malicious") else "No")
    _set_col(cv, col_map, "Lockfile URL", _safe_get(dep, "lockfile_line_url"))
    _set_col(cv, col_map, "Message", _truncate(_safe_get(raw, "rule_message")))
    _set_col(cv, col_map, "Categories", _join_list(raw.get("categories")))
    _set_col(cv, col_map, "Code URL", _safe_get(raw, "line_of_code_url"))

    return item_name, cv


# ---------------------------------------------------------------------------
# Secrets mapper
# ---------------------------------------------------------------------------

def secrets_finding_to_item(finding: Finding, col_map: dict[str, str]) -> tuple[str, dict]:
    raw = finding.raw

    item_name = f"[{finding.severity}] {finding.rule_name} — {finding.file_path}:{finding.line}"
    cv: dict = {}

    _set_col(cv, col_map, "Finding ID", finding.id)
    _set_col(cv, col_map, "Severity", _SEVERITY_LABELS.get(finding.severity, finding.severity.capitalize()))
    _set_col(cv, col_map, "Rule", finding.rule_name)
    _set_col(cv, col_map, "Triage State", _safe_get(raw, "triage_state"))
    _set_col(cv, col_map, "Validation State", _safe_get(raw, "validation_state"))
    _set_col(cv, col_map, "File", f"{finding.file_path}:{finding.line}")
    _set_col(cv, col_map, "Repo", finding.repo)
    _set_col(cv, col_map, "Confidence", _safe_get(raw, "confidence"))
    _set_col(cv, col_map, "Categories", _join_list(raw.get("categories")))
    _set_col(cv, col_map, "Message", _truncate(_safe_get(raw, "rule_message")))
    _set_col(cv, col_map, "Code URL", _safe_get(raw, "line_of_code_url"))
    _set_col(cv, col_map, "External Ticket", _safe_get(raw, "external_ticket"))

    return item_name, cv


# ---------------------------------------------------------------------------
# Board routing config
# ---------------------------------------------------------------------------

BOARD_CONFIG = {
    "SAST":    {"env_var": "MONDAY_BOARD_ID_SAST",    "mapper": sast_finding_to_item},
    "SCA":     {"env_var": "MONDAY_BOARD_ID_SCA",      "mapper": sca_finding_to_item},
    "Secrets": {"env_var": "MONDAY_BOARD_ID_SECRETS",   "mapper": secrets_finding_to_item},
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(state_path: Path = DEFAULT_STATE_FILE, limit: int | None = None) -> None:
    cfg = load_config()
    state = load_state(state_path)

    today = str(date.today())
    state.setdefault("daily", {})
    state["daily"].setdefault(today, 0)

    # --- Build clients ---
    semgrep = SemgrepClient(
        token=cfg["SEMGREP_APP_TOKEN"],
        deployment_slug=cfg["SEMGREP_DEPLOYMENT_SLUG"],
        deployment_id=cfg["SEMGREP_DEPLOYMENT_ID"],
    )

    boards: dict[str, dict] = {}
    for board_type, bc in BOARD_CONFIG.items():
        board_id = int(cfg[bc["env_var"]])
        client = MondayClient(token=cfg["MONDAY_API_TOKEN"], board_id=board_id)
        boards[board_type] = {"client": client, "mapper": bc["mapper"]}

    # --- Fetch findings ---
    print("Fetching Semgrep findings…")
    fetch_kwargs = {} if limit is None else {"max_findings": limit}
    try:
        sast = semgrep.fetch_findings("sast", **fetch_kwargs)
        sca = semgrep.fetch_findings("sca", **fetch_kwargs)
        secrets = semgrep.fetch_secrets()
    except SemgrepAPIError as exc:
        print(f"Semgrep API error: {exc}")
        sys.exit(1)

    findings_by_type = {"SAST": sast, "SCA": sca, "Secrets": secrets}
    total = sum(len(v) for v in findings_by_type.values())
    print(f"  SAST: {len(sast)}  SCA: {len(sca)}  Secrets: {len(secrets)}  Total: {total}")

    # --- Deduplicate ---
    already_synced = set(state.get("synced", {}).keys())

    # --- Fetch column maps (one per board, only if that board has new findings) ---
    col_maps: dict[str, dict] = {}

    # --- Route and create ---
    created = 0
    for board_type, type_findings in findings_by_type.items():
        new = [f for f in type_findings if f.id not in already_synced]
        if not new:
            continue

        board = boards[board_type]
        if board_type not in col_maps:
            col_maps[board_type] = board["client"].get_column_map()

        col_map = col_maps[board_type]
        mapper = board["mapper"]

        for finding in new:
            item_name, col_vals = mapper(finding, col_map)
            try:
                monday_id, _ = board["client"].create_item(item_name, col_vals)
                state["synced"][finding.id] = {
                    "monday_item_id": monday_id,
                    "board": board_type,
                }
                state["daily"][today] += 1
                created += 1
                print(f"  [{board_type}] {finding.id} → Monday item {monday_id}")
            except MondayAPIError as exc:
                print(f"  [{board_type}] Failed for {finding.id}: {exc}")

    new_total = sum(len([f for f in fl if f.id not in already_synced]) for fl in findings_by_type.values())
    save_state(state, state_path)
    print(f"\nDone: {created} created, {new_total - created} failed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync Semgrep findings to Monday.com")
    parser.add_argument("--limit", type=int, default=None, metavar="N", help="Max findings per type")
    args = parser.parse_args()
    run(limit=args.limit)
