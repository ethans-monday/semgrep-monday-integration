# Agent Guide: Semgrep to monday.com Sync

This document describes how `sync.py` behaves when run autonomously (cron, Lambda, CI pipeline).

> **For AI assistants:** whenever you make a feature addition or change to this project, update all three documentation files before considering the task done: `README.md`, `agent.md`, and `CLAUDE.md`.

## Expected environment variables

All 6 variables must be set. The script exits with code 1 and a clear error message if any are missing.

```
SEMGREP_APP_TOKEN
SEMGREP_DEPLOYMENT_SLUG
MONDAY_API_TOKEN
MONDAY_BOARD_ID_SAST
MONDAY_BOARD_ID_SCA
MONDAY_BOARD_ID_SECRETS
```

The numeric deployment ID (required for the Secrets v2 API endpoints) is auto-discovered at runtime from the slug — no manual configuration needed.

## Behavior

1. Fetches all open findings from Semgrep (SAST, SCA, Secrets). SAST uses two v1 `/findings` calls — `issue_type=sast` and `issue_type=ai_sast` — merged and deduplicated by finding ID before processing. SCA uses the v1 `/findings` endpoint with `dedup=true`. Secrets use the v2 Issues API (`POST /api/agent/deployments/{id}/issues` with `issueType: ISSUE_TYPE_SECRETS`). After the open secrets fetch, a second POST is made with `aggregateIssueStates: [AGGREGATE_ISSUE_STATE_FIXED]` to capture fixed secrets that were never reviewed — fixed findings whose `note` field contains `monday.com` are skipped (already reviewed). Results are merged and deduplicated by finding ID. The fixed fetch is not subject to `--limit`; it always pages through all fixed secrets so that a limit on open findings cannot cause unreviewed fixed findings to be missed. Because the Semgrep triage API silently ignores note and state changes on FIXED findings (returns 200 but applies nothing), a separate `fixed_state.json` file is used for dedup. Fixed findings are skipped if their ID is in `fixed_state.json` OR if their `note` contains `monday.com` (previously reviewed via the normal open flow). On successful item creation, the finding ID is added to `fixed_state.json` and saved at the end of the run. Format v2: `{"version": 2, "SECRETS": [fid, ...], "SAST": {item_id: [fid, ...]}, "SCA": {item_id: [fid, ...]}}`. v1 (secrets-only list) is auto-migrated on load. The SAST/SCA sub-dicts are written to by the `--mark-fixed` mode when it migrates items out of `state.json`.
2. Drops findings from repos listed under `ignore_repos` in `filters.yaml` across all types.
3. Loads `state.json` for deduplication. Findings already synced are skipped.
4. Groups new SAST and SCA findings to reduce board noise (see **Finding grouping** below). Secrets are not grouped.
5. For each group (or individual Secrets finding), creates a monday.com item on the appropriate board with all available metadata and a deep-link to the finding in the Semgrep Cloud UI.
6. Immediately after each successful item creation, posts a rich HTML update to the item's Updates feed. Grouped items list each member finding's details and Semgrep URL.
7. If `--set-triage-reviewing` is passed: triages the finding(s) in Semgrep — sets triage state to `"reviewing"` and adds a note with the monday.com item URL (e.g. `Created monday item: https://acme.monday.com/boards/123/pulses/456`). SAST/SCA use the v1 triage endpoint; Secrets use the v2 bulk-update endpoint (`PATCH /api/agent/deployments/{id}/findings/v2` with `FINDING_TRIAGE_STATE_REVIEWING`). Triage failure is non-fatal. Skipped by default.
8. Saves updated state. All member finding IDs in a group are recorded, pointing to the same monday.com item ID.

## Error handling

- **Semgrep API errors** (auth failure, network) -- script exits with code 1.
- **monday.com item creation failure** (per finding) -- logged, finding is NOT added to state, will be retried on next run.
- **monday.com update-post failure** (per finding) -- logged as a warning, finding IS written to state (the item exists on the board without the rich update body). Re-running does not re-attempt the missing update.
- **Semgrep triage failure** (per finding) -- logged as a warning, finding IS written to state. The monday.com item exists; the Semgrep finding just won't be marked as "reviewing".
- **monday.com rate limiting (429)** -- automatically retries up to 3 times, respecting the `Retry-After` header.
- **Transient transport errors** (`httpx.ReadError`, `ConnectError`, timeouts) -- caught at both call sites so a single blip does not crash a full sync.

## Finding grouping

SAST and SCA findings are grouped before item creation to reduce board noise:

- **SCA:** Grouped by `{repo, package, file}`. CVE column contains all CVEs (comma-separated). Representative (used for item name, severity, links) is chosen by highest severity → reachable → highest confidence.
- **SAST:** Grouped by `{repo, file, end location}`. Rule names, CWEs, OWASP, and vulnerability classes are merged across members. Representative chosen by highest severity → AI true positive → highest confidence.
- **Secrets:** Not grouped.

All member finding IDs are tracked in `state.json` — re-runs skip the entire group. Grouping only applies to new (not-yet-synced) findings; it does not compare against previously synced items.

## API budget

Each group (or individual Secrets finding) consumes **2** monday.com API calls (one `create_item` plus one `create_update`) and **1** Semgrep API call (`triage`). Each unique repo encountered also costs **1** Semgrep API call to fetch project tags (cached for the duration of the run — subsequent findings from the same repo reuse the cached result). Plus one `get_column_map` query per board per run (cached after first use) and one `get_account_slug` query per run.

Grouping reduces API spend — e.g. 10 SCA findings across 3 packages becomes 3 items (6 monday calls + 3 triage calls) instead of 10 items (20 monday calls + 10 triage calls). Idempotent re-runs only spend calls on findings that haven't been synced before.

## State file format (v4)

```json
{
  "version": 4,
  "monday_items_created": {
    "SAST": { "<monday_item_id>": ["<finding_id>", "..."] },
    "SCA": { "<monday_item_id>": ["<finding_id>", "..."] },
    "Secrets": { "<monday_item_id>": ["<finding_id>"] }
  },
  "daily": {
    "YYYY-MM-DD": <call_count>
  }
}
```

Top-level keys are board types. Each maps monday.com item IDs to lists of Semgrep finding IDs (one for ungrouped, multiple for grouped). State v1–v3 files are automatically migrated on load.

To force a full re-sync, delete `state.json` before running.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (including 0 new findings) |
| 1 | Configuration error or Semgrep API failure |

## CLI flags

```
python sync.py                              # sync all findings
python sync.py --limit 100                  # cap at 100 findings per type
python sync.py --filters my.yaml            # use a specific filters file
python sync.py --no-filters                 # bypass filtering even if filters.yaml exists
python sync.py --set-triage-reviewing       # triage synced findings to 'reviewing' in Semgrep
python sync.py --dry-run                    # fetch and print finding IDs, no side effects
python sync.py --mark-fixed                 # after sync, reconcile items: mark Fixed / Not scanned by Semgrep (SAST + SCA)
```

## Mark-fixed reconciliation pass

`--mark-fixed` triggers a reconciliation pass **after** the normal sync completes in the same invocation. It only touches SAST and SCA (Secrets already has its own fixed-pass baked into the sync).

Flow (v2 API — collapses per-repo work into a small handful of paginated calls):

1. **Backfill:** for state entries with `repo=""` (pre-v5 migrations), call monday `get_items_by_ids` on the "Repo" column and fill it in. Save state.json immediately so backfill isn't lost if a later step bails.
2. **Bulk `/projects` fetch** — one paginated call. Semgrep excludes archived repos, so `repo not in active_repo_names` = "not scanned anymore."
3. **v2 fixed-findings fetch** — one paginated call per board type via `POST /api/agent/deployments/{id}/issues` with `{aggregateIssueStates: [AGGREGATE_ISSUE_STATE_FIXED], onPrimaryBranch: true}`. When `--fixed-since-days N` is set, adds `timeFilter: TIME_FILTER_FIXED_AT` and `since: <ISO cutoff>` to limit to recent transitions.
4. **Dispatch per state entry:**
   - Repo absent from active-projects list → mark `Not scanned by Semgrep`, migrate to `not_scanned_state.json`.
   - Finding IDs intersect the fetched fixed-on-primary set → mark `Fixed`, migrate to `fixed_state.json`.
   - Otherwise → leave state untouched.

`--dry-run` prints candidates without touching monday or state files. `--type sast` / `--type sca` narrows scope. `--fixed-since-days N` narrows the v2 fetch to findings fixed in the last N days. Even with `--dry-run` the backfill step is skipped (state.json isn't written during dry-run).

## Filtering

Set `SEMGREP_FILTERS_FILE` to a YAML path, or use `--filters PATH`. If `filters.yaml` exists in the repo root it is applied automatically. `--no-filters` disables all filtering for that run.

Filters are pushed server-side. SAST/SCA use query params on the v1 `/findings` endpoint. Secrets use the v2 `filter` body on the POST Issues endpoint — all secrets filtering is server-side (no client-side post-filters needed). Exception for SAST only: `ai_verdict: [not_analyzed]` (and any list that includes it) is applied client-side after fetching, since the v1 API has no equivalent param. Filters gate new fetches only — `state.json` is never modified based on filter config.

The `status` filter key is supported for all three types. For SAST/SCA it maps to the v1 `status` query param (values: `open`, `fixed`, etc.). For Secrets it maps to the v2 `tab` filter (values: `ISSUE_TAB_OPEN`, `ISSUE_TAB_REVIEWING`, etc. — single value only). Combined with triage-on-sync (which sets findings to "reviewing"), this provides server-side dedup for all three types.

## Lambda usage

Use `lambda_handler.py` as the entry point. It reads credentials from AWS Secrets Manager and writes state to `/tmp/state.json` (ephemeral) or DynamoDB (persistent). See `lambda_handler.py` for details.

Recommended schedule: EventBridge cron, every 4-6 hours.
