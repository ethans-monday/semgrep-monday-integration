# Agent Guide: Semgrep to monday.com Sync

This document describes how `sync.py` behaves when run autonomously (cron, Lambda, CI pipeline).

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

The numeric deployment ID (required for the `/secrets` endpoint) is auto-discovered at runtime from the slug — no manual configuration needed.

## Behavior

1. Fetches all open findings from Semgrep (SAST, SCA, Secrets). SAST and SCA use `dedup=true` to deduplicate across branches.
2. Loads `state.json` for deduplication. Findings already synced are skipped.
3. Groups new SAST and SCA findings to reduce board noise (see **Finding grouping** below). Secrets are not grouped.
4. For each group (or individual Secrets finding), creates a monday.com item on the appropriate board with all available metadata and a deep-link to the finding in the Semgrep Cloud UI.
5. Immediately after each successful item creation, posts a rich HTML update to the item's Updates feed. Grouped items list each member finding's details and Semgrep URL.
6. Saves updated state. All member finding IDs in a group are recorded, pointing to the same monday.com item ID.

## Error handling

- **Semgrep API errors** (auth failure, network) -- script exits with code 1.
- **monday.com item creation failure** (per finding) -- logged, finding is NOT added to state, will be retried on next run.
- **monday.com update-post failure** (per finding) -- logged as a warning, finding IS written to state (the item exists on the board without the rich update body). Re-running does not re-attempt the missing update.
- **monday.com rate limiting (429)** -- automatically retries up to 3 times, respecting the `Retry-After` header.
- **Transient transport errors** (`httpx.ReadError`, `ConnectError`, timeouts) -- caught at both call sites so a single blip does not crash a full sync.

## Finding grouping

SAST and SCA findings are grouped before item creation to reduce board noise:

- **SCA:** Grouped by `{repo, package, version}`. CVE column contains all CVEs (comma-separated). Representative (used for item name, severity, links) is chosen by highest severity → reachable → highest confidence.
- **SAST:** Grouped by `{repo, file, end location}`. Rule names, CWEs, OWASP, and vulnerability classes are merged across members. Representative chosen by highest severity → AI true positive → highest confidence.
- **Secrets:** Not grouped.

All member finding IDs are tracked in `state.json` — re-runs skip the entire group. Grouping only applies to new (not-yet-synced) findings; it does not compare against previously synced items.

## API budget

Each group (or individual Secrets finding) consumes **2** monday.com API calls: one `create_item` plus one `create_update`. Plus one `get_column_map` query per board per run (cached after first use).

Grouping reduces API spend — e.g. 10 SCA findings across 3 packages becomes 3 items (6 calls) instead of 10 items (20 calls). Idempotent re-runs only spend calls on findings that haven't been synced before.

## State file format (v2)

```json
{
  "version": 2,
  "synced": {
    "<semgrep_finding_id>": {
      "monday_item_id": "<monday_item_id>",
      "board": "SAST|SCA|Secrets"
    }
  },
  "daily": {
    "YYYY-MM-DD": <call_count>
  }
}
```

State v1 files (from earlier versions) are automatically migrated on load.

To force a full re-sync, delete `state.json` before running.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (including 0 new findings) |
| 1 | Configuration error or Semgrep API failure |

## CLI flags

```
python sync.py                        # sync all findings
python sync.py --limit 100            # cap at 100 findings per type
python sync.py --filters my.yaml      # use a specific filters file
python sync.py --no-filters           # bypass filtering even if filters.yaml exists
```

## Filtering

Set `SEMGREP_FILTERS_FILE` to a YAML path, or use `--filters PATH`. If `filters.yaml` exists in the repo root it is applied automatically. `--no-filters` disables all filtering for that run.

Filters are pushed to the Semgrep API as query params (server-side). Exception: `ai_verdict: [not_analyzed]` (and any list that includes it) is applied client-side after fetching, since the Semgrep API has no equivalent param for findings where the AI verdict field is absent. Filters gate new fetches only — `state.json` is never modified based on filter config.

## Lambda usage

Use `lambda_handler.py` as the entry point. It reads credentials from AWS Secrets Manager and writes state to `/tmp/state.json` (ephemeral) or DynamoDB (persistent). See `lambda_handler.py` for details.

Recommended schedule: EventBridge cron, every 4-6 hours.
