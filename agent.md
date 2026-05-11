# Agent Guide: Semgrep to monday.com Sync

This document describes how `sync.py` behaves when run autonomously (cron, Lambda, CI pipeline).

## Expected environment variables

All 7 variables must be set. The script exits with code 1 and a clear error message if any are missing.

```
SEMGREP_APP_TOKEN
SEMGREP_DEPLOYMENT_SLUG
SEMGREP_DEPLOYMENT_ID
MONDAY_API_TOKEN
MONDAY_BOARD_ID_SAST
MONDAY_BOARD_ID_SCA
MONDAY_BOARD_ID_SECRETS
```

## Behavior

1. Fetches all open findings from Semgrep (SAST, SCA, Secrets).
2. Loads `state.json` for deduplication. Findings already synced are skipped.
3. For each new finding, creates a monday.com item on the appropriate board with all available metadata and a deep-link to the finding in the Semgrep Cloud UI.
4. Immediately after each successful item creation, posts a rich HTML update (finding description, AI remediation guidance, suggested fix code) to the item's Updates feed.
5. Saves updated state after processing each type.

## Error handling

- **Semgrep API errors** (auth failure, network) -- script exits with code 1.
- **monday.com item creation failure** (per finding) -- logged, finding is NOT added to state, will be retried on next run.
- **monday.com update-post failure** (per finding) -- logged as a warning, finding IS written to state (the item exists on the board without the rich update body). Re-running does not re-attempt the missing update.
- **monday.com rate limiting (429)** -- automatically retries up to 3 times, respecting the `Retry-After` header.
- **Transient transport errors** (`httpx.ReadError`, `ConnectError`, timeouts) -- caught at both call sites so a single blip does not crash a full sync.

## API budget per new finding

Each new finding consumes **2** monday.com API calls: one `create_item` plus one `create_update`. Plus one `get_column_map` query per board per run (cached after first use).

A full sync of 1,000 new findings costs roughly 2,003 calls. Idempotent re-runs only spend calls on findings that haven't been synced before.

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
python sync.py                # sync all findings
python sync.py --limit 100    # cap at 100 findings per type
```

## Lambda usage

Use `lambda_handler.py` as the entry point. It reads credentials from AWS Secrets Manager and writes state to `/tmp/state.json` (ephemeral) or DynamoDB (persistent). See `lambda_handler.py` for details.

Recommended schedule: EventBridge cron, every 4-6 hours.
