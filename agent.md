# Agent Guide: Semgrep to Monday.com Sync

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
3. For each new finding, creates a Monday.com item on the appropriate board with all available metadata.
4. Saves updated state after processing.

## Error handling

- **Semgrep API errors** (auth failure, network) -- script exits with code 1.
- **Monday.com item creation failure** (per finding) -- logged, finding is NOT added to state, will be retried on next run.
- **Monday.com rate limiting (429)** -- automatically retries up to 3 times, respecting the `Retry-After` header.

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
