# Semgrep to monday.com Integration

## Project overview

Python integration that syncs Semgrep Cloud Platform findings (SAST, SCA, Secrets) to three separate monday.com boards with full context preservation. Each new board item also gets a rich HTML post in the monday.com Updates feed.

## Key files

- `semgrep_client.py` -- Semgrep API client. Two pagination schemes: offset for `/findings` (SAST + SCA), cursor for `/secrets`. Both `fetch_findings` and `fetch_secrets` accept `extra_params` for filter pushdown.
- `monday_client.py` -- monday.com GraphQL client. Handles `API-Version: 2025-04` header, Retry-After rate limiting, `column_values` as JSON variable, and the `create_update` mutation.
- `sync.py` -- Orchestrator. Three type-specific column mappers and three type-specific update-body formatters extract fields from `Finding.raw` dict. Routes findings to the correct board, creates the item, then posts the Updates-feed body. Loads filters and passes them as `extra_params` to each fetch call.
- `filters.py` -- Config-file-driven filter layer. `load_filters(path)` parses a YAML file and validates keys against `ALLOWED_FILTERS`. `to_query_params(board_type, filters)` converts a filter block to Semgrep API query params. `filter_findings(findings, board_type, filters)` applies any client-side post-filters (currently: `ai_verdict` when `not_analyzed` is included, since the Semgrep API has no equivalent param).
- `setup_boards.py` -- Creates the three monday.com boards with all columns. `BOARD_COLUMNS` dict defines column layouts (includes the "Semgrep URL" column).
- `lambda_handler.py` -- AWS Lambda template. Reads secrets from Secrets Manager, calls `sync.run()`.

## Architecture

- `Finding` dataclass carries a `raw: dict` with the full API response. Mapper functions extract type-specific fields for monday.com columns; formatter functions build the HTML update body from the same `raw` dict.
- State v2 format: `{"version": 2, "synced": {"finding_id": {"monday_item_id": "...", "board": "SAST"}}, "daily": {...}}`. v1 is auto-migrated on load. Filters never modify state — they gate new fetches only.
- monday.com column types: `text` (default), `status` (Severity, Confidence, Triage State, Validation State, Reachability, Transitivity, AI Verdict, etc.), `link` (Semgrep URL, Code URL), `dropdown` (Categories, Vuln Classes, OWASP). Column IDs are auto-discovered per board via `get_column_map()` (cached per client).
- `create_item` uses `create_labels_if_missing: true` so status labels are created on the fly from whatever values the sync writes. Board columns are created with `defaults: {"labels": {}}` so no default labels ("Done", "Stuck", etc.) are pre-populated.
- Field normalization: snake_case fields (triage_state, verdict) use `_snake_to_title()` → "True Positive". Single-word lowercase fields (confidence, reachability, transitivity) use `.capitalize()`. Secrets severity and confidence have `SEVERITY_`/`CONFIDENCE_` prefixes that are stripped before capitalizing. AI Verdict defaults to `"Not analyzed"` when absent.
- `sync.run()` injects the Semgrep deep-link URL (`https://semgrep.dev/orgs/<slug>/findings/<id>` or `/secrets/<id>`) into the "Semgrep URL" column before creating the item.
- **Finding grouping:** SAST and SCA findings are grouped before item creation. SCA groups by `(repo, package, version)`; SAST groups by `(repo, file_path, end_location)`. `FindingGroup` dataclass holds a `representative` (highest priority finding) and `members` list. Representative is selected by `_finding_score()`: severity → reachability/verdict → confidence. Merged fields (CVE for SCA; Rule/CWE/OWASP/VulnClasses for SAST) are applied post-mapper via `_apply_sca_merged_fields` / `_apply_sast_merged_fields`. Group-aware formatters (`format_update_body_sca_group`, `format_update_body_sast_group`) list each member's details + Semgrep URL. All member IDs are tracked in state. Secrets are not grouped.

## Error handling

- `create_item` failures: logged, finding is NOT written to state → retried next run.
- `create_update` failures (including transient `httpx.ReadError`, `ConnectError`, timeouts): logged as a warning, finding IS persisted to state. The item exists on the board without a rich update body; re-running does not re-attempt.
- Both call sites use `except Exception` so transport-level blips don't crash the whole sync mid-batch.

## Important constraints

- monday.com `API-Version: 2025-04` is required. Older versions were deprecated Feb 2026. The `complexity` field was removed from the `Item` type in this version.
- Semgrep `/secrets` endpoint uses a **numeric deployment ID**, not the org slug. The `/findings` endpoint uses the slug.
- `column_values` must be passed as a GraphQL **variable** (not inlined), serialized with `json.dumps()`.
- `load_dotenv(override=True)` is used because the Semgrep MCP plugin may set `SEMGREP_APP_TOKEN` in the shell environment.
- Each new finding costs **two** monday.com API calls (create_item + create_update). See README for daily-limit math.

## Running tests

```bash
source .venv/bin/activate
pytest tests/ -v
```

All tests mock HTTP calls via `pytest-httpx`. No credentials needed.

## Never commit

- `.env` (contains API tokens)
- `state.json` (contains finding IDs and monday.com item IDs)
- `.venv/`, `__pycache__/`, `.pytest_cache/`, `.claude/`
