# Semgrep to Monday.com Integration

## Project overview

Python integration that syncs Semgrep Cloud Platform findings (SAST, SCA, Secrets) to three separate Monday.com boards with full context preservation.

## Key files

- `semgrep_client.py` -- Semgrep API client. Two pagination schemes: offset for /findings (SAST + SCA), cursor for /secrets.
- `monday_client.py` -- Monday.com GraphQL client. Handles `API-Version: 2025-04` header, Retry-After rate limiting, column_values as JSON variable.
- `sync.py` -- Orchestrator. Three type-specific mappers extract fields from `Finding.raw` dict. Routes findings to the correct board.
- `setup_boards.py` -- Creates the three Monday.com boards with all columns. `BOARD_COLUMNS` dict defines column layouts.
- `lambda_handler.py` -- AWS Lambda template. Reads secrets from Secrets Manager.

## Architecture

- `Finding` dataclass carries a `raw: dict` with the full API response. Mapper functions extract type-specific fields.
- State v2 format: `{"version": 2, "synced": {"finding_id": {"monday_item_id": "...", "board": "SAST"}}, "daily": {...}}`
- Monday.com columns are all text type. Column IDs are auto-discovered via `get_column_map()`.

## Important constraints

- Monday.com `API-Version: 2025-04` is required. Older versions were deprecated Feb 2026. The `complexity` field was removed from the `Item` type in this version.
- Semgrep `/secrets` endpoint uses a **numeric deployment ID**, not the org slug. The `/findings` endpoint uses the slug.
- `column_values` must be passed as a GraphQL **variable** (not inlined), serialized with `json.dumps()`.
- `load_dotenv(override=True)` is used because the Semgrep MCP plugin may set `SEMGREP_APP_TOKEN` in the shell environment.

## Running tests

```bash
source .venv/bin/activate
pytest tests/ -v
```

All tests mock HTTP calls via `pytest-httpx`. No credentials needed.

## Never commit

- `.env` (contains API tokens)
- `state.json` (contains finding IDs and Monday.com item IDs)
- `.venv/`
