# Semgrep to monday.com Integration

Syncs security findings from the Semgrep Cloud Platform to monday.com boards. Findings are separated into three dedicated boards with type-specific columns that preserve full context from the Semgrep API. Each new item also gets a rich HTML post in the monday.com Updates feed containing the AI-generated finding narrative, remediation guidance, and suggested fix code.

```
Semgrep Cloud API  -->  sync.py  -->  monday.com GraphQL API
  v1 /findings (SAST)                   SAST Findings board   (+ Updates feed)
  v1 /findings (SCA)                    SCA Findings board    (+ Updates feed)
  v2 /issues (Secrets)                  Secrets Findings board (+ Updates feed)
```

## What Gets Synced

**SAST board (23 columns)** -- AI triage verdict, CWE, OWASP, vulnerability classes, AI guidance, autofix availability, component risk, rule explanation, Semgrep deep-link, and more.

**SCA board (23 columns)** -- CVE, reachability status, EPSS score/percentile, vulnerable package + version, ecosystem, transitivity, fix recommendations, malicious package flag, Semgrep deep-link.

**Secrets board (13 columns)** -- Validation state (confirmed valid/invalid/unvalidated), confidence, secret type, triage state, CWE, OWASP, message, standard finding metadata, Semgrep deep-link.

All boards include: Finding ID, severity, confidence, rule name, triage state, file location, repo, code URL, and Semgrep URL.

### Updates feed

After creating each board item, the script posts an HTML update to the item's Updates panel containing:

- Header with severity, rule, file:line, and repo
- **SAST:** AI-generated finding description (instance-specific attack narrative), CWE/OWASP, component risk, triage state, and a Remediation section with numbered fix steps plus the suggested patch code
- **SCA:** CVE, reachability, EPSS score, vulnerable package details, fix recommendation, lockfile URL
- **Secrets:** validation state, secret type, confidence, triage state, CWE/OWASP, message, code URL

## Prerequisites

- Python 3.10+
- A Semgrep Cloud Platform account (Team or Enterprise tier for API access)
- A monday.com account (any tier — see rate-limit notes below)

## Setup Guide

### 1. Clone and install

```bash
cd semgrep-monday-integration
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Get your Semgrep credentials

1. **Deployment slug** -- visible in your browser URL bar: `semgrep.dev/orgs/<your-slug>`.
2. **API token** -- go to Semgrep Cloud > Settings > Tokens > Generate new token. Select the **Web API** scope.

### 3. Get your monday.com credentials

1. **API token** -- click your avatar > Developers > My access tokens. Copy the personal API token.
2. **Workspace ID** (optional) -- visible in your monday.com URL: `your-org.monday.com/workspaces/<id>`. Only needed if you have multiple workspaces and want boards created in a specific one.

### 4. Create your .env file

```bash
cp .env.example .env
```

Edit `.env` and fill in your Semgrep credentials and monday.com API token. Leave the board IDs empty for now.

### 5. Create monday.com boards

```bash
python setup_boards.py                        # default workspace
python setup_boards.py --workspace 12345678   # specific workspace
```

This creates three boards (Semgrep SAST Findings, Semgrep SCA Findings, Semgrep Secrets Findings) with all columns pre-configured. The script prints board IDs at the end -- copy them into your `.env` file.

### 6. Run the sync

```bash
python sync.py                            # sync all open findings
python sync.py --limit 50                 # sync up to 50 per type (for testing)
python sync.py --set-triage-reviewing     # also triage findings in Semgrep
```

## Configuration

| Variable | Description |
|---|---|
| `SEMGREP_APP_TOKEN` | Semgrep API token (Web API scope) |
| `SEMGREP_DEPLOYMENT_SLUG` | Your org slug from `semgrep.dev/orgs/<slug>` |
| `MONDAY_API_TOKEN` | monday.com personal API token |
| `MONDAY_BOARD_ID_SAST` | Board ID for SAST findings |
| `MONDAY_BOARD_ID_SCA` | Board ID for SCA findings |
| `MONDAY_BOARD_ID_SECRETS` | Board ID for Secrets findings |
| `MONDAY_ACCOUNT_SLUG` | (Optional) monday.com subdomain — auto-discovered if not set |

## Usage

### Finding grouping

SAST and SCA findings are automatically grouped to reduce board noise:

- **SCA:** Findings with the same `{repo, package, version}` become a single board item. The CVE column contains all CVEs (comma-separated). The item's representative (used for severity, file, links) is chosen by highest severity → reachable → highest confidence.
- **SAST:** Findings with the same `{repo, file, end location}` become a single board item. Rule names, CWEs, OWASP, and vulnerability classes are merged. Representative chosen by highest severity → AI true positive → highest confidence.

Grouped items get a richer Updates-feed post listing each member finding's details and Semgrep URL. All member finding IDs are tracked in `state.json`, so re-runs won't re-sync any of them.

Secrets findings are not grouped.

### Triage-on-sync (opt-in)

With the `--set-triage-reviewing` flag, the script triages each synced finding in Semgrep — setting its triage state to `"reviewing"` and adding a note with a link to the monday.com item (e.g. `Created monday item: https://acme.monday.com/boards/123/pulses/456`).

```bash
python sync.py --set-triage-reviewing
```

This provides server-side deduplication for all three types: filtering by `status: [open]` (SAST/SCA) or `status: [ISSUE_TAB_OPEN]` (Secrets) in `filters.yaml` ensures already-synced findings are excluded on subsequent runs.

The monday.com account slug (subdomain) is auto-discovered via the `account { slug }` GraphQL query. If this fails, set `MONDAY_ACCOUNT_SLUG` in `.env`.

Without the flag, triage is skipped and dedup relies entirely on `state.json`.

### Idempotent syncs

The script tracks synced findings in `state.json` as a fallback. Running it multiple times is safe -- findings already synced are skipped. This makes it suitable for cron jobs or scheduled runs.

### The --limit flag

Use `--limit N` to cap the number of findings fetched per type. Useful for initial testing or when you want to gradually populate boards.

### Filtering

The sync supports a YAML config file that gates which findings are fetched from Semgrep. Filters are pushed server-side — SAST/SCA as query params on the v1 API, Secrets as a `filter` body on the v2 Issues API. Only matching findings are downloaded, saving API budget and bandwidth.

**File location and precedence:**
1. `--filters PATH` CLI flag
2. `SEMGREP_FILTERS_FILE` env var
3. `filters.yaml` at the repo root (default)
4. `--no-filters` flag bypasses filtering entirely even if a file exists

**No file = no filtering** (current behavior is preserved).

Copy the example file to get started:

```bash
cp filters.example.yaml filters.yaml
# then edit filters.yaml to match your needs
```

Example `filters.yaml`:

```yaml
sast:
  severity: [CRITICAL, HIGH]
  confidence: [HIGH]
  ai_verdict: [true_positive]

sca:
  severity: [CRITICAL, HIGH]
  reachability: [reachable]

secrets:
  status: [ISSUE_TAB_OPEN]
  severity: [SEVERITY_HIGH, SEVERITY_CRITICAL]
  validation_state: [VALIDATION_STATE_CONFIRMED_VALID]
```

**Semantics:** all keys within a block must match (AND); all values within a list match as OR. Unknown keys and unknown board types cause a hard failure at load time — typos are caught immediately. Non-list values (e.g. `severity: HIGH` instead of `severity: [HIGH]`) also fail with a clear error.

**Supported filter keys per board type:**

| Key | SAST | SCA | Secrets |
|---|---|---|---|
| `severity` | ✓ (low/medium/high/critical) | ✓ | ✓ (SEVERITY_HIGH etc.) |
| `confidence` | ✓ scalar | ✓ scalar | ✓ (CONFIDENCE_HIGH etc.) |
| `repo` | ✓ | ✓ | ✓ |
| `rule` | ✓ | | |
| `ai_verdict` | ✓ (true_positive, false_positive, not_analyzed¹) | | |
| `status` | ✓ (open/fixed/ignored/reviewing/fixing/provisionally_ignored) | ✓ | ✓ scalar (ISSUE_TAB_OPEN/REVIEWING/IGNORED/CLOSED/FIXING) |
| `reachability` | | ✓ | |
| `transitivity` | | ✓ | |
| `malicious` | | ✓ ([true])² | |
| `validation_state` | | | ✓ |
| `secret_type` | | | ✓ (free-text values, e.g. "API Key") |
| `repo_visibility` | | | ✓ (REPOSITORY_VISIBILITY_PUBLIC etc.) |
| `exclude_historical` | | | ✓ ([true])³ |

¹ `not_analyzed` (and any list that includes it) is applied client-side after fetching — the Semgrep v1 API has no equivalent param for findings where the AI verdict field is absent.

² `malicious: [true]` triggers a second SCA query with only `is_malicious=true` — no other SCA filters (severity, reachability, etc.) are applied to it. Results are merged with the primary SCA fetch and deduplicated.

³ `exclude_historical: [true]` filters out historical secrets issues (those no longer present in code). Boolean trigger — only `[true]` is accepted.

Filters gate new fetches only — existing items in `state.json` are never modified or removed.

### State file

`state.json` stores:
- `monday_items_created` -- nested by board type (`SAST`, `SCA`, `Secrets`), then monday.com item ID → list of Semgrep finding IDs (one-to-many for grouped findings)
- `daily` -- API call count per day (informational)
- `version` -- state format version (currently 4)

To re-sync everything, delete `state.json` and run again.

### Error resilience

- If a monday.com item creation fails, the finding is **not** written to state and will be retried on the next run.
- If the item was created but posting the Updates-feed body fails (transient network error, etc.), a warning is logged and the item is still persisted to state. The item exists on the board without the rich update body.

## Testing

```bash
pip install -r requirements.txt   # includes pytest + pytest-httpx
pytest tests/ -v
```

All tests use mocked HTTP calls -- no real API credentials needed.

## AWS Lambda Deployment

A `lambda_handler.py` template is included. It wraps `sync.run()` and reads credentials from AWS Secrets Manager instead of `.env`.

### Quick setup

1. **Store secrets in AWS Secrets Manager** -- create a secret with the same key/value pairs as `.env` (all 7 variables).

2. **Create a Lambda function** -- Python 3.12 runtime, 512 MB memory, 5-minute timeout.

3. **Package the code**:
   ```bash
   pip install -r requirements.txt -t package/
   cp sync.py semgrep_client.py monday_client.py lambda_handler.py package/
   cd package && zip -r ../deploy.zip .
   ```

4. **Upload `deploy.zip`** as the Lambda code.

5. **Set environment variables** on the Lambda:
   - `SECRETS_NAME` -- name of your Secrets Manager secret
   - `STATE_TABLE` -- DynamoDB table name (if using DynamoDB for state)

6. **IAM permissions** -- the Lambda execution role needs:
   - `secretsmanager:GetSecretValue` for your secret
   - `dynamodb:GetItem`, `dynamodb:PutItem` (if using DynamoDB)

7. **Add a trigger** -- EventBridge cron rule, e.g., `rate(6 hours)`.

### State in Lambda

The template defaults to `/tmp/state.json`, which is ephemeral (lost on cold starts). For production, switch to DynamoDB -- the template includes a placeholder for this. Create a table with `finding_id` as the partition key.

## API Limits and Rate Limiting

The script handles monday.com rate limiting automatically by respecting the `Retry-After` header on 429 responses (retries up to 3 times).

### monday.com daily API limits by plan

| Plan | Daily limit |
|---|---|
| Free | 200 |
| Standard | 1,000 |
| Pro | 10,000 |
| Enterprise | 25,000 |

**API calls per new finding:** each finding creates **two** monday.com calls (one `create_item`, one `create_update`) plus **one** Semgrep API call (`triage`). A full sync of 1,000 new findings costs roughly **2,004 monday.com calls** (3 column-map queries + 1 account-slug query + 1,000 × 2) and **1,000 Semgrep triage calls**. Plan your tier and cron cadence accordingly — idempotent re-runs only spend calls on *new* findings.

### Semgrep API

No documented rate limits for the findings REST API. The script uses reasonable page sizes (100 per request).

## Troubleshooting

**404 on findings endpoint** -- verify your deployment slug is correct. It should match the URL path at `semgrep.dev/orgs/<slug>`, not your org display name.

**Rate limited (429 errors)** -- the script auto-retries up to 3 times, honouring the `Retry-After` header. If you're on a free monday.com plan with 200 calls/day, use `--limit` to stay within budget.

**Update post failed: ...** -- the monday.com item was created but the Updates-feed body couldn't be posted (usually a transient network reset). The finding is still recorded in state; only the rich update body is missing. Re-running will not re-attempt the failed update.

**Empty secrets results** -- confirm that Secrets scanning is enabled in your Semgrep org. The numeric deployment ID is auto-discovered from your slug; no manual configuration is needed. If using `status: [ISSUE_TAB_OPEN]`, verify that untriaged secrets exist in the Semgrep UI.

**Column not found errors** -- run `setup_boards.py` to create boards with the correct column layout. Don't manually add, rename, or delete columns on the boards the script writes to.
