# Semgrep to Monday.com Integration

Syncs security findings from the Semgrep Cloud Platform to Monday.com boards. Findings are separated into three dedicated boards with type-specific columns that preserve full context from the Semgrep API.

```
Semgrep Cloud API  -->  sync.py  -->  Monday.com GraphQL API
  /findings (SAST)                      SAST Findings board
  /findings (SCA)                       SCA Findings board
  /secrets                              Secrets Findings board
```

## What Gets Synced

**SAST board (22 columns)** -- AI triage verdict, CWE, OWASP, vulnerability classes, AI guidance, autofix availability, component risk, rule explanation, and more.

**SCA board (22 columns)** -- CVE, reachability status, EPSS score/percentile, vulnerable package + version, ecosystem, transitivity, fix recommendations, malicious package flag.

**Secrets board (12 columns)** -- Validation state (confirmed valid/invalid/unvalidated), confidence, and standard finding metadata.

All boards include: Finding ID, severity, confidence, rule name, triage state, file location, repo, message, and code URL.

## Prerequisites

- Python 3.10+
- A Semgrep Cloud Platform account (Team or Enterprise tier for API access)
- A Monday.com account (any tier)

## Setup Guide

### 1. Clone and install

```bash
cd semgrep-monday-integration
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Get your Semgrep credentials

1. **Deployment slug** -- visible in your browser URL bar: `semgrep.dev/orgs/<your-slug>`
2. **Deployment ID** (numeric) -- go to Semgrep Cloud > Settings > Deployment. The numeric ID appears in the URL or on the page.
3. **API token** -- go to Semgrep Cloud > Settings > Tokens > Generate new token. Select the **Web API** scope.

### 3. Get your Monday.com credentials

1. **API token** -- click your avatar > Developers > My access tokens. Copy the personal API token.
2. **Workspace ID** (optional) -- visible in your Monday.com URL: `your-org.monday.com/workspaces/<id>`. Only needed if you have multiple workspaces and want boards created in a specific one.

### 4. Create your .env file

```bash
cp .env.example .env
```

Edit `.env` and fill in your Semgrep credentials and Monday.com API token. Leave the board IDs empty for now.

### 5. Create Monday.com boards

```bash
python setup_boards.py                        # default workspace
python setup_boards.py --workspace 12345678   # specific workspace
```

This creates three boards (Semgrep SAST Findings, Semgrep SCA Findings, Semgrep Secrets Findings) with all columns pre-configured. The script prints board IDs at the end -- copy them into your `.env` file.

### 6. Run the sync

```bash
python sync.py              # sync all open findings
python sync.py --limit 50   # sync up to 50 per type (for testing)
```

## Configuration

| Variable | Description |
|---|---|
| `SEMGREP_APP_TOKEN` | Semgrep API token (Web API scope) |
| `SEMGREP_DEPLOYMENT_SLUG` | Your org slug from `semgrep.dev/orgs/<slug>` |
| `SEMGREP_DEPLOYMENT_ID` | Numeric deployment ID (used for /secrets endpoint) |
| `MONDAY_API_TOKEN` | Monday.com personal API token |
| `MONDAY_BOARD_ID_SAST` | Board ID for SAST findings |
| `MONDAY_BOARD_ID_SCA` | Board ID for SCA findings |
| `MONDAY_BOARD_ID_SECRETS` | Board ID for Secrets findings |

## Usage

### Idempotent syncs

The script tracks synced findings in `state.json`. Running it multiple times is safe -- findings already synced are skipped. This makes it suitable for cron jobs or scheduled runs.

### The --limit flag

Use `--limit N` to cap the number of findings fetched per type. Useful for initial testing or when you want to gradually populate boards.

### State file

`state.json` stores:
- `synced` -- mapping of Semgrep finding ID to Monday.com item ID and board type
- `daily` -- API call count per day (informational)
- `version` -- state format version (currently 2)

To re-sync everything, delete `state.json` and run again.

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

The script handles Monday.com rate limiting automatically by respecting the `Retry-After` header on 429 responses (retries up to 3 times).

### Monday.com daily API limits by plan

| Plan | Daily limit |
|---|---|
| Free | 200 |
| Standard | 1,000 |
| Pro | 10,000 |
| Enterprise | 25,000 |

With large finding counts, plan accordingly. A full sync of 1,000 findings requires ~1,003 API calls (3 column map queries + 1,000 create_item calls).

### Semgrep API

No documented rate limits for the findings REST API. The script uses reasonable page sizes (100 per request).

## Troubleshooting

**404 on findings endpoint** -- verify your deployment slug is correct. It should match the URL path at `semgrep.dev/orgs/<slug>`, not your org display name.

**Rate limited (429 errors)** -- the script auto-retries. If you're on a free Monday.com plan with 200 calls/day, use `--limit` to stay within budget.

**Empty secrets results** -- the `/secrets` endpoint uses a numeric deployment ID, not the slug. Verify `SEMGREP_DEPLOYMENT_ID` is correct. Also confirm that Secrets scanning is enabled in your Semgrep org.

**Column not found errors** -- run `setup_boards.py` to create boards with the correct column layout. Don't manually add/rename columns.
