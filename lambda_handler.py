"""AWS Lambda handler for Semgrep → monday.com sync.

Reads credentials from AWS Secrets Manager instead of .env.
State is stored in /tmp/state.json (ephemeral) by default.

Setup:
  1. Store all 7 env vars as key/value pairs in a Secrets Manager secret.
  2. Set the SECRETS_NAME environment variable on the Lambda to the secret name.
  3. IAM: grant secretsmanager:GetSecretValue to the Lambda execution role.
  4. Trigger: EventBridge cron rule (e.g., rate(6 hours)).

For persistent state, replace /tmp/state.json with DynamoDB
(see the TODO comments below).
"""

import json
import os
from pathlib import Path

import boto3

# Import the sync engine
from sync import run

SECRETS_NAME = os.environ.get("SECRETS_NAME", "semgrep-monday-integration")
STATE_PATH = Path("/tmp/state.json")


def _load_secrets() -> None:
    """Fetch secrets from AWS Secrets Manager and inject as env vars."""
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=SECRETS_NAME)
    secrets = json.loads(response["SecretString"])

    for key, value in secrets.items():
        os.environ[key] = str(value)


def handler(event, context):
    """Lambda entry point.

    Args:
        event: EventBridge event (ignored).
        context: Lambda context object.

    Returns:
        Dict with sync results summary.
    """
    _load_secrets()

    # TODO: For persistent state across Lambda invocations, replace STATE_PATH
    # with a DynamoDB-backed state loader. The sync module's load_state/save_state
    # functions work with any Path — you'd need to:
    #   1. Download state from DynamoDB to /tmp/state.json before run()
    #   2. Upload /tmp/state.json back to DynamoDB after run()
    #
    # DynamoDB table schema:
    #   Partition key: "state_key" (String) — use a fixed value like "sync_state"
    #   Attribute: "data" (String) — JSON-serialized state dict

    run(state_path=STATE_PATH)

    # Read state to return summary
    if STATE_PATH.exists():
        state = json.loads(STATE_PATH.read_text())
        synced_count = len(state.get("synced", {}))
    else:
        synced_count = 0

    return {
        "statusCode": 200,
        "body": json.dumps({"total_synced": synced_count}),
    }
