"""Create three Monday.com boards for Semgrep findings (SAST, SCA, Secrets).

Usage:
    python setup_boards.py                       # default workspace
    python setup_boards.py --workspace YOUR_WORKSPACE_ID

Prints .env lines for the new board IDs at the end.
"""

import argparse
import os
import sys
import time

from dotenv import load_dotenv

from monday_client import MondayClient

# ---------------------------------------------------------------------------
# Column definitions — importable by tests and other modules
# ---------------------------------------------------------------------------

BOARD_COLUMNS: dict[str, list[str]] = {
    "SAST": [
        "Finding ID",
        "Severity",
        "Confidence",
        "Rule",
        "Triage State",
        "File",
        "End Location",
        "Repo",
        "Categories",
        "CWE",
        "OWASP",
        "Vuln Classes",
        "Message",
        "AI Verdict",
        "AI Reason",
        "AI Guidance",
        "Has Autofix",
        "Component",
        "Code URL",
        "Sourcing Policy",
        "External Ticket",
        "Rule Explanation",
    ],
    "SCA": [
        "Finding ID",
        "Severity",
        "Confidence",
        "Rule",
        "Triage State",
        "File",
        "Repo",
        "CVE",
        "Reachability",
        "Reachable Condition",
        "EPSS Score",
        "EPSS Percentile",
        "Package",
        "Version",
        "Ecosystem",
        "Transitivity",
        "Fix Recommendation",
        "Is Malicious",
        "Lockfile URL",
        "Message",
        "Categories",
        "Code URL",
    ],
    "Secrets": [
        "Finding ID",
        "Severity",
        "Rule",
        "Triage State",
        "Validation State",
        "File",
        "Repo",
        "Confidence",
        "Categories",
        "Message",
        "Code URL",
        "External Ticket",
    ],
}


def create_board(client: MondayClient, name: str, workspace_id: int | None) -> str:
    """Create a board and return its ID."""
    ws_arg = f", workspace_id: {workspace_id}" if workspace_id else ""
    query = f'mutation {{ create_board(board_name: "{name}", board_kind: public{ws_arg}) {{ id }} }}'
    data = client._post(query)
    return data["data"]["create_board"]["id"]


def create_columns(client: MondayClient, board_id: str, columns: list[str]) -> None:
    """Create text columns on a board."""
    for title in columns:
        query = """
        mutation ($boardId: ID!, $title: String!) {
          create_column(board_id: $boardId, title: $title, column_type: text) { id title }
        }
        """
        data = client._post(query, {"boardId": board_id, "title": title})
        col = data["data"]["create_column"]
        print(f"    {col['title']} ({col['id']})")
        time.sleep(0.3)  # gentle rate limiting for column creation


def main():
    parser = argparse.ArgumentParser(description="Create Monday.com boards for Semgrep findings")
    parser.add_argument("--workspace", type=int, default=None, help="Monday.com workspace ID")
    args = parser.parse_args()

    load_dotenv(override=True)
    token = os.getenv("MONDAY_API_TOKEN")
    if not token:
        print("Error: MONDAY_API_TOKEN not set in .env")
        sys.exit(1)

    # Use board_id=0 as placeholder — we're only creating boards, not querying one.
    client = MondayClient(token=token, board_id=0)

    board_ids: dict[str, str] = {}

    for board_type, columns in BOARD_COLUMNS.items():
        board_name = f"Semgrep {board_type} Findings"
        print(f"\nCreating board: {board_name} ({len(columns)} columns)")
        board_id = create_board(client, board_name, args.workspace)
        board_ids[board_type] = board_id
        print(f"  Board ID: {board_id}")
        create_columns(client, board_id, columns)

    print("\n" + "=" * 50)
    print("Add these to your .env file:\n")
    print(f"MONDAY_BOARD_ID_SAST={board_ids['SAST']}")
    print(f"MONDAY_BOARD_ID_SCA={board_ids['SCA']}")
    print(f"MONDAY_BOARD_ID_SECRETS={board_ids['Secrets']}")
    print("=" * 50)


if __name__ == "__main__":
    main()
