"""Create three monday.com boards for Semgrep findings (SAST, SCA, Secrets).

Usage:
    python setup_boards.py                       # default workspace
    python setup_boards.py --workspace YOUR_WORKSPACE_ID

Prints .env lines for the new board IDs at the end.
"""

import argparse
import json
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
        "Semgrep URL",
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
        "Semgrep URL",
    ],
    "Secrets": [
        "Finding ID",
        "Severity",
        "Rule",
        "Triage State",
        "Validation State",
        "Secret Type",
        "File",
        "Repo",
        "Confidence",
        "Message",
        "CWE",
        "OWASP",
        "Code URL",
        "Semgrep URL",
    ],
}

COLUMN_TYPES: dict[str, str] = {
    "Severity":         "status",
    "Confidence":       "status",
    "Triage State":     "status",
    "Validation State": "status",
    "Reachability":     "status",
    "Ecosystem":        "status",
    "Transitivity":     "status",
    "Is Malicious":     "status",
    "Sourcing Policy":  "status",
    "Component":        "dropdown",
    "Has Autofix":      "status",
    "AI Guidance":      "text",
    "AI Verdict":       "status",
    "Categories":       "dropdown",
    "Vuln Classes":     "dropdown",
    "OWASP":            "dropdown",
    "Semgrep URL":      "link",
    "Code URL":         "link",
    "Secret Type":      "dropdown",
}


def create_board(client: MondayClient, name: str, workspace_id: int | None) -> str:
    """Create a board and return its ID."""
    ws_arg = ", workspace_id: $workspaceId" if workspace_id else ""
    query = f"mutation ($boardName: String!{', $workspaceId: ID!' if workspace_id else ''}) {{ create_board(board_name: $boardName, board_kind: public{ws_arg}) {{ id }} }}"
    variables: dict = {"boardName": name}
    if workspace_id:
        variables["workspaceId"] = str(workspace_id)
    data = client._post(query, variables)
    return data["data"]["create_board"]["id"]


def clear_default_items(client: MondayClient, board_id: str) -> None:
    """Delete any items auto-created by monday.com (e.g. 'Task 1') on a new board."""
    query = """
    query ($boardId: [ID!]) {
      boards(ids: $boardId) {
        items_page { items { id name } }
      }
    }
    """
    data = client._post(query, {"boardId": [board_id]})
    items = data["data"]["boards"][0]["items_page"]["items"]
    for item in items:
        mutation = "mutation ($itemId: ID!) { delete_item(item_id: $itemId) { id } }"
        client._post(mutation, {"itemId": item["id"]})
        print(f"    Deleted default item '{item['name']}' ({item['id']})")


def create_columns(client: MondayClient, board_id: str, columns: list[str]) -> None:
    """Create columns on a board, using type from COLUMN_TYPES (default: text)."""
    for title in columns:
        col_type = COLUMN_TYPES.get(title, "text")
        query = """
        mutation ($boardId: ID!, $title: String!, $colType: ColumnType!, $defaults: JSON) {
          create_column(board_id: $boardId, title: $title, column_type: $colType, defaults: $defaults) { id title }
        }
        """
        defaults = json.dumps({"labels": {}}) if col_type == "status" else json.dumps({})
        data = client._post(query, {"boardId": board_id, "title": title, "colType": col_type, "defaults": defaults})
        col = data["data"]["create_column"]
        print(f"    {col['title']} ({col['id']}) [{col_type}]")
        time.sleep(0.3)


def main():
    parser = argparse.ArgumentParser(description="Create monday.com boards for Semgrep findings")
    parser.add_argument("--workspace", type=int, default=None, help="monday.com workspace ID")
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
        clear_default_items(client, board_id)
        create_columns(client, board_id, columns)

    print("\n" + "=" * 50)
    print("Add these to your .env file:\n")
    print(f"MONDAY_BOARD_ID_SAST={board_ids['SAST']}")
    print(f"MONDAY_BOARD_ID_SCA={board_ids['SCA']}")
    print(f"MONDAY_BOARD_ID_SECRETS={board_ids['Secrets']}")
    print("=" * 50)


if __name__ == "__main__":
    main()
