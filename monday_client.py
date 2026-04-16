"""Monday.com GraphQL API client.

Key behaviours enforced here:
  - API-Version: 2025-04 header on every request (older versions deprecated Feb 2026)
  - column_values passed as a GraphQL variable (not inlined), serialised with json.dumps
  - Status column values use {"label": "..."} format
  - 429 rate-limit errors are retried after honouring the Retry-After header
  - GraphQL errors inside a 200 response are raised as MondayAPIError
"""

import json
import time

import httpx

MONDAY_URL = "https://api.monday.com/v2"
MONDAY_API_VERSION = "2025-04"
MAX_RETRIES = 3


class MondayAPIError(Exception):
    pass


class MondayClient:
    def __init__(self, token: str, board_id: int) -> None:
        self.board_id = board_id
        self._headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "API-Version": MONDAY_API_VERSION,
        }
        self._column_map: dict[str, str] | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, query: str, variables: dict | None = None) -> dict:
        body: dict = {"query": query}
        if variables:
            body["variables"] = variables

        for attempt in range(MAX_RETRIES):
            response = httpx.post(MONDAY_URL, headers=self._headers, json=body, timeout=30)

            if response.status_code == 429:
                wait = int(response.headers.get("Retry-After", 60))
                print(f"  [monday] rate limited — waiting {wait}s (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(wait)
                continue

            if response.status_code != 200:
                raise MondayAPIError(f"HTTP {response.status_code}: {response.text[:300]}")

            data = response.json()
            if "errors" in data:
                raise MondayAPIError(f"GraphQL errors: {data['errors']}")

            return data

        raise MondayAPIError(f"Exceeded {MAX_RETRIES} retries due to rate limiting")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_column_map(self) -> dict[str, str]:
        """Return {column_title: column_id} for the configured board.

        Result is cached — only one API call per client lifetime.
        """
        if self._column_map is not None:
            return self._column_map

        query = """
        query ($boardId: [ID!]) {
          boards(ids: $boardId) {
            columns { id title }
          }
        }
        """
        data = self._post(query, {"boardId": [str(self.board_id)]})
        columns = data["data"]["boards"][0]["columns"]
        self._column_map = {col["title"]: col["id"] for col in columns}
        return self._column_map

    def create_item(self, name: str, column_values: dict) -> tuple[str, int]:
        """Create a board item.

        Args:
            name: Item title string.
            column_values: Dict of {column_id: value}. Status columns must use
                           {"label": "..."} format. Serialised internally.

        Returns:
            (monday_item_id, complexity_points_remaining)
        """
        mutation = """
        mutation ($boardId: ID!, $itemName: String!, $colVals: JSON!) {
          create_item(board_id: $boardId, item_name: $itemName, column_values: $colVals) {
            id
          }
        }
        """
        variables = {
            "boardId": str(self.board_id),
            "itemName": name,
            "colVals": json.dumps(column_values),
        }
        data = self._post(mutation, variables)
        item = data["data"]["create_item"]
        return item["id"], 0
