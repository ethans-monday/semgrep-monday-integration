"""monday.com GraphQL API client.

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
        self._account_slug: str | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, query: str, variables: dict | None = None) -> dict:
        body: dict = {"query": query}
        if variables:
            body["variables"] = variables

        for attempt in range(MAX_RETRIES):
            print(f"  [monday] POST {MONDAY_URL}")
            response = httpx.post(MONDAY_URL, headers=self._headers, json=body, timeout=30)

            if response.status_code == 429:
                wait = int(response.headers.get("Retry-After", 60))
                print(f"  [monday] rate limited — waiting {wait}s (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(wait)
                continue

            if response.status_code == 403 and attempt < MAX_RETRIES - 1:
                wait = 2 ** attempt
                print(f"  [monday] 403 — retrying in {wait}s (attempt {attempt + 1}/{MAX_RETRIES})")
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

    def get_account_slug(self) -> str:
        """Return the monday.com account slug (subdomain in URLs).

        Cached after first call. Falls back to MONDAY_ACCOUNT_SLUG env var.
        """
        if self._account_slug is not None:
            return self._account_slug
        try:
            data = self._post("query { account { slug } }")
            slug = data.get("data", {}).get("account", {}).get("slug", "")
            if slug:
                self._account_slug = slug
                return slug
        except Exception:
            pass
        import os
        slug = os.getenv("MONDAY_ACCOUNT_SLUG", "")
        self._account_slug = slug
        return slug

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

    def create_update(self, item_id: str, body: str) -> str:
        """Post a text update (comment) to an item's Updates panel.

        Args:
            item_id: The monday.com item ID returned by create_item.
            body:    Plain text or HTML string shown in the Updates section.

        Returns:
            The monday.com update ID.
        """
        mutation = """
        mutation ($itemId: ID!, $body: String!) {
          create_update(item_id: $itemId, body: $body) {
            id
          }
        }
        """
        data = self._post(mutation, {"itemId": item_id, "body": body})
        return data["data"]["create_update"]["id"]

    def get_board_items(self, column_ids: list[str]) -> list[dict]:
        """Fetch all items from the board with specified column values.

        Returns list of dicts: {"id": str, "column_values": [{"id": str, "text": str}]}
        Paginates automatically using cursor.
        """
        query = """
        query ($boardId: [ID!], $columnIds: [String!], $cursor: String) {
          boards(ids: $boardId) {
            items_page(limit: 500, cursor: $cursor) {
              cursor
              items {
                id
                column_values(ids: $columnIds) {
                  id
                  text
                }
              }
            }
          }
        }
        """
        items: list[dict] = []
        cursor = None
        while True:
            variables: dict = {"boardId": [str(self.board_id)], "columnIds": column_ids}
            if cursor:
                variables["cursor"] = cursor
            data = self._post(query, variables)
            page = data["data"]["boards"][0]["items_page"]
            items.extend(page["items"])
            cursor = page.get("cursor")
            if not cursor:
                break
        return items

    def get_items_by_ids(self, item_ids: list[str], column_ids: list[str]) -> list[dict]:
        """Fetch specific items by ID with specified column values."""
        query = """
        query ($itemIds: [ID!], $columnIds: [String!]) {
          items(ids: $itemIds) {
            id
            column_values(ids: $columnIds) {
              id
              text
            }
          }
        }
        """
        data = self._post(query, {"itemIds": item_ids, "columnIds": column_ids})
        return data["data"]["items"]

    def change_column_values(self, item_id: str, column_values: dict) -> str:
        """Update column values on an existing item.

        Args:
            item_id: The monday.com item ID.
            column_values: Dict of {column_id: value}.

        Returns:
            The item ID.
        """
        mutation = """
        mutation ($boardId: ID!, $itemId: ID!, $colVals: JSON!) {
          change_multiple_column_values(
            board_id: $boardId,
            item_id: $itemId,
            column_values: $colVals,
            create_labels_if_missing: true
          ) {
            id
          }
        }
        """
        variables = {
            "boardId": str(self.board_id),
            "itemId": item_id,
            "colVals": json.dumps(column_values),
        }
        data = self._post(mutation, variables)
        return data["data"]["change_multiple_column_values"]["id"]

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
          create_item(board_id: $boardId, item_name: $itemName, column_values: $colVals, create_labels_if_missing: true) {
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
