"""Unit tests for MondayClient.

All HTTP calls are intercepted by pytest-httpx.
"""

import json
import time

import pytest

from monday_client import MondayClient, MondayAPIError

TOKEN = "test-monday-token"
BOARD_ID = 999888777

MONDAY_URL = "https://api.monday.com/v2"

COLUMNS_RESPONSE = {
    "data": {
        "boards": [
            {
                "columns": [
                    {"id": "status0", "title": "Severity"},
                    {"id": "text1",   "title": "Rule"},
                    {"id": "text2",   "title": "File"},
                    {"id": "text3",   "title": "Repo"},
                    {"id": "status4", "title": "Type"},
                    {"id": "text5",   "title": "Finding ID"},
                ]
            }
        ]
    }
}

CREATE_ITEM_RESPONSE = {
    "data": {
        "create_item": {
            "id": "111222333",
            "complexity": {"query": 1000, "after": 8500000},
        }
    }
}


def make_client() -> MondayClient:
    return MondayClient(token=TOKEN, board_id=BOARD_ID)


# ---------------------------------------------------------------------------
# Column map
# ---------------------------------------------------------------------------

def test_column_map_built_from_query(httpx_mock):
    httpx_mock.add_response(url=MONDAY_URL, json=COLUMNS_RESPONSE)

    col_map = make_client().get_column_map()
    assert col_map["Severity"] == "status0"
    assert col_map["Rule"] == "text1"
    assert col_map["Type"] == "status4"


def test_column_map_cached(httpx_mock):
    """Second call must not fire a second HTTP request."""
    httpx_mock.add_response(url=MONDAY_URL, json=COLUMNS_RESPONSE)

    client = make_client()
    client.get_column_map()
    client.get_column_map()  # should use cache

    assert len(httpx_mock.get_requests()) == 1


# ---------------------------------------------------------------------------
# create_item — request shape
# ---------------------------------------------------------------------------

def test_create_item_sends_variable(httpx_mock):
    """`column_values` must be passed via GraphQL variables, not inlined."""
    httpx_mock.add_response(url=MONDAY_URL, json=CREATE_ITEM_RESPONSE)

    make_client().create_item("Test item", {"status0": {"label": "High"}})

    body = json.loads(httpx_mock.get_requests()[0].content)
    assert "variables" in body
    assert "colVals" in body["variables"]
    # colVals must be a JSON string (serialised), not a plain dict
    col_vals_raw = body["variables"]["colVals"]
    assert isinstance(col_vals_raw, str)
    parsed = json.loads(col_vals_raw)
    assert "status0" in parsed


def test_create_item_status_label_format(httpx_mock):
    """Status column values must use {"label": "..."} format."""
    httpx_mock.add_response(url=MONDAY_URL, json=CREATE_ITEM_RESPONSE)

    col_vals = {
        "status0": {"label": "High"},
        "status4": {"label": "SAST"},
    }
    make_client().create_item("item", col_vals)

    body = json.loads(httpx_mock.get_requests()[0].content)
    parsed = json.loads(body["variables"]["colVals"])
    assert parsed["status0"] == {"label": "High"}
    assert parsed["status4"] == {"label": "SAST"}


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

def test_api_version_header(httpx_mock):
    httpx_mock.add_response(url=MONDAY_URL, json=CREATE_ITEM_RESPONSE)

    make_client().create_item("item", {})

    request = httpx_mock.get_requests()[0]
    assert request.headers["API-Version"] == "2025-04"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_retry_after_respected(httpx_mock, monkeypatch):
    """On a 429, the client should sleep for Retry-After seconds then retry."""
    slept: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))

    httpx_mock.add_response(
        url=MONDAY_URL,
        status_code=429,
        headers={"Retry-After": "5"},
        text="Too Many Requests",
    )
    httpx_mock.add_response(url=MONDAY_URL, json=CREATE_ITEM_RESPONSE)

    make_client().create_item("item", {})

    assert slept == [5.0]
    assert len(httpx_mock.get_requests()) == 2


# ---------------------------------------------------------------------------
# Complexity
# ---------------------------------------------------------------------------

def test_create_item_returns_id(httpx_mock):
    """create_item returns the item ID from the response."""
    httpx_mock.add_response(url=MONDAY_URL, json=CREATE_ITEM_RESPONSE)

    item_id, _ = make_client().create_item("item", {})
    assert item_id == "111222333"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_graphql_error_in_200_raises(httpx_mock):
    """`errors` key inside a 200 response must be treated as failure."""
    httpx_mock.add_response(
        url=MONDAY_URL,
        json={"errors": [{"message": "Column not found"}]},
    )

    with pytest.raises(MondayAPIError, match="GraphQL errors"):
        make_client().create_item("item", {})


def test_http_500_raises(httpx_mock):
    httpx_mock.add_response(url=MONDAY_URL, status_code=500, text="Internal Server Error")

    with pytest.raises(MondayAPIError, match="500"):
        make_client().create_item("item", {})
