"""Sync Semgrep project tags to monday.com board items.

Reads the Repo column from each item on all configured boards, looks up the
matching Semgrep project, and writes its tags into the Project Tags dropdown column.
"""

import argparse
import os
import sys

from dotenv import load_dotenv

from monday_client import MondayClient
from semgrep_client import SemgrepClient

BOARD_ENV_VARS = {
    "SAST": "MONDAY_BOARD_ID_SAST",
    "SCA": "MONDAY_BOARD_ID_SCA",
    "Secrets": "MONDAY_BOARD_ID_SECRETS",
}


def run(item_ids: list[str] | None = None, dry_run: bool = False) -> None:
    load_dotenv(override=True)

    semgrep_token = os.environ["SEMGREP_APP_TOKEN"]
    semgrep_slug = os.environ["SEMGREP_DEPLOYMENT_SLUG"]
    monday_token = os.environ["MONDAY_API_TOKEN"]

    semgrep = SemgrepClient(semgrep_token, semgrep_slug)

    print("Fetching Semgrep projects...")
    projects = semgrep.fetch_projects()
    project_tags = {p["name"]: p.get("tags", []) for p in projects}
    print(f"  Found {len(projects)} projects")

    total_updated = 0
    total_skipped = 0

    for board_type, env_var in BOARD_ENV_VARS.items():
        board_id_str = os.environ.get(env_var)
        if not board_id_str:
            print(f"\n[{board_type}] Skipping — {env_var} not set")
            continue

        board_id = int(board_id_str)
        monday = MondayClient(monday_token, board_id)

        col_map = monday.get_column_map()
        repo_col_id = col_map.get("Repo")
        tags_col_id = col_map.get("Project Tags")

        if not repo_col_id:
            print(f"\n[{board_type}] Skipping — no 'Repo' column found")
            continue
        if not tags_col_id:
            print(f"\n[{board_type}] Skipping — no 'Project Tags' column found")
            continue

        print(f"\n[{board_type}] Board {board_id} (Repo={repo_col_id}, Project Tags={tags_col_id})")

        if item_ids:
            items = monday.get_items_by_ids(item_ids, [repo_col_id])
        else:
            items = monday.get_board_items([repo_col_id])
        print(f"  Found {len(items)} items")

        updated = 0
        skipped = 0
        for item in items:
            item_id = item["id"]
            col_vals = {cv["id"]: cv["text"] for cv in item["column_values"]}
            repo = col_vals.get(repo_col_id, "").strip()

            if not repo:
                skipped += 1
                continue

            tags = project_tags.get(repo)
            if tags is None:
                print(f"  [skip] item {item_id}: no Semgrep project matching '{repo}'")
                skipped += 1
                continue

            if not tags:
                print(f"  [skip] item {item_id}: project '{repo}' has no tags")
                skipped += 1
                continue

            if dry_run:
                print(f"  [dry-run] item {item_id}: would set tags {tags}")
                updated += 1
                continue

            monday.change_column_values(item_id, {tags_col_id: {"labels": tags}})
            print(f"  [updated] item {item_id}: tags={tags}")
            updated += 1

        print(f"  [{board_type}] Updated: {updated}, Skipped: {skipped}")
        total_updated += updated
        total_skipped += skipped

    print(f"\nDone. Total updated: {total_updated}, Total skipped: {total_skipped}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sync Semgrep project tags to monday.com board items"
    )
    parser.add_argument(
        "--items",
        default=None,
        metavar="IDS",
        help="Comma-separated monday item IDs (omit for entire board)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and match only — don't update the board",
    )
    args = parser.parse_args()

    item_ids = None
    if args.items:
        item_ids = [i.strip() for i in args.items.split(",") if i.strip()]

    run(item_ids=item_ids, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
