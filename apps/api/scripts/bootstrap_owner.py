"""Bootstrap (or fetch) the Aetherix Platform Owner account.

Idempotent: running it repeatedly returns the same account id.

Usage (from repo root, with the API venv active OR via the venv python):

    .venv/bin/python -m scripts.bootstrap_owner \\
        --email owner@aetherix.local --name "Aetherix Owner"

The schema must already exist; the API normally calls ``init_schema()`` on
startup, but this script also calls it so the very first run works against
a fresh database.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from app.db import init_schema
from app.services import tenancy


def main() -> int:
    parser = argparse.ArgumentParser(description="Ensure the Aetherix Platform Owner account exists")
    parser.add_argument("--email", default="owner@aetherix.local", help="Owner email (default: owner@aetherix.local)")
    parser.add_argument("--name", default="Aetherix Owner", help="Owner full name (default: 'Aetherix Owner')")
    parser.add_argument(
        "--password",
        default=None,
        help="Owner password. Falls back to AETHERIX_OWNER_PASSWORD env, then an interactive prompt.",
    )
    args = parser.parse_args()

    init_schema()

    password = args.password or os.environ.get("AETHERIX_OWNER_PASSWORD")
    if not password:
        password = getpass.getpass("Owner password (min 8 chars, blank to skip): ") or None
        if password:
            confirm = getpass.getpass("Confirm password: ")
            if confirm != password:
                print("Passwords do not match.", file=sys.stderr)
                return 2

    account = tenancy.ensure_platform_owner(args.email, args.name, password=password)

    print("Platform Owner ready.")
    print(f"  account_id : {account.id}")
    print(f"  email      : {account.email}")
    print(f"  full_name  : {account.full_name}")
    print(f"  status     : {account.status}")
    print()
    if password:
        print("Sign in to the console with this email and password.")
    else:
        print("No password set — set one via POST /accounts/{id}/password before signing in.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
