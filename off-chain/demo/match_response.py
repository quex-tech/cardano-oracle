#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
"""Match a responses.py listing (stdin) against a Pool Action ID and freshness cutoff.

Usage: ./responses.py | match_response.py <pool_action_id> <cutoff_epoch>
Prints the matched response block and exits 0, or exits 1 if none matches.
"""
import datetime
import sys


def main() -> int:
    pool_action_id, cutoff = sys.argv[1], int(sys.argv[2])
    blocks: list[list[str]] = []
    block: list[str] = []
    for line in sys.stdin:
        if line.startswith("- UTxO:") and block:
            blocks.append(block)
            block = []
        block.append(line.rstrip("\n"))
    if block:
        blocks.append(block)

    for b in blocks:
        text = "\n".join(b)
        if pool_action_id not in text:
            continue
        ts_line = next((l for l in b if "Timestamp:" in l), None)
        if not ts_line:
            continue
        ts = datetime.datetime.fromisoformat(ts_line.split(None, 1)[1].strip().replace("Z", "+00:00"))
        if ts.timestamp() < cutoff:
            continue  # stale response from an earlier request
        print(text)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
