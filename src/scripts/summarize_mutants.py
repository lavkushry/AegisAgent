#!/usr/bin/env python3
"""TEST-006 (#1166): summarize a cargo-mutants `outcomes.json` kill rate.

Used by .github/workflows/mutation-testing.yml to print an informational
kill-rate summary; never fails the calling workflow.
"""

import json
import sys


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "mutants-out/outcomes.json"
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"could not read/parse {path}: {e}")
        return 0

    outcomes = data.get("outcomes", [])
    total = len(outcomes)
    caught = sum(1 for o in outcomes if o.get("summary") == "CaughtMutant")
    missed = sum(1 for o in outcomes if o.get("summary") == "MissedMutant")
    unviable = sum(1 for o in outcomes if o.get("summary") == "Unviable")
    timeout = sum(1 for o in outcomes if o.get("summary") == "Timeout")
    viable = total - unviable
    rate = (caught / viable * 100) if viable else 0.0

    print(f"total mutants:   {total}")
    print(f"caught:          {caught}")
    print(f"missed:          {missed}")
    print(f"timeout:         {timeout}")
    print(f"unviable:        {unviable}")
    print(f"kill rate:       {rate:.1f}% (of {viable} viable mutants)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
