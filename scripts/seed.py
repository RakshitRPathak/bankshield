"""Reset and seed the prototype: estate, baseline logs, attack scenarios, policies, first scan."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bankshield.bootstrap import seed  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-attacks", action="store_true", help="seed without injecting attack scenarios")
    ap.add_argument("--history-days", type=int, default=10, help="days of estate history to replay (0 = none)")
    args = ap.parse_args()
    seed(attacks=not args.no_attacks, history_days=args.history_days)


if __name__ == "__main__":
    main()
