#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from core.env_loader import load_dotenv_if_present


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SkillAttack unified experiment entrypoint.",
        usage="python main.py [main|compare] [mode-specific args]",
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="main",
        choices=["main", "compare"],
        help="Experiment mode to run.",
    )
    parser.add_argument(
        "mode_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the selected mode.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    load_dotenv_if_present()

    from experiments import compare_run, main_run

    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    args = parser.parse_args(raw_argv)

    if args.mode == "compare":
        return compare_run.main(args.mode_args)
    return main_run.main(args.mode_args)


if __name__ == "__main__":
    raise SystemExit(main())
