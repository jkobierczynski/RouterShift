# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Command line: routershift convert | parse | platforms."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .convert import PLATFORMS, convert, parse
from .errors import RoutershiftError
from .names import read_port_map


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _write(path: Optional[str], text: str) -> None:
    if not path or path == "-":
        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="routershift", description="Convert switch and router configurations.")
    parser.add_argument("--version", action="version", version=f"routershift {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    conv = sub.add_parser("convert", help="convert a configuration to another platform")
    conv.add_argument("input", help="configuration file, or - for standard input")
    conv.add_argument("--from", dest="source", required=True, choices=sorted(PLATFORMS))
    conv.add_argument("--to", dest="target", required=True, choices=sorted(PLATFORMS))
    conv.add_argument("-o", "--output", help="where to write the configuration (default: standard output)")
    conv.add_argument("--report", help="where to write the report (default: standard error)")
    conv.add_argument("--report-format", choices=("text", "json"), default="text")
    conv.add_argument("--port-map", help="file of 'source port = target port' lines")

    prs = sub.add_parser("parse", help="show the vendor-neutral model of a configuration as JSON")
    prs.add_argument("input")
    prs.add_argument("--from", dest="source", required=True, choices=sorted(PLATFORMS))

    sub.add_parser("platforms", help="list the platforms")

    args = parser.parse_args(argv)
    try:
        if args.command == "platforms":
            for key, title in PLATFORMS.items():
                print(f"{key:8} {title}")
        elif args.command == "parse":
            sys.stdout.write(parse(_read(args.input), args.source).to_json())
        else:
            port_map = read_port_map(_read(args.port_map)) if args.port_map else None
            output, report = convert(_read(args.input), args.source, args.target, port_map)
            _write(args.output, output)
            text = report.to_json() if args.report_format == "json" else report.to_text()
            if args.report:
                _write(args.report, text)
            else:
                sys.stderr.write(text)
    except (RoutershiftError, OSError) as exc:
        print(f"routershift: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
