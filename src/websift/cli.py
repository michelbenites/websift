"""Command line interface for websift.

Usage: ws.py scan PATH

Exit codes: 0 when the scan finds nothing, 1 when it finds something,
2 for a usage error (no command, an unknown command, a missing PATH,
or a PATH that is not a folder). A usage error always prints its
message to stderr. A Python file with a syntax error is skipped with
a warning on stderr, and does not change the exit code by itself.
"""

import argparse
import sys
from dataclasses import dataclass, field

from . import rules  # noqa: F401  (importing this registers the rules)
from .discovery import discover_python_files, is_folder, read_source
from .registry import run_rules
from .report import format_syntax_warning, format_usage_error, write_report, write_warnings

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

_PROG = "ws"
_DESCRIPTION = "websift reads Python source and reports security problems it finds in the code."
_EPILOG = "exit codes: 0 nothing found, 1 findings reported, 2 usage error"


class _ArgumentError(Exception):
    """Raised instead of letting argparse call sys.exit directly, so
    main() can turn a bad command line into a normal return value."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _ArgumentError(message)


@dataclass
class ScanResult:
    """The outcome of scanning one folder."""

    findings: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def exit_code(self):
        return EXIT_FINDINGS if self.findings else EXIT_OK


def build_parser():
    parser = _Parser(prog=_PROG, description=_DESCRIPTION, epilog=_EPILOG)
    subparsers = parser.add_subparsers(dest="command", metavar="command")
    subparsers.required = True

    scan_parser = subparsers.add_parser("scan", help="scan a project folder for security problems")
    scan_parser.add_argument("path", help="folder to scan")

    return parser


def main(argv=None):
    """Run the command line interface. Returns the process exit code."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except _ArgumentError as exc:
        return _usage_error(str(exc))

    if args.command == "scan":
        return _run_scan(args.path)

    return _usage_error("unknown command: " + str(args.command))


def _usage_error(message):
    print(format_usage_error(message), file=sys.stderr)
    return EXIT_USAGE


def _run_scan(path):
    if not is_folder(path):
        return _usage_error(path + " is not a folder")

    result = _scan_folder(path)

    write_warnings(result.warnings, sys.stderr)
    write_report(result.findings, sys.stdout)

    return result.exit_code


def _scan_folder(path):
    """Scan every Python file under path. Returns a ScanResult.

    A file with a syntax error contributes a warning instead of
    findings, and scanning continues with the remaining files.
    """
    result = ScanResult()
    for file_path in discover_python_files(path):
        source = read_source(file_path)
        file_findings, error = run_rules(file_path, source)
        if error is not None:
            result.warnings.append(format_syntax_warning(file_path, error))
            continue
        result.findings.extend(file_findings)
    return result


if __name__ == "__main__":
    sys.exit(main())
