"""Command-line entrypoint for the ReconEveryThings engine."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

from rec_cli import TOOL_NAME, __version__
from rec_cli.engine import ReconEngine, ReconError, run_json
from rec_cli.schema import Mode, ReconResult
from rec_cli.utils.logger import Logger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recn",
        description=(
            "ReconEveryThings: chained infrastructure and OSINT reconnaissance. "
            "Use only against assets you are authorized to assess."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  recn -t example.com -m infra --stealth -o result.json\n"
            "  recn -t example.com -m infra --modules whois,subdomains,techstack\n"
            "  recn -t example.com -m infra --modules techstack,waf\n"
            "  recn -t example.com -m infra --modules fuzz --wordlist dirs.txt\n"
            "  recn -t jane.doe@example.com -m osint --stealth -o person.json\n"
        ),
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="target domain, IP/CIDR, email, username, URL, or person name",
    )
    parser.add_argument(
        "-m",
        "--mode",
        required=True,
        choices=("infra", "osint"),
        help="operation mode: infra or osint",
    )
    parser.add_argument(
        "--modules",
        default="all",
        help=(
            "comma-separated modules (for example whois,subdomains,techstack,waf); "
            "defaults to all modules for the selected mode"
        ),
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        help="enable jittered pacing, passive port data, and header rotation",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the validated JSON result to this file",
    )
    parser.add_argument(
        "--skip-liveness",
        action="store_true",
        help=(
            "skip the httpx liveness pre-check and probe every collected "
            "host URL directly"
        ),
    )
    parser.add_argument(
        "--wordlist",
        metavar="FILE",
        help=(
            "custom directory wordlist that replaces the bundled directory "
            "list; sensitive file discovery still uses the bundled list"
        ),
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP or SOCKS5 proxy URL for outbound HTTP requests",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress banner and progress logs; print raw JSON or a summary",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {__version__}",
    )
    return parser


def _write_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_dir():
        raise IsADirectoryError(f"output path is a directory: {path}")
    serialized = json.dumps(payload, indent=2, ensure_ascii=True) + "\n"
    file_descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(file_descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _summary(result: ReconResult) -> str:
    hosts = result.infra_data.hosts
    vulnerabilities = sum(len(host.potential_vulnerabilities) for host in hosts)
    endpoints = sum(len(host.js_findings.extracted_endpoints) for host in hosts)
    secrets = sum(len(host.js_findings.potential_secrets) for host in hosts)
    paths = sum(len(host.path_findings) for host in hosts)
    sensitive_paths = sum(
        1
        for host in hosts
        for finding in host.path_findings
        if finding.sensitive
    )
    identity = result.osint_data.target_identity
    return (
        f"target={result.meta.target} mode={result.meta.mode.value} "
        f"stealth={str(result.meta.stealth_enabled).lower()} "
        f"hosts={len(hosts)} asns={len(result.infra_data.whois_asn.asns)} "
        f"vulns={vulnerabilities} paths={paths} sensitive_paths={sensitive_paths} "
        f"js_endpoints={endpoints} secrets={secrets} "
        f"emails={len(identity.emails)} social={len(result.osint_data.social_profiles)} "
        f"repos={len(result.osint_data.git_findings)} "
        f"documents={len(result.osint_data.document_metadata)} "
        f"pivots={len(result.pivots_suggested)}"
    )


async def _execute(args: argparse.Namespace, logger: Logger) -> ReconResult:
    modules = [part for part in args.modules.split(",") if part.strip()]
    engine = ReconEngine(
        target=args.target,
        mode=Mode(args.mode),
        modules=modules,
        stealth=bool(args.stealth),
        skip_liveness=bool(args.skip_liveness),
        wordlist=args.wordlist,
        proxy=args.proxy,
        logger=logger,
    )
    return await engine.run()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = Logger(quiet=bool(args.quiet), stream=sys.stdout)
    started = time.monotonic()

    if not args.quiet:
        logger.banner(args.target, args.mode, bool(args.stealth))

    try:
        result = asyncio.run(_execute(args, logger))
    except ReconError as exc:
        logger.error(str(exc))
        return 2
    except KeyboardInterrupt:
        logger.error("interrupted")
        return 130
    except Exception as exc:
        logger.error(f"execution failed: {type(exc).__name__}: {exc}")
        return 1

    elapsed = time.monotonic() - started
    payload = run_json(result)
    output_path = Path(args.output).expanduser() if args.output else None
    if output_path:
        try:
            _write_atomic(output_path, payload)
        except Exception as exc:
            logger.error(f"could not write output file: {exc}")
            return 1

    if args.quiet:
        if output_path:
            logger.summary(f"{_summary(result)} elapsed={elapsed:.2f}s")
        else:
            print(json.dumps(payload, indent=2, ensure_ascii=True))
    else:
        logger.summary(_summary(result))
        logger.summary(f"elapsed={elapsed:.2f}s")
        if output_path:
            logger.summary(f"output={output_path.resolve()}")
        else:
            logger.info("no output file requested; use -o FILE for machine-readable JSON")
    return 0


if __name__ == "__main__":
    GOLD = "\033[38;2;255;215;0m"
    RESET = "\033[0m"

    banner = r"""   ___                    ____                  __  __   _            
  / _ \___ _______  ___  / __/  _____ ______ __/ /_/ /  (_)__  ___ ____
 / , _/ -_) __/ _ \/ _ \/ _/| |/ / -_) __/ // / __/ _ \/ / _ \/ _ `(_-<
/_/|_|\__/\__/\___/_//_/___/|___/\__/_/  \_, /\__/_//_/_/_//_/\_, /___/
                                        /___/                /___/     """

    print(f"{GOLD}{banner}{RESET}")
    raise SystemExit(main())
