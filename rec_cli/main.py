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


def _thread_count(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("threads must be an integer") from exc
    if not 1 <= number <= 64:
        raise argparse.ArgumentTypeError("threads must be between 1 and 64")
    return number


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
            "  recn -t example.com -m infra --modules vhost --vhost-wordlist hosts.txt\n"
            "  recn -t example.com -m infra --modules wayback -o archive.json\n"
            "  recn -t example.com -m infra -sm fuzz,vhost -o passive.json\n"
            "  recn -t example.com -m infra --modules assets -o assets.json\n"
            "  recn -t example.com -m infra --threads 16 -o fast.json\n"
            "  recn -t jane.doe@example.com -m osint --stealth -o person.json\n"
            "  recn -t jane.doe -m osint --modules username --strict 1 -o handles.json\n"
            "  recn -t jane.doe@example.com -m osint --modules breach -o breaches.json\n"
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
        "-sm",
        "--skip-modules",
        metavar="LIST",
        help=(
            "comma-separated modules to exclude from the selected set "
            "(for example fuzz,vhost); all other modules still run"
        ),
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        help="enable jittered pacing, passive port data, and header rotation",
    )
    parser.add_argument(
        "--strict",
        metavar="LEVEL",
        type=int,
        choices=(0, 1),
        default=None,
        help=(
            "OSINT match strictness: 0 keeps the current search behavior; "
            "1 requires stronger identity evidence and suppresses weak or "
            "blocked matches (default: REC_STRICT or 0)"
        ),
    )
    parser.add_argument(
        "--threads",
        metavar="N",
        type=_thread_count,
        help=(
            "active-mode HTTP worker count (1-64) and request rate floor; "
            "ignored in stealth mode, which stays capped and jittered"
        ),
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
            "list; the bundled sensitive file and API lists still run"
        ),
    )
    parser.add_argument(
        "--vhost-wordlist",
        metavar="FILE",
        help=(
            "custom virtual host label list that replaces the bundled vhost "
            "wordlist for the vhost phase"
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
    assets = [finding for host in hosts for finding in host.assets]
    asset_js = sum(1 for finding in assets if finding.kind == "js")
    asset_css = sum(1 for finding in assets if finding.kind == "css")
    asset_html = sum(1 for finding in assets if finding.kind == "html")
    vhosts = sum(len(host.vhosts) for host in hosts)
    archived = sum(len(host.historical_urls) for host in hosts)
    identity = result.osint_data.target_identity
    return (
        f"target={result.meta.target} mode={result.meta.mode.value} "
        f"stealth={str(result.meta.stealth_enabled).lower()} "
        f"strict={result.meta.strict_level} "
        f"strict_filtered={result.osint_data.strict_filtered} "
        f"hosts={len(hosts)} asns={len(result.infra_data.whois_asn.asns)} "
        f"vulns={vulnerabilities} paths={paths} sensitive_paths={sensitive_paths} "
        f"assets={len(assets)} (js={asset_js} css={asset_css} html={asset_html}) "
        f"vhosts={vhosts} wayback={archived} "
        f"js_endpoints={endpoints} secrets={secrets} "
        f"emails={len(identity.emails)} social={len(result.osint_data.social_profiles)} "
        f"username_matches={result.osint_data.username_enum.matches} "
        f"breaches={len(result.osint_data.breach.findings)} "
        f"repos={len(result.osint_data.git_findings)} "
        f"documents={len(result.osint_data.document_metadata)} "
        f"pivots={len(result.pivots_suggested)}"
    )


async def _execute(args: argparse.Namespace, logger: Logger) -> ReconResult:
    modules = [part for part in args.modules.split(",") if part.strip()]
    skip_modules = (
        [part for part in args.skip_modules.split(",") if part.strip()]
        if args.skip_modules
        else None
    )
    engine = ReconEngine(
        target=args.target,
        mode=Mode(args.mode),
        modules=modules,
        skip_modules=skip_modules,
        stealth=bool(args.stealth),
        strict=args.strict,
        skip_liveness=bool(args.skip_liveness),
        wordlist=args.wordlist,
        vhost_wordlist=args.vhost_wordlist,
        threads=args.threads,
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
    raise SystemExit(main())
