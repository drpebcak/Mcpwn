#!/usr/bin/env python3
"""Mcpwn - MCP Security Testing Framework"""

import argparse
import logging
import sys

from core import MCPPentester

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def main():
    parser = argparse.ArgumentParser(description="MCP Security Testing Framework")
    parser.add_argument("--version", action="version", version="Mcpwn 1.0")
    parser.add_argument(
        "--safe-mode", action="store_true", help="Skip destructive tests"
    )
    parser.add_argument("--tags", nargs="+", help="Only run specific test tags")
    parser.add_argument(
        "--timeout", type=int, default=10, help="Request timeout in seconds"
    )
    parser.add_argument("--parallel", action="store_true", help="Use parallel flooding")
    parser.add_argument("--output-json", type=str, help="Export findings as JSON")
    parser.add_argument("--output-html", type=str, help="Export findings as HTML")
    parser.add_argument(
        "--output-sarif", type=str, help="Export findings as SARIF (for CI/CD)"
    )
    parser.add_argument(
        "--rce-only", action="store_true", help="Focus on RCE detection only (fast)"
    )
    parser.add_argument(
        "--quick", action="store_true", help="Quick scan with minimal payloads"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "auto"],
        default="auto",
        help="Transport type (auto-detected by default)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retry attempts for HTTP requests (default: 3)",
    )
    parser.add_argument(
        "--initial-backoff",
        type=float,
        default=0.5,
        help="Initial backoff delay in seconds for retries (default: 0.5)",
    )
    parser.add_argument(
        "--backoff-multiplier",
        type=float,
        default=2.0,
        help="Multiplier for exponential backoff (default: 2.0)",
    )
    parser.add_argument(
        "--max-backoff",
        type=float,
        default=10.0,
        help="Maximum backoff delay in seconds (default: 10.0)",
    )
    parser.add_argument(
        "target", nargs=argparse.REMAINDER, help="MCP server command or HTTP URL"
    )

    args = parser.parse_args()

    logger = logging.getLogger("mcpwn")

    if not args.target:
        logger.error("Error: MCP server command or URL required")
        parser.print_help()
        return 1

    if args.timeout <= 0:
        logger.error("Timeout must be positive")
        return 1

    # Determine transport type and target
    if len(args.target) == 1 and (
        args.target[0].startswith("http://") or args.target[0].startswith("https://")
    ):
        # URL provided
        target = args.target[0]
        transport_type = "http" if args.transport == "auto" else args.transport
    else:
        # Command provided
        target = args.target
        transport_type = "stdio" if args.transport == "auto" else args.transport

    if transport_type == "http" and not isinstance(target, str):
        logger.error("HTTP transport requires URL, not command")
        return 1

    if (
        transport_type == "stdio"
        and isinstance(target, str)
        and target.startswith("http")
    ):
        logger.error("Stdio transport requires command, not URL")
        return 1

    try:
        timeout = 5 if args.quick else args.timeout

        # Validate retry configuration
        if args.max_retries < 0:
            logger.error("Max retries must be non-negative")
            return 1
        if args.initial_backoff <= 0:
            logger.error("Initial backoff must be positive")
            return 1
        if args.backoff_multiplier < 1:
            logger.error("Backoff multiplier must be >= 1")
            return 1
        if args.max_backoff <= 0:
            logger.error("Max backoff must be positive")
            return 1

        pentester = MCPPentester(
            target,
            config={
                "safe_mode": args.safe_mode,
                "tags": args.tags,
                "timeout": timeout,
                "parallel": args.parallel,
                "output_json": args.output_json,
                "output_html": args.output_html,
                "output_sarif": args.output_sarif,
                "rce_only": args.rce_only,
                "quick": args.quick,
                "max_retries": args.max_retries,
                "initial_backoff": args.initial_backoff,
                "backoff_multiplier": args.backoff_multiplier,
                "max_backoff": args.max_backoff,
            },
            transport_type=transport_type,
        )
        pentester.run()
    except Exception as e:
        logger.critical("Fatal error: %s", e, exc_info=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
