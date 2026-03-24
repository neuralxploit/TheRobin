#!/usr/bin/env python3
"""
AI Pentest Console — Entry Point

Usage:
  python main.py
  python main.py --target http://example.com
  python main.py --model glm-5:cloud
  python main.py --target http://example.com --model deepseek-v3.1:671b-cloud
"""

import argparse
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

from app import App


def main():
    parser = argparse.ArgumentParser(
        prog="pentest-console",
        description="AI Web Application Penetration Testing Console",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py -t https://target.com
  python main.py -t https://target.com -u admin -p secret123
  python main.py -t target.com --mode osint
  python main.py -t https://target.com --mode full -s target.com,api.target.com
  python main.py -m glm-5:cloud -t https://target.com
  python main.py -m lmstudio:qwen2.5-coder-32b -t https://target.com
  python main.py -T targets.txt --mode full
        """,
    )
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "--target", "-t",
        metavar="URL",
        help="Target URL (webapp) or domain (osint/full mode)",
    )
    target_group.add_argument(
        "--targets-file", "-T",
        metavar="FILE",
        help="File containing target URLs (one per line). Runs each target sequentially.",
    )
    parser.add_argument(
        "--model", "-m",
        metavar="MODEL",
        help="Model name: Ollama (glm-4.7:cloud), LM Studio (lmstudio:model-name), or Claude (claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--username", "-u",
        metavar="USER",
        help="Username for authentication testing",
    )
    parser.add_argument(
        "--password", "-p",
        metavar="PASS",
        help="Password for authentication testing",
    )
    parser.add_argument(
        "--scope", "-s",
        metavar="DOMAINS",
        help="Comma-separated in-scope domains/IPs (e.g. target.com,api.target.com)",
    )
    parser.add_argument(
        "--mode",
        choices=["webapp", "osint", "full"],
        default="webapp",
        help="Engagement mode: webapp (default), osint (passive only), full (osint + webapp)",
    )
    parser.add_argument(
        "--tor",
        action="store_true",
        help="Route HTTP requests through Tor (SOCKS5 on localhost:9050)",
    )
    parser.add_argument(
        "--headers",
        metavar="HEADERS",
        help="Custom headers for all requests (e.g. 'X-Bug-Bounty: HackerOne-user')",
    )
    args = parser.parse_args()

    # Collect targets — either single URL or from file
    targets = []
    if args.targets_file:
        targets_path = Path(args.targets_file)
        if not targets_path.is_file():
            print(f"Error: targets file not found: {args.targets_file}")
            sys.exit(1)
        targets = [
            line.strip() for line in targets_path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not targets:
            print(f"Error: no targets found in {args.targets_file}")
            sys.exit(1)
        print(f"Loaded {len(targets)} target(s) from {args.targets_file}")
        if args.username or args.password:
            print(f"WARNING: Credentials will be sent to ALL {len(targets)} targets")
    else:
        targets = [args.target] if args.target else [None]

    try:
        for i, target in enumerate(targets):
            if len(targets) > 1:
                print(f"\n{'='*60}")
                print(f"  Target {i+1}/{len(targets)}: {target}")
                print(f"{'='*60}\n")
            app = App(
                model_override=args.model,
                target=target,
                username=args.username,
                password=args.password,
                scope=args.scope,
                mode=args.mode,
                tor=args.tor,
                headers=args.headers,
                batch=bool(args.targets_file),
            )
            app.run()
    except KeyboardInterrupt:
        print("\n\nExiting. Stay ethical.")
        sys.exit(0)


if __name__ == "__main__":
    main()
