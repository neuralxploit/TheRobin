#!/usr/bin/env python3
"""
AI Pentest Console — Entry Point

Usage:
  python main.py
  python main.py --target http://example.com
  python main.py --model kimi-k2.5:cloud
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
  python main.py -m kimi-k2.5:cloud -t https://target.com
        """,
    )
    parser.add_argument(
        "--target", "-t",
        metavar="URL",
        help="Target URL (webapp) or domain (osint/full mode)",
    )
    parser.add_argument(
        "--model", "-m",
        metavar="MODEL",
        help="Ollama model (e.g. kimi-k2.5:cloud, glm-4.7:cloud)",
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
    args = parser.parse_args()

    try:
        app = App(
            model_override=args.model,
            target=args.target,
            username=args.username,
            password=args.password,
            scope=args.scope,
            mode=args.mode,
            tor=args.tor,
        )
        app.run()
    except KeyboardInterrupt:
        print("\n\nExiting. Stay ethical.")
        sys.exit(0)


if __name__ == "__main__":
    main()
