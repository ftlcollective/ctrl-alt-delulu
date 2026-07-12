"""
Ctrl+Alt+Delulu — Parts 01 + 02 combined pipeline
Owner: Sumaira

Runs the Core Scanner (Part 01) on a target codebase, then feeds every
finding through the AI Explanation Layer (Part 02) to produce beginner
-friendly explanations.

Usage:
    export ANTHROPIC_API_KEY="your-key-here"
    python main.py path/to/codebase [--config auto|path/to/rules.yaml]
"""

import argparse
import json
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()  # picks up NVIDIA_API_KEY etc. from a local .env file, if present
except ImportError:
    pass

sys.path.insert(0, "core")
sys.path.insert(0, "ai-layer")

from scanner import scan, save_findings          # Part 01
from explain import explain_findings, save_explanations, print_explanation  # Part 02


def main():
    parser = argparse.ArgumentParser(description="Scan a codebase and explain the findings in plain language.")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument(
        "--config",
        default="auto",
        help='Semgrep config: "auto" (registry, needs internet) or a path to a local rules.yaml',
    )
    parser.add_argument("--skip-ai", action="store_true", help="Only run the scanner, skip AI explanations")
    args = parser.parse_args()

    print(f"🔍 Scanning {args.target} with Semgrep (config: {args.config}) ...")
    findings = scan(args.target, config=args.config)
    save_findings(findings, "findings.json")
    print(f"   Found {len(findings)} issue(s). Raw findings saved to findings.json\n")

    if not findings:
        print("Nothing to explain — clean scan! 🎉")
        return

    if args.skip_ai:
        return

    print(f"🤖 Explaining {len(findings)} finding(s) with AI ...")
    raw_findings = [f.to_dict() for f in findings]
    explanations = explain_findings(raw_findings)

    for exp in explanations:
        print_explanation(exp)

    save_explanations(explanations, "explanations.json")
    print(f"\n\n✅ Saved {len(explanations)} explanation(s) to explanations.json")


if __name__ == "__main__":
    main()
