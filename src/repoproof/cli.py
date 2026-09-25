from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .core import current_report, load_config, save_json, snapshot, transition

def _print_report(report: dict) -> None:
    findings = report.get("findings", [])
    print("REPOPROOF")
    print("=" * 64)
    for f in findings:
        symbol = {"VERIFIED": "✓", "CONTRADICTED": "✗", "UNPROVEN": "?"}.get(f["status"], "•")
        print(f"{symbol} {f['section']:<10} {f['id']}: {f['status']}")
        print(f"  {f['statement']}")
        for ev in f.get("evidence", [])[:5]:
            print(f"    - {ev}")
    print("-" * 64)
    print(f"RESULT: {report['result']}")

def main() -> int:
    parser = argparse.ArgumentParser(prog="repoproof", description="Executable repository transition proofs")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--repo", default=".", help="repository path")
    parser.add_argument("--json", dest="json_path", help="write full JSON report")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="check current claims and boundaries")
    sub.add_parser("baseline", help="write .repoproof/baseline.json")
    d = sub.add_parser("diff", help="prove a repository transition")
    d.add_argument("base")
    d.add_argument("head")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    config = load_config(repo)
    if args.command == "check":
        report = current_report(repo, config)
    elif args.command == "baseline":
        report = {"snapshot": snapshot(repo), "result": "BASELINED"}
        save_json(repo / ".repoproof" / "baseline.json", report)
        print(f"Wrote {repo / '.repoproof' / 'baseline.json'}")
        return 0
    else:
        report = transition(repo, config, args.base, args.head)

    if args.json_path:
        save_json(Path(args.json_path), report)
    _print_report(report)
    return 2 if report["result"] == "REVIEW_REQUIRED" else 0

if __name__ == "__main__":
    raise SystemExit(main())
