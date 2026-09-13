#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from codegraph.remediation.scoped_verification import verify_candidate  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify one remediation candidate with target-only OPA policy evidence; does not apply changes."
    )
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument("--source", required=True, help="Workspace-relative Java source path")
    parser.add_argument("--method", required=True, help="Source declaration selector, e.g. demo.Crypto#hash(String[])")
    parser.add_argument("--candidate", required=True, help="File containing the replacement method declaration")
    parser.add_argument("--rule-id", required=True)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--expected-policy-sha256")
    parser.add_argument("--policy-dir")
    parser.add_argument("--work-dir")
    args = parser.parse_args(argv)

    result = verify_candidate(
        workspace_root=args.workspace_root,
        source=args.source,
        method_selector=args.method,
        candidate=args.candidate,
        rule_id=args.rule_id,
        expected_source_sha256=args.expected_source_sha256,
        expected_policy_sha256=args.expected_policy_sha256,
        policy_dir=args.policy_dir,
        work_dir=args.work_dir,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "POLICY_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
