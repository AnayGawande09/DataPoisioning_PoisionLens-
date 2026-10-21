"""CLI tool for audit log verification."""

import argparse
import sys
from poisonlens.audit.log import verify_audit_log


def main():
    parser = argparse.ArgumentParser(description="PoisonLens Audit Log Verification CLI")
    parser.add_argument("--verify", type=str, required=True, help="Path to audit log JSONL file to verify")
    args = parser.parse_args()

    is_valid, bad_idx, msg = verify_audit_log(args.verify)
    if is_valid:
        print(f"[OK] {msg}")
        sys.exit(0)
    else:
        print(f"[FAIL] {msg}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
