#!/usr/bin/env python3
"""Extract the reason text a guardrail emitted for each case.

The output is one JSONL row per result row, keeping the fields needed by a reason
coding pass. Coding is a separate step; the coding prompt is in
scoring/reason_coding_prompt.md.

Usage:
  python3 scoring/extract_reasons.py --result ToolEmu=results/toolemu/native_bt.jsonl \
      --out results/toolemu/reasons_bt.jsonl
"""
import argparse
import json
import os


def reason_of(row):
    for key in ("reason", "raw_response", "raw", "raw_output", "rationale",
                "analysis", "parsed", "explanation"):
        value = row.get(key)
        if value:
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False)
            return str(value)
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--result", action="append", required=True,
                    help="GUARD=PATH; repeat for several files")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as out:
        for item in args.result:
            if "=" not in item:
                raise SystemExit(f"expected GUARD=PATH, got {item!r}")
            guard, path = item.split("=", 1)
            for line in open(path, encoding="utf-8", errors="replace"):
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if row.get("_header") or row.get("verdict") in (None, "parse_fail", "error"):
                    continue
                out.write(json.dumps({
                    "guard": guard,
                    "tier": row.get("name_token") or row.get("name_grade") or "",
                    "half": row.get("half"),
                    "cell_id": row.get("cg_cell_id") or row.get("cell_id"),
                    "id": row.get("id"),
                    "verdict": row.get("verdict"),
                    "reason": reason_of(row),
                    "model": row.get("model"),
                }, ensure_ascii=False) + "\n")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
