#!/usr/bin/env python
"""NeMo Guardrails adapter for the four relation boards.

Imports the shared NeMo adapter (adapt_nemo.py) for its rendering and rail call, then
runs one whole board file per arm. The rule text enters NeMo's policy slot verbatim.

Environment: same as adapt_nemo.py (NEMO_API_BASE, NEMO_API_KEY, NEMO_MODEL, CG_ROOT,
CG_RESULTS).

Usage: adapt_nemo_relmain.py --arm e3_board [--limit 3 --smoke]
"""
import argparse, asyncio, hashlib, json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adapt_nemo as N

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(os.path.dirname(HERE), "data/boards")

BOARDS = {
    "e3_board":   ("priority/conflict_board.jsonl",
                  "e9f6aa4e56a7183cd88e7b4849d8950b", 2908),
    "ib_audience": ("new_relations/audience.jsonl",
                  "7b1b90a4e1864216cf8dffeed2ec4dbf", 2888),
    "ib_window": ("new_relations/window.jsonl",
                  "a498e14f834b2a3950afe5bbb46bbfb8", 2876),
    "ib_kid":    ("new_relations/kid.jsonl",
                  "5a2ce08a9372a2cd4c4864162d40c8f2", 2796),
    "ib_floor":  ("new_relations/floor.jsonl",
                  "0b2d646c68b7c5bcb83aec942840aac9", 2780),
    "e2_board":  ("direction/direction_board.jsonl",
                  "b076eadbe65c5eaee8d5d5f9acaca745", 4888),
    "e2_placebo": ("direction/direction_placebo.jsonl",
                  "f344c20c464d1e6ac3cc4169e3e7fb60", 1258),
    "e1_board":  ("crossed/relation_board.jsonl",
                  "13537ab7f88165d31da0cbf7d87078de", 1286),
}

PRIORITY = ["e3_board", "ib_audience", "ib_window", "ib_kid", "ib_floor",
            "e2_board", "e2_placebo", "e1_board"]
CORPUS_VERSION = "main-corpus relation boards (benign-half boards)"


def load_board(tok):
    rel, _, _ = BOARDS[tok]
    path = os.path.join(WORK, rel)
    h = hashlib.md5(open(path, "rb").read()).hexdigest()
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    seen = set()
    for r in rows:
        assert r["id"] not in seen, f"duplicate id {r['id']}"
        seen.add(r["id"])
    return rows, h, path


class Writer(N.Writer):
    """Same Writer; header provenance = main relation boards."""

    def __init__(self, path, n_expect, corpus_path, corpus_md5_8, rep_n=1):
        import threading
        self.path, self.lock = path, threading.Lock()
        self.done = set()
        if os.path.exists(path):
            with open(path, "rb") as f:
                raw = f.read()
            lines = raw.split(b"\n")
            if lines and lines[-1] == b"":
                lines = lines[:-1]
            keep, dropped = [], 0
            for ln in lines:
                try:
                    d = json.loads(ln)
                    keep.append(ln)
                    if not d.get("_header"):
                        self.done.add(d["id"])
                except Exception:
                    dropped += 1
            with open(path, "wb") as f:
                for ln in keep:
                    f.write(ln + b"\n")
            if dropped:
                print(f"[resume] repaired {path}: dropped {dropped} partial lines, "
                      f"{len(self.done)} done", flush=True)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            hdr = {"_header": True, "guard": "NeMoGuardrails",
                   "framework_version": N.FRAMEWORK_VERSION,
                   "framework_engine": "LLMRails",
                   "rail_form": "input rail (self-check-input wiring) with custom "
                                "check_pending_action action; policy slot in prompts.yml",
                   "backend": "api", "model": N.LLM_MODEL, "endpoint": N.LLM_API_BASE,
                   "sampling": N.SAMPLING, "caliber": N.CALIBER, "pmode_tag": N.CALIBER,
                   "retry": f"<= {N.MAX_ATTEMPTS} identical resends; parse_fail retained",
                   "verdict_map": "rail RailOutcome: allow/deny; deny subdivided by verdict_form",
                   "n": n_expect, "rep": rep_n, "corpus": corpus_path,
                   "corpus_md5_8": corpus_md5_8, "corpus_version": CORPUS_VERSION,
                   "family": "relation_boards_main",
                   "render_mode": "callsurface" if N.CALL_SURFACE else "objective_only",
                   "tstamp": time.time()}
            if N.CALL_SURFACE:
                hdr["call_surface"] = {"form": 'pending_action = objective + "\\n" + LAST '
                                               "assistant tool_calls (corpus serialization)",
                                       "note": "same render as the default path"}
            self.append(json.dumps(hdr, ensure_ascii=False).encode() + b"\n")


async def run_arm(tok, args, ts):
    rows, md5_full, corpus_path = load_board(tok)
    smoke = ".SMOKE" if args.smoke else ""
    cs = ".callsurf" if N.CALL_SURFACE else ".objectiveonly"
    rep = f".rep{args.rep}" if args.rep > 1 else ""
    if getattr(args, "out", ""):
        out = args.out
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    else:
        os.makedirs(N.RESULTS, exist_ok=True)
        out = (f"{N.RESULTS}/src__NeMoGuardrails-0.24.1__gpt-oss-120b__api__{N.CALIBER}__"
               f"oversafety.jsonl{smoke}{cs}.{tok}.{md5_full[:8]}.{ts}{rep}")
    if args.limit:
        rows = rows[: args.limit]
    W = Writer(out, len(rows), corpus_path, md5_full[:8], rep_n=args.rep)
    todo = [r for r in rows if r["id"] not in W.done]
    print(f"[{tok}] corpus={corpus_path} md5={md5_full[:8]} rows={len(rows)} "
          f"todo={len(todo)} out={out}", flush=True)
    if not todo:
        print(f"[{tok}] already complete", flush=True)
        return out, 0, 0
    rails = N.build_rails()
    counters = {"parse_fail": 0, "ok": 0}
    t0 = time.time()
    for i, rec in enumerate(todo, 1):
        row = await N.run_cell(rails, rec, tok, "native", md5_full[:8], args.rep,
                               audit=bool(args.audit))
        W.write(row)
        counters["parse_fail" if row["verdict"] == "parse_fail" else "ok"] += 1
        if i % 25 == 0 or i == len(todo):
            el = time.time() - t0
            eta = el / i * (len(todo) - i)
            print(f"[{tok}] {i}/{len(todo)} ok={counters['ok']} "
                  f"parse_fail={counters['parse_fail']} el={el:.0f}s eta={eta/60:.1f}m "
                  f"last={row['id']}:{row['verdict']}", flush=True)
    print(f"[{tok}] DONE ok={counters['ok']} parse_fail={counters['parse_fail']}", flush=True)
    return out, counters["ok"], counters["parse_fail"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True, choices=list(BOARDS))
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--ts", default=time.strftime("%Y%m%dT%H%M"))
    ap.add_argument("--out", default="", help="exact output path")
    args = ap.parse_args()
    out, ok, pf = asyncio.run(run_arm(args.arm, args, args.ts))
    print(f"SUMMARY {args.arm}.rep{args.rep}: out={out} ok={ok} parse_fail={pf}", flush=True)


if __name__ == "__main__":
    main()
