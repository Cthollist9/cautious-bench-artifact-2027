#!/usr/bin/env python
"""AGrail adapter for the four relation boards.

Imports the shared AGrail adapter (adapt_agrail.py) for its rendering and transport,
then runs one whole board file per arm. The rule text enters agent_usage_principles
verbatim; the boards differ only in the relation values they carry.

Environment: same as adapt_agrail.py (AGRAIL_API_BASE, AGRAIL_API_KEY, AGRAIL_MODEL,
AGRAIL_EMB_MODEL, CG_ROOT, AGRAIL_ROOT, CG_RESULTS).
"""
import argparse, hashlib, json, os, sys, threading, time, traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adapt_agrail as A          # module import runs its env hygiene; no side effects

WORK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data/boards")

# board path under data/boards -> (file, md5, expected rows)
RELATION_MD5 = {
    "e1_board":    ("crossed/relation_board.jsonl", "13537ab7f88165d31da0cbf7d87078de", 1286),
    "e2_board":    ("direction/direction_board.jsonl", "b076eadbe65c5eaee8d5d5f9acaca745", 4888),
    "e2_placebo":  ("direction/direction_placebo.jsonl", "f344c20c464d1e6ac3cc4169e3e7fb60", 1258),
    "e3_board":    ("priority/conflict_board.jsonl", "e9f6aa4e56a7183cd88e7b4849d8950b", 2908),
    "ib_audience": ("new_relations/audience.jsonl", "7b1b90a4e1864216cf8dffeed2ec4dbf", 2888),
    "ib_floor":    ("new_relations/floor.jsonl", "0b2d646c68b7c5bcb83aec942840aac9", 2780),
    "ib_kid":      ("new_relations/kid.jsonl", "5a2ce08a9372a2cd4c4864162d40c8f2", 2796),
    "ib_window":   ("new_relations/window.jsonl", "a498e14f834b2a3950afe5bbb46bbfb8", 2876),
}


def load_whole(key):
    """Whole-file load with the required fields."""
    rel, _, _ = RELATION_MD5[key]
    path = os.path.normpath(os.path.join(WORK, rel))
    h = hashlib.md5(open(path, "rb").read()).hexdigest()
    rows = [json.loads(l) for l in open(path, encoding="utf-8")]
    need = ("id", "profile", "contents", "objective", "half", "declared_axis",
            "family", "gt_label", "oracle_verdict")
    for r in rows:
        miss = [f for f in need if f not in r]
        assert not miss, f"{path}: row {r.get('id')} missing {miss}"
        r.setdefault("cg_cell_id", r.get("cell_id", r["id"]))
    return rows, h, path


def run_family(key, args, ts):
    rows, md5_full, corpus_path = load_whole(key)
    arm = f"agr_{key}"
    smoke = ".SMOKE" if args.smoke else ""
    cs = ".callsurf" if A.CALL_SURFACE else ".objectiveonly"
    if getattr(args, "out", ""):
        out = args.out
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    else:
        os.makedirs(A.RESULTS, exist_ok=True)
        out = (f"{A.RESULTS}/"
               f"src__AGrail__gpt-oss-120b__api__{A.CALIBER}__oversafety.jsonl{smoke}{cs}.{arm}.{md5_full[:8]}.{ts}")
    if args.limit:
        rows = rows[: args.limit]
    print(f"[{arm}] corpus={corpus_path} md5={md5_full[:8]} whole-file rows={len(rows)} "
          f"out={out}", flush=True)
    G = A.load_guardrail()
    emb = A.load_embedding()
    W = A.Writer(out, arm, len(rows), corpus_path, md5_full[:8])
    todo = [r for r in rows if r["id"] not in W.done]
    if not todo:
        print(f"[{arm}] already complete ({len(W.done)} rows)", flush=True)
        return out, 0, 0
    counters = {"parse_fail": 0, "ok": 0}

    def work(rec):
        row = A.run_row(G, emb, rec, arm, "native", md5_full[:8], audit=False)
        W.write(row)
        return row

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(work, r): r["id"] for r in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                row = fut.result()
            except Exception:
                row = {"id": futs[fut], "verdict": "parse_fail",
                       "error": traceback.format_exc()[-1600:], "model": None,
                       "endpoint": A.UNI_API_BASE, "arm": arm, "caliber": A.CALIBER,
                       "corpus_md5_8": md5_full[:8], "attempts": A.MAX_ATTEMPTS}
                W.write(row)
            counters["parse_fail" if row["verdict"] == "parse_fail" else "ok"] += 1
            if i % 10 == 0 or i == len(todo):
                el = time.time() - t0
                eta = el / i * (len(todo) - i)
                print(f"[{arm}] {i}/{len(todo)} ok={counters['ok']} parse_fail={counters['parse_fail']} "
                      f"el={el:.0f}s eta={eta/60:.1f}m last={row['id']}:{row['verdict']}", flush=True)
    print(f"[{arm}] DONE rows={len(W.done)+len(todo)} ok={counters['ok']} parse_fail={counters['parse_fail']}", flush=True)
    return out, counters["ok"], counters["parse_fail"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True, help="agr_<key>; keys: " + " ".join(RELATION_MD5))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--ts", default=time.strftime("%Y%m%dT%H%M"))
    ap.add_argument("--out", default="", help="exact output path")
    args = ap.parse_args()
    assert args.workers <= 4, "workers hard cap = 4 (tiered-concurrency ruling)"
    key = args.arm[4:] if args.arm.startswith("agr_") else args.arm
    assert key in RELATION_MD5, f"unknown relation key {key}"
    out, ok, pf = run_family(key, args, args.ts)
    print(f"SUMMARY {args.arm}: out={out} ok={ok} parse_fail={pf}", flush=True)


if __name__ == "__main__":
    main()
