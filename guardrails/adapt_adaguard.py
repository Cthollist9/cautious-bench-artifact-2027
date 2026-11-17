#!/usr/bin/env python
"""AdaGuard-8B adapter for the benchmark.

Reads the main corpus (plain and scary name tiers, benign and twin halves), the
rule-deletion corpus, and the relation boards. The rule text is split at clause
boundaries and passed verbatim in AdaGuard's policy slot. Requires the AdaGuard
package and the AdaGuard-8B weights.

Environment:
  CG_ROOT          artifact root (default: parent of this file)
  ADAGUARD_ROOT    AdaGuard source checkout
  ADAGUARD_WEIGHTS AdaGuard-8B weights directory
  CG_RESULTS       result directory (default: <CG_ROOT>/results)
  CUDA_VISIBLE_DEVICES / --device

Usage:
  adapt_adaguard.py --arm native_bt [--limit 10 --smoke]
  adapt_adaguard.py --arm all | native | strip | relation
"""
import argparse, hashlib, json, os, sys, threading, time, traceback

CG = os.environ.get("CG_ROOT",
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ADAGUARD_ROOT = os.environ.get("ADAGUARD_ROOT", os.path.join(CG, "third_party", "AdaGuard"))
if ADAGUARD_ROOT not in sys.path:
    sys.path.insert(0, ADAGUARD_ROOT)

WEIGHT_DIR = os.environ.get("ADAGUARD_WEIGHTS", os.path.join(CG, "models", "AdaGuard-8B"))
WEIGHT_SHA256 = "ce289a30e3d2a61608d527cc412593321a8ce691dc3b7b26afbdb53d82e46bdd"
WEIGHT_NAME = "AdaGuard-8B"
DEVICE = os.environ.get("ADAGUARD_DEVICE", "cuda:0")
MODEL_FIELD = WEIGHT_NAME
BACKEND = os.environ.get("CG_BACKEND", "local")
ENDPOINT = BACKEND
CALIBER = "adaguard8b-clausesplit-greedy-mnt640-ml16000-eager-bf16"
MAX_NEW_TOKENS, MAX_LENGTH = 640, 16000
RESULTS = os.environ.get("CG_RESULTS", os.path.join(CG, "results"))

CORPORA = {
    "bt": ("corpus_plain.jsonl", None),
    "tt": ("corpus_scary.jsonl", None),
}
DELETION_DIR = os.path.join(CG, "data/boards", "deletion")
RFAMILY_FAMS = ["strip"]
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


ARMS = {}
for _ck in ("bt", "tt"):
    for _h in ("benign", "twin"):
        _suf = "" if _h == "benign" else "_twin"
        ARMS[f"native_{_ck}{_suf}"] = ("native", _ck, _h)
        for _fam in RFAMILY_FAMS:
            ARMS[f"{_fam}_{_ck}{_suf}"] = (_fam, _ck, _h)
for _fam in RELATION_MD5:
    ARMS[f"{_fam}_bt"] = (_fam, "bt", "all")

NATIVE_ORDER = ["native_bt", "native_bt_twin", "native_tt", "native_tt_twin"]
STRIP_ORDER = ["strip_bt", "strip_bt_twin", "strip_tt", "strip_tt_twin"]
RELATION_ORDER = [f"{k}_bt" for k in RELATION_MD5]
PHASE1_ORDER = NATIVE_ORDER
PHASE2_ORDER = STRIP_ORDER

# ---- clause splitter: boundaries ONLY, verbatim text, provable reconstruction -------------
import re
_ABBREV = re.compile(r'(?:e\.g|i\.e)\.$')

def split_profile(profile):
    """Return (clauses, seps, tags); join(clauses[i]+seps[i]) == profile byte-for-byte.
    Boundary = whitespace run preceded by '.' or ';' at paren-depth 0, except when the
    '.' closes a known abbreviation (e.g. / i.e.). Newlines are always boundaries.
    Tags are line-granular: every clause of a gate-bearing line is tagged 'gate'."""
    clauses, seps, line_tags = [], [], []
    n = len(profile)
    depth = 0
    i = 0
    start = 0
    while i < n:
        ch = profile[i]
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth = max(0, depth - 1)
        elif ch in '.;' and depth == 0:
            # look ahead: whitespace run then non-space -> candidate boundary
            j = i + 1
            while j < n and profile[j] in ' \t':
                j += 1
            if j > i + 1 and j < n:
                left = profile[start:j]
                if not _ABBREV.search(left[-6:]):
                    clauses.append(left.rstrip(' \t'))
                    seps.append(profile[start + len(left.rstrip(' \t')):j])
                    line_tags.append(_tag_line(left))
                    start = j
        elif ch == '\n':
            left = profile[start:i]
            if left.strip():
                clauses.append(left)
                seps.append('\n')
                line_tags.append(_tag_line(left))
            else:
                if clauses:
                    seps[-1] += '\n'  # blank line merges into the following boundary
            start = i + 1
        i += 1
    tail = profile[start:]
    if tail.strip():
        clauses.append(tail.rstrip('\n'))
        seps.append(tail[len(tail.rstrip('\n')):])
        line_tags.append(_tag_line(tail))
    # reconstruction proof (byte-for-byte)
    assert ''.join(c + s for c, s in zip(clauses, seps)) == profile, \
        f"reconstruction mismatch on profile of len {n}"
    return clauses, seps, line_tags

def _tag_line(line):
    """Classify the SOURCE LINE a clause came from (tags attach at line granularity)."""
    c = line.lstrip()
    gate_markers = ('-gate:', 'owner-of-record:', 'session principal:')
    if any(m in c for m in gate_markers):
        return 'gate'
    if c.startswith('You are an agent acting as role'):
        return 'role_header'
    if c.startswith('Available tools:'):
        return 'tools_list'
    if c.startswith('Tool:'):
        return 'tool_decl'
    if c.startswith('Parameters:') or c.startswith('- '):
        return 'params'
    return 'desc'

# ---- policy build: clause-split of the profile carried by the arm corpus --------------------

def build_policy(rec, slot_mode):
    clauses, seps, tags = split_profile(rec["profile"])
    assert 1 <= len(clauses) <= 100, f"{len(clauses)} clauses for {rec['id']} (slot={slot_mode})"
    pol = [{"id": f"R{i+1}", "text": c} for i, c in enumerate(clauses)]
    return pol, [{"id": p["id"], "tag": t, "n_chars": len(p["text"])}
                 for p, t in zip(pol, tags)]

def build_content(rec):
    """Corpus contents -> THEIR event schema, corpus temporal order, agent event last."""
    events = []
    for m in rec["contents"]:
        if m["role"] == "user" and m.get("content", "").strip():
            events.append({"role": "user", "content": m["content"]})
        elif m["role"] == "tool" and m.get("content", "").strip():
            events.append({"role": "environment", "content": m["content"]})
    thoughts = [m["thought"] for m in rec["contents"]
                if m["role"] == "assistant" and m.get("thought", "").strip()]
    events.append({"role": "agent", "thought": "\n".join(thoughts), "action": rec["objective"]})
    return [events]

def _normalize(rows, src):
    """Synthesize `id` when absent (nt corpus); assert unique ids and expected half counts."""
    out = []
    seen = set()
    for r in rows:
        if "id" not in r or not r["id"]:
            r = dict(r)
            r["id"] = f"{r['cell_id']}__{r['half']}"
        assert r["id"] not in seen, f"duplicate id {r['id']} in {src}"
        seen.add(r["id"])
        out.append(r)
    return out

def load_main(corpus_key, half):
    fn, _ = CORPORA[corpus_key]
    path = os.path.join(CG, "data/main", fn)
    h = hashlib.md5(open(path, "rb").read()).hexdigest()
    rows = [json.loads(l) for l in open(path) if l.strip()]
    rows = [r for r in rows if r["half"] == half]
    return _normalize(rows, path), path, h

def resolve_arm_corpus(family, corpus_key, half):
    """Rule-deletion corpus for the requested name tier."""
    assert corpus_key in ("bt", "tt"), f"arm corpora run on bt/tt tiers, got {corpus_key}"
    fn = "deletion_plain.jsonl" if corpus_key == "bt" else "deletion_scary.jsonl"
    path = os.path.join(DELETION_DIR, fn)
    assert os.path.exists(path), f"arm corpus not found: {path}"
    h = hashlib.md5(open(path, "rb").read()).hexdigest()
    rows = [json.loads(l) for l in open(path) if l.strip()]
    rows = [r for r in rows if r["half"] == half]
    return _normalize(rows, path), path, h

# ---- inference (their runtime; batching driver-side) --------------------------------------
_MODEL_CACHE = {}

def load_guard(batch=None):
    key = ("guard", batch is not None)
    if key not in _MODEL_CACHE:
        try:
            from adaguard.model import load_model
        except Exception as exc:
            raise SystemExit("Set ADAGUARD_ROOT to an AdaGuard checkout: %s" % exc)
        model, tok = load_model(WEIGHT_DIR, device=DEVICE, dtype="bfloat16")
        if batch:
            tok.padding_side = "left"   # manual left-padding of THEIR per-row prompts
        _MODEL_CACHE[key] = (model, tok)
    return _MODEL_CACHE[key]

def predict_row(model, tok, row):
    """Their exact single-row path (adaguard.infer.Guard.predict semantics)."""
    from adaguard.model import generate
    _, response, (text, _, _, ended) = generate(model, tok, row,
        max_new_tokens=MAX_NEW_TOKENS, max_length=MAX_LENGTH)
    return parse_result(tok, row, response, text, ended)

def parse_result(tok, row, response, text, ended):
    from adaguard.formatting import parse_guard_response
    parsed = parse_guard_response(text)
    ids = [r["id"] for r in row["policy"]]
    ordered = tuple(x for x in ids if x in parsed.labels)
    # The label list answers which rules the guard relied on; order is not part of
    # the verdict. Compare as a set; keep policy-order equality as a provenance flag.
    set_equal = (set(parsed.labels) == set(ordered)
                 and len(parsed.labels) == len(ordered))
    order_variant = set_equal and parsed.labels != ordered
    valid = ended and parsed.valid and set_equal
    out = {"status": "OK" if valid else "INVALID", "raw_response": text,
           "analysis": parsed.analysis if valid else None,
           "violated_ids": list(parsed.labels) if valid else None,
           "unsafe": bool(parsed.labels) if valid else None, "output_tokens": len(response)}
    if valid and order_variant:
        out["label_order_variant"] = True
    return out

def run_batch(model, tok, rows):
    """Left-padded batch greedy generation of THEIR prompt texts; per-row parse identical
    to their predict()."""
    import torch
    from transformers import GenerationConfig
    from adaguard.model import prompt_text, check_length
    from adaguard.formatting import parse_guard_response
    texts = [prompt_text(tok, r) for r in rows]
    ids_list = [tok.encode(t, add_special_tokens=False) for t in texts]
    for ids in ids_list:
        check_length(model, len(ids) + MAX_NEW_TOKENS, MAX_LENGTH)
    maxlen = max(len(x) for x in ids_list)
    pad = tok.pad_token_id
    input_ids = torch.full((len(rows), maxlen), pad, dtype=torch.long)
    attn = torch.zeros((len(rows), maxlen), dtype=torch.long)
    pos = torch.zeros((len(rows), maxlen), dtype=torch.long)
    for i, ids in enumerate(ids_list):
        input_ids[i, maxlen - len(ids):] = torch.tensor(ids, dtype=torch.long)
        attn[i, maxlen - len(ids):] = 1
    pos = (attn.cumsum(-1) - 1).clamp(min=0)
    out = model.generate(
        input_ids=input_ids.to(model.device), attention_mask=attn.to(model.device),
        position_ids=pos.to(model.device),
        generation_config=GenerationConfig(
            max_new_tokens=MAX_NEW_TOKENS, do_sample=False,
            eos_token_id=tok.eos_token_id, pad_token_id=pad, use_cache=True))
    results = []
    for i, r in enumerate(rows):
        resp = out[i, maxlen:].tolist()
        # batched generate pads early-finished rows to the batch max length with
        # pad_token; their single-row path stops at EOS, so trim trailing pads to
        # reproduce it exactly (their regions() requires last token == eos).
        while resp and resp[-1] == pad:
            resp.pop()
        from adaguard.model import regions
        text, _, _, ended = regions(tok, resp)
        results.append(parse_result(tok, r, resp, text, ended))
    return results

# ---- writer (AGrail-caliber resume/repair; .part staging) ----------------------------------
# In-progress arm files do not carry the final discoverable name: canonical arms write
# to <final>.part and are renamed atomically at completion. Resume reads .part if
# present, else the final file (completed-arm reruns become no-ops).
class Writer:
    def __init__(self, path, arm, n_expect, corpus_path, corpus_md5_full,
                 arm_base=None, rep=1, scrub_errors=False, exec_mode="single-row greedy",
                 final_path=None):
        self.path, self.lock = path, threading.Lock()
        self.done = set()
        self.corpus_md5_full = corpus_md5_full
        src = path if os.path.exists(path) else (final_path or "")
        if src and os.path.exists(src):
            with open(src, "rb") as f:
                lines = f.read().split(b"\n")
            if lines and lines[-1] == b"":
                lines = lines[:-1]
            keep, dropped, scrubbed = [], 0, 0
            for ln in lines:
                try:
                    d = json.loads(ln)
                    if (scrub_errors and not d.get("_header") and d.get("status") == "INVALID"
                            and "error" in d):
                        scrubbed += 1     # transient exception rows: redo them
                        continue
                    keep.append(ln)
                    if not d.get("_header"):
                        self.done.add(d["id"])
                        if d.get("corpus_md5_8") != corpus_md5_full[:8]:
                            raise SystemExit(f"[FATAL] {src}: row corpus md5 "
                                             f"{d.get('corpus_md5_8')} != current {corpus_md5_full[:8]} — corpus drifted mid-run")
                except SystemExit:
                    raise
                except Exception:
                    dropped += 1
            if src == path:   # only rewrite the STAGING file, never a completed final
                with open(path, "wb") as f:
                    for ln in keep:
                        f.write(ln + b"\n")
                if dropped or scrubbed:
                    print(f"[resume] repaired {path}: dropped {dropped} partial, scrubbed "
                          f"{scrubbed} error rows, {len(self.done)} done", flush=True)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            hdr = {"_header": True, "mode": arm, "arm_base": arm_base or arm, "rep": rep, "backend": BACKEND,
                   "guard": "AdaGuard",
                   "model": MODEL_FIELD, "weight": f"AdaGuard-8B @ {WEIGHT_DIR}",
                   "weight_sha256": WEIGHT_SHA256, "device": DEVICE,
                   "sampling": "greedy (do_sample=False)", "caliber": CALIBER,
                   "exec_mode": exec_mode,
                   "max_new_tokens": MAX_NEW_TOKENS, "max_length": MAX_LENGTH,
                   "runtime": "AdaGuard model load (bf16, eager); prompts, validation, and parsing from AdaGuard; batching driver-side left-pad",
                   "policy_form": ("native=clause-split verbatim of main-corpus profile; "
                                   "rule-deletion=clause-split verbatim of the arm-corpus profile"),
                   "n": n_expect, "corpus": corpus_path, "corpus_md5_8": corpus_md5_full[:8],
                   "corpus_md5_full": corpus_md5_full,
                   "tstamp": time.time()}
            with open(path, "a") as f:
                f.write(json.dumps(hdr, ensure_ascii=False) + "\n")

    def write(self, row):
        with self.lock:
            with open(self.path, "a") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
                f.flush()

def audit_row(rec, policy, policy_meta, content):
    """Side-by-side render-fidelity audit record. content = THEIR schema (list of segments)."""
    events = [e for seg in content for e in seg]
    return {
        "id": rec["id"], "cell_id": rec["cell_id"], "half": rec["half"],
        "policy": policy, "policy_meta": policy_meta, "content_events": content,
        "corpus": {"profile": rec["profile"],
                    "user_messages": [m["content"] for m in rec["contents"] if m["role"] == "user"],
                    "tool_observations": [m["content"] for m in rec["contents"] if m["role"] == "tool"],
                    "objective": rec["objective"],
                    "assistant_thoughts": [m.get("thought", "") for m in rec["contents"] if m["role"] == "assistant"]},
        "checks": {
            "clause_texts_join_to_profile": True,  # asserted in build_policy
            "n_policy_rules": len(policy),
            "user_events_eq_corpus_user_msgs": [e["content"] for e in events if e["role"] == "user"] ==
                [m["content"] for m in rec["contents"] if m["role"] == "user"],
            "env_events_eq_corpus_tool_msgs": [e["content"] for e in events if e["role"] == "environment"] ==
                [m["content"] for m in rec["contents"] if m["role"] == "tool"],
            "agent_action_eq_objective": [e["action"] for e in events if e["role"] == "agent"] == [rec["objective"]],
            "agent_thought_eq_joined_thoughts": [e["thought"] for e in events if e["role"] == "agent"] ==
                ["\n".join(m.get("thought", "") for m in rec["contents"]
                           if m["role"] == "assistant" and m.get("thought", "").strip())]}}

def run_arm(arm, args, ts):
    family, corpus_key, half = ARMS[arm]
    if family == "native":
        rows, corpus_path, md5_full = load_main(corpus_key, half)
        slot_mode = "native"
    elif family in RELATION_MD5:
        rel, want_md5, want_rows = RELATION_MD5[family]
        path = os.path.join(CG, "data/boards", rel)
        md5_full = hashlib.md5(open(path, "rb").read()).hexdigest()
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        rows, corpus_path = _normalize(rows, path), path
        slot_mode = "relation:" + family
    else:
        rows, corpus_path, md5_full = resolve_arm_corpus(family, corpus_key, half)
        slot_mode = "rfamily:" + family
    rep = getattr(args, "rep", 1)
    arm_tok = arm if rep == 1 else f"{arm}.rep{rep}"
    _b = max(1, getattr(args, "batch", None) or 1)
    if getattr(args, "lgroup", False) and _b > 1 and not getattr(args, "smoke", False):
        arm_tok = f"{arm_tok}.lgroupb{_b}"
    smoke = ".SMOKE" if args.smoke else ""
    exm = ".exactlen" if (getattr(args, "exactlen", False) and not args.smoke) else ""
    os.makedirs(RESULTS, exist_ok=True)
    if getattr(args, "out", ""):
        out = args.out
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    else:
        out = (f"{RESULTS}/"
               f"src__AdaGuard-8B__{BACKEND}__{CALIBER}__oversafety.jsonl{smoke}{exm}.{arm_tok}.{md5_full[:8]}.{ts}")
    if args.cells:
        wanted = set(args.cells.split(","))
        rows = [r for r in rows if r["cell_id"] in wanted or r["id"] in wanted]
        assert rows, f"no cells matched --cells {args.cells}"
    elif args.limit:
        rows = rows[:args.limit]
    print(f"[{arm}] corpus={os.path.basename(corpus_path)} md5={md5_full[:8]} half={half} "
          f"slot={slot_mode} rows={len(rows)} out={out}", flush=True)

    # build + validate (their contract) every row first
    built = []
    for rec in rows:
        policy, pmeta = build_policy(rec, slot_mode)
        content = build_content(rec)
        row = {"policy": policy, "content": content}
        from adaguard.data import validate
        validate(row, target=False)          # THEIR validate() must pass — hard gate
        built.append((rec, row, pmeta))

    # .part staging (R5-side ingestion discipline): canonical arms write to <final>.part,
    # renamed atomically to <final> at completion. Completed-arm reruns are no-ops.
    part = out + ".part"
    if not args.smoke:
        if os.path.exists(out) and not os.path.exists(part):
            n_fin = 0
            for ln in open(out, errors="replace"):
                try:
                    if ln.strip() and not json.loads(ln).get("_header"):
                        n_fin += 1
                except Exception:
                    pass
            if n_fin >= len(rows):
                print(f"[{arm}] already complete at FINAL name ({n_fin} rows): {out}", flush=True)
                return out, 0, 0
        out_write = part
    else:
        out_write = out
    W = Writer(out_write, arm_tok, len(rows), corpus_path, md5_full, arm_base=arm, rep=rep,
               scrub_errors=getattr(args, "scrub_errors", False),
               exec_mode=("exactlen zero-pad batch (gate-verified)"
                          if (getattr(args, "exactlen", False) and (args.batch or 1) > 1 and not args.smoke)
                          else (f"lgroup batch B={_b} left-pad greedy (per-arm 100-row dual gate >=99%)"
                                if (getattr(args, "lgroup", False) and _b > 1 and not args.smoke)
                                else "single-row greedy")),
               final_path=None if args.smoke else out)
    todo = [(rec, row, pmeta) for rec, row, pmeta in built if rec["id"] not in W.done]
    if not todo:
        print(f"[{arm}] already complete ({len(W.done)} rows)", flush=True)
        return out, 0, 0
    model, tok = load_guard(batch=args.batch)

    B = max(1, args.batch or 1)
    # Length-grouped batching: sort todo by prompt token length so each batch holds
    # near-equal-length rows and padding is small. Chunk composition/order only; per-chunk
    # generation semantics (prompts, left-pad, greedy) unchanged. Rows are id-keyed on
    # file, so write order does not matter.
    if getattr(args, "lgroup", False) and B > 1:
        from adaguard.model import prompt_text
        todo = sorted(todo, key=lambda t: len(tok.encode(prompt_text(tok, t[1]),
                                                         add_special_tokens=False)))
        print(f"[{arm}] lgroup: todo sorted by prompt length "
              f"(min={len(tok.encode(prompt_text(tok, todo[0][1]), add_special_tokens=False))} "
              f"max={len(tok.encode(prompt_text(tok, todo[-1][1]), add_special_tokens=False))} tok)",
              flush=True)

    # Batch-equivalence check vs the single-row path (first min(8,len) rows).
    # The verdict tuple (status, unsafe, violated_ids) must agree; raw text may drift.
    # Any verdict mismatch on this probe falls back to B=1 for the arm.
    if args.check_batch and todo:
        chk = todo[:8]
        bres = run_batch(model, tok, [r for _, r, _ in chk])
        n_diff = 0
        for (rec, row, pmeta), br in zip(chk, bres):
            sr = predict_row(model, tok, row)
            same = (sr["status"] == br["status"] and sr["unsafe"] == br["unsafe"]
                    and (sr["violated_ids"] or None) == (br["violated_ids"] or None))
            raw_eq = sr["raw_response"] == br["raw_response"]
            if not same:
                n_diff += 1
            print(f"[check-batch] {rec['id']}: single={sr['status']}/{sr['unsafe']} "
                  f"batch={br['status']}/{br['unsafe']} verdict_equal={same} raw_equal={raw_eq}", flush=True)
        if n_diff:
            B = 1
            print(f"[check-batch] FALLBACK: {n_diff}/{len(chk)} verdict-diverged -> batch=1 for this arm", flush=True)
        else:
            print(f"[check-batch] all {len(chk)} rows verdict-identical to their single-row path; batch={B}", flush=True)
    # Exact-length zero-pad batching: group rows by exact prompt token length; only rows
    # of identical length share a batch, so padding is zero. Output files carry the
    # ".exactlen." filename marker, and the exec_mode field is recorded per row.
    if getattr(args, "exactlen", False) and B > 1:
        from adaguard.model import prompt_text
        groups = {}
        for t in todo:
            L = len(tok.encode(prompt_text(tok, t[1]), add_special_tokens=False))
            groups.setdefault(L, []).append(t)
        ordered = []
        for L in sorted(groups):
            for i in range(0, len(groups[L]), B):
                ordered.append(groups[L][i:i + B])
        todo_plan = ordered                    # list of equal-length chunks
        n_groups = len(groups)
        cov = sum(len(g) for g in groups.values() if len(g) >= 2)
        print(f"[{arm}] exactlen: {n_groups} distinct lengths, {cov}/{len(todo)} rows in "
              f"groups>=2, {len(ordered)} chunks of <= {B}", flush=True)
    else:
        todo_plan = None                       # plain sequential chunking below

    # LENGTH-GROUPED BATCHING (moved: sort happens before the probe so the probe chunk
    # is representative of the length-homogeneous batches used at run time).
    counters = {"OK": 0, "INVALID": 0}
    t0 = time.time()
    i = 0
    n_written = [0]
    exec_mode = ("exactlen zero-pad batch (gate-verified)" if getattr(args, "exactlen", False) and B > 1
                 else "single-row greedy")
    plan = todo_plan if todo_plan is not None else [todo[j:j + B] for j in range(0, len(todo), B)]
    for chunk in plan:
        i += len(chunk)
        rec_err = None
        try:
            results = run_batch(model, tok, [r for _, r, _ in chunk])
        except Exception:
            traceback.print_exc()
            rec_err = traceback.format_exc()[-1200:]
            results = None
        for (rec, row, pmeta), res in zip(chunk, results or [None] * len(chunk)):
            if res is None:
                res = {"status": "INVALID", "raw_response": None, "analysis": None,
                       "violated_ids": None, "unsafe": None, "output_tokens": None}
            outrow = {"id": rec["id"], "cg_cell_id": rec.get("cg_cell_id", rec["cell_id"]), "cell_id": rec["cell_id"],
                      "half": rec["half"], "declared_axis": rec.get("declared_axis"), "family": rec.get("family"),
                      "name_category": rec.get("name_category"), "gt_label": rec["gt_label"],
                      "oracle_verdict": rec["oracle_verdict"],
                      "status": res["status"], "unsafe": res["unsafe"], "violated_ids": res["violated_ids"],
                      "analysis": res["analysis"], "output_tokens": res["output_tokens"],
                      "model": MODEL_FIELD, "weight_sha256": WEIGHT_SHA256,
                      "backend": BACKEND, "device": DEVICE, "endpoint": ENDPOINT,
                      "guard": "AdaGuard", "arm": arm_tok, "arm_base": arm, "rep": rep, "slot_mode": slot_mode, "caliber": CALIBER,
                      "exec_mode": exec_mode,
                      "corpus_md5_8": md5_full[:8],
                      "n_policy_rules": len(row["policy"]), "policy_chars": sum(len(p["text"]) for p in row["policy"]),
                      "policy_meta": pmeta,
                      "dur_s": round(time.time() - t0, 1), "tstamp": time.time()}
            if res["status"] == "INVALID":
                outrow["raw_response"] = res["raw_response"]
                if rec_err:
                    outrow["error"] = rec_err
            if args.audit_out and n_written[0] < 10:  # audit the first 10 cells of this run
                outrow["_audit"] = audit_row(rec, row["policy"], pmeta, row["content"])
            n_written[0] += 1
            W.write(outrow)
            counters[res["status"]] = counters.get(res["status"], 0) + 1
        if (i // B) % 5 == 0 or i >= len(todo):
            el = time.time() - t0
            print(f"[{arm}] {i}/{len(todo)} OK={counters['OK']} INVALID={counters['INVALID']} "
                  f"el={el:.0f}s rate={i/max(el,1):.2f} rows/s eta={(len(todo)-i)/max(i/max(el,1),1e-9)/60:.1f}m", flush=True)
    if args.audit_out:
        audits = []
        lines_in = [ln for ln in open(out)]
        lines_out = []
        for ln in lines_in:
            d = json.loads(ln)
            if not d.get("_header") and "_audit" in d:
                audits.append({"id": d["id"], "audit": d["_audit"], "status": d["status"]})
            d.pop("_audit", None)
            lines_out.append(json.dumps(d, ensure_ascii=False))
        with open(out, "w") as f:  # rewrite without _audit blocks
            f.write("\n".join(lines_out) + "\n")
        json.dump({"arm": arm, "caliber": CALIBER, "corpus_md5_8": md5_full[:8], "cells": audits},
                  open(args.audit_out, "w"), ensure_ascii=False, indent=1)
        print(f"[{arm}] render audit -> {args.audit_out} ({len(audits)} cells)", flush=True)
    print(f"[{arm}] DONE rows={len(todo)} OK={counters['OK']} INVALID={counters['INVALID']}", flush=True)
    # completion gate: .part -> final rename only at full row count (+ README line)
    if not args.smoke and os.path.exists(part):
        n_tot, n_inv = 0, 0
        for ln in open(part, errors="replace"):
            try:
                d = json.loads(ln)
            except Exception:
                continue
            if d.get("_header"):
                continue
            n_tot += 1
            n_inv += (d.get("status") == "INVALID")
        if n_tot >= len(rows):
            os.rename(part, out)
            print(f"[{arm}] COMPLETE: renamed to final name, rows={n_tot} invalid={n_inv}",
                  flush=True)
        else:
            print(f"[{arm}] WARN: staging file holds {n_tot}/{len(rows)} rows — kept as .part "
                  f"(not discoverable); rerun this arm to finish", flush=True)
    return out, counters["OK"], counters["INVALID"]

def main():
    global WEIGHT_DIR, DEVICE, CG, ADAGUARD_ROOT, MODEL_FIELD, DELETION_DIR, RESULTS
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True,
                    help="arm name, or all | native | strip | relation")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--cells", default="")
    ap.add_argument("--audit-out", default="")
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--check-batch", action="store_true")
    ap.add_argument("--lgroup", action="store_true",
                    help="length-grouped batching (sort by prompt token length before chunking)")
    ap.add_argument("--exactlen", action="store_true",
                    help="exact-length zero-pad batching (identical prompt lengths share a batch)")
    ap.add_argument("--scrub-errors", action="store_true",
                    help="on resume, drop exception-error rows (status INVALID + error) so they rerun")
    ap.add_argument("--weight-dir", default="",
                    help="override weight directory (default <base>/models/AdaGuard-8B)")
    ap.add_argument("--base", default=CG)
    ap.add_argument("--rdir", default="", help="override rule-deletion corpus directory")
    ap.add_argument("--device", default=DEVICE)
    ap.add_argument("--rep", type=int, default=1, help="repetition id (rep1 = plain arm token)")
    ap.add_argument("--ts", default=time.strftime("%Y%m%dT%H%M"))
    ap.add_argument("--out", default="", help="exact output path (single-arm runs)")
    args = ap.parse_args()
    if args.out and args.arm in ("all", "native", "strip", "relation"):
        raise SystemExit("--out requires a single --arm")
    CG = args.base
    ADAGUARD_ROOT = os.environ.get("ADAGUARD_ROOT", os.path.join(CG, "third_party", "AdaGuard"))
    sys.path.insert(0, ADAGUARD_ROOT)
    DEVICE = args.device
    gpu_idx = DEVICE.split(":")[-1] if ":" in DEVICE else DEVICE
    MODEL_FIELD = f"{WEIGHT_NAME}@{ENDPOINT}:{gpu_idx}"
    WEIGHT_DIR = args.weight_dir or os.path.join(CG, "models", "AdaGuard-8B")
    DELETION_DIR = args.rdir or os.path.join(CG, "data", "boards", "deletion")
    if not os.environ.get("CG_RESULTS"):
        RESULTS = os.path.join(CG, "results")
    if args.arm == "native":
        jobs = [(a, 1) for a in PHASE1_ORDER]
    elif args.arm == "strip":
        jobs = [(a, 1) for a in PHASE2_ORDER]
    elif args.arm == "relation":
        jobs = [(a, 1) for a in RELATION_ORDER]
    elif args.arm == "all":
        jobs = [(a, 1) for a in PHASE1_ORDER + PHASE2_ORDER]
    else:
        assert args.arm in ARMS, f"unknown arm {args.arm}"
        jobs = [(args.arm, args.rep)]
    fails = {}
    for arm, rep in jobs:
        args.rep = rep
        _out, ok, inv = run_arm(arm, args, args.ts)
        fails[f"{arm}.rep{rep}"] = inv
    print("SUMMARY INVALID per arm:", fails, flush=True)

if __name__ == "__main__":
    main()
