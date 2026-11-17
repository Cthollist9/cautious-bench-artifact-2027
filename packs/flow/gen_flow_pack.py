"""Generate the flow-permission pack delivery files."""
from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_CODES = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _CODES not in sys.path:
    sys.path.insert(0, _CODES)
sys.path.insert(0, _HERE)

from src.generate import generate_corpus  # noqa: E402
from gen_variants import verb_polarity  # noqa: E402
from flow_pack_archetypes import SPEC, flow_registry, name_overrides, tier_names  # noqa: E402

PACK_VERSION = "flow_pack_v1"
N_CELLS = sum(len(spec["cells"]) for spec in SPEC)
TIERS = (("neutral", "flow_pack_v1_neutral.jsonl"),
         ("bt", "flow_pack_v1_bt.jsonl"),
         ("tt", "flow_pack_v1_tt.jsonl"))


def _spec_lookup():
    """cell_id -> (spec, cell, i) for the tracing fields."""
    out = {}
    for spec in SPEC:
        for i, cell in enumerate(spec["cells"], 1):
            out[f"{spec['aid']}.{i}"] = (spec, cell, i)
    return out


def _pol_by_cell():
    out = {}
    for spec in SPEC:
        for i, cell in enumerate(spec["cells"], 1):
            out[f"{spec['aid']}.{i}"] = verb_polarity([spec["op"]])
    return out


def build_tier(tier: str, outdir: str) -> str:
    """Generate one tier's file and return its path."""
    overrides = None if tier == "neutral" else name_overrides(tier)
    out = generate_corpus(flow_registry(), strict=True, resource_overrides=overrides)
    assert out.n_cells == N_CELLS and out.n_samples == 2 * N_CELLS and not out.rejected, \
        (f"{tier}: expected {N_CELLS} cells / {2 * N_CELLS} samples / 0 rejected, got "
         f"{out.n_cells}/{out.n_samples}/{len(out.rejected)}")
    lookup = _spec_lookup()
    pol = _pol_by_cell()
    path = os.path.join(outdir, dict(TIERS)[tier])
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for r in out.nl:
            spec, cell, i = lookup[r["cell_id"]]
            names = tier_names(spec, cell, i)
            grade = {"neutral": 0, "bt": 1, "tt": 2}[tier]
            r = dict(r)
            r["sut"] = f"{PACK_VERSION}-{tier}"
            r["name_token"] = tier
            r["name_grade"] = names[grade]
            r["name_category"] = {"neutral": "N", "bt": "B", "tt": "T"}[tier]
            r["verb_polarity"] = pol[r["cell_id"]]
            r["archetype"] = spec["aid"]
            r["axis"] = r["declared_axis"]
            r["cg_cell_id"] = r["cell_id"]
            r["pack_version"] = PACK_VERSION
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    print(f"  {tier:8s}: {path} ({n} rows)")
    return path


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else _HERE
    os.makedirs(outdir, exist_ok=True)
    print(f"flow pack v1 — {len(SPEC)} archetypes / {N_CELLS} cells / 3 tiers")
    for tier, _ in TIERS:
        build_tier(tier, outdir)
    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
