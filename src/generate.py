"""Build and validate corpus samples; only samples that pass all checks are emitted."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from . import conformance, render_nl
from .ct import Ct
from .model import Model

# A cell factory: yields (Ct, Model) pairs for one archetype's cells.
CellFactory = Callable[[], Iterable[tuple[Ct, Model]]]


class ConformanceError(RuntimeError):
    """Raised when a sample fails an INTERNAL-tier gate item (the gate refuses to emit it)."""

    def __init__(self, ct: Ct, result: conformance.GateResult):
        self.ct = ct
        self.result = result
        fails = [f"{i.id}({i.tier.value}): {i.note}" for i in result.internal_failures]
        super().__init__(f"cell {ct.cell_id} FAILED the promotion gate — internal failures: {fails}")


@dataclass
class CorpusOutput:
    structured: list[dict] = field(default_factory=list)   # the structured Ct rows
    nl: list[dict] = field(default_factory=list)            # the AgentDoG-native samples (benign + twin)
    rejected: list[str] = field(default_factory=list)       # cell_ids that failed (strict=False only)
    heterogenization: dict = field(default_factory=dict)    # CG-C12 pool-level report (clones + per-family)

    @property
    def n_cells(self) -> int:
        return len(self.structured)

    @property
    def n_samples(self) -> int:
        return len(self.nl)

    def d_u_split(self) -> dict[str, int]:
        return {"D": sum(1 for r in self.structured if r.get("decidable") == "D"),
                "U": sum(1 for r in self.structured if r.get("decidable") == "U")}


def _qual_key(ct: Ct) -> tuple:
    """CG-C12 value-normalized qualitative key = (actor, surface-family, channel, axis, auth-mech,
 criticality) — value slots (path/URL/recipient/qty/table/secret) normalized OUT, so variants differing
 only in those collapse to one key. surface-family = the archetype's scary-surface CLASS (the first cell's
 op + resource top-level domain), NOT the archetype_id — so two distinct archetypes that are value-only
 clones (same scary-surface class) surface as a monoculture."""
    ax = ct.declared_axis.value
    if ax == "provenance":
        # §3.9: injection/provenance carried in the directive's LOCUS (A/B/C) + multi-step for cross-tool
        steps = "multi" if len(ct.ccr.benign.τ) > 1 else "1"
        mech = f"origin-label-{ct.contrast_channel.value}-{steps}"
    elif ax == "crossSession":
        # §3.8: 4 DISTINCT cross-session mechanisms — single-recall (preference/procedure) vs laundering-
        # channel (compaction) vs aggregate-worst-origin (fragment) vs per-write-over-τ (drift). The mechanism
        # is carried by the trajectory SHAPE (the leading act), NOT the surface label — encoding it here makes
        # the L1 "named-distinct but mechanically-identical" monoculture VISIBLE in the report (the surface
        # key alone would hide it behind cosmetic label differences).
        ops = tuple(a.op for a in ct.ccr.benign.τ)
        shape = ("single-recall" if len(ops) <= 1
                 else "laundered" if ops[0] in ("summarize", "echo")
                 else "aggregate-worst" if ops[0] == "fuse"
                 else "per-write" if ops[0] == "accumulate" else "multi")
        mech = f"origin-{shape}"
    else:
        mech = {"roleScope": "scope-prefix", "consent": "user-consent", "precondition": "world-fact-gate",
                "dataIsolation": "secret-sink", "sealEncoding": "seal-format", "integrity": "hash-chain",
                "aggregate": "budget-bound", "bridge": "bridge-arg"
                }.get(ax, ax)
    crit = "contested" if ct.contested else ("U" if ct.decidable == "U" else "clean")
    # surface-family = the FULL act-sequence (op + resource top-level domain per act), not just the first
    # cell — so a 2-step read→sink (r9b) ≠ a 1-step direct send, and a scale-sink ≠ a pay-sink (distinct
    # sub-scenarios), while value-only clones (same sequence, different recipient/path) still collapse.
    def _dom(act):
        r = act.resource or act.target or ""
        return r.split(":")[0] if ":" in r else (str(r).rsplit("/", 1)[0] or str(r))
    surface = tuple((act.op, _dom(act)) for act in ct.ccr.benign.τ)
    return (ct.principal, surface, ct.contrast_channel.value, ct.declared_axis.value, mech, crit)


def report_heterogenization(cells: list[tuple[Ct, Model]]) -> dict:
    """ shortfall is a disclosed tradeoff, NEVER a blocking violation). Scans the built corpus for (a) cross-
 archetype value-only monocultures (≥2 distinct archetype_ids sharing a qual-key) and (b) the per-family
 distinct-archetype counts (the CG-T5 coverage report). Returns {clones, per_family}. Logged at generation."""
    from collections import defaultdict
    by_key = defaultdict(set)
    by_family = defaultdict(set)
    for ct, _ in cells:
        by_key[_qual_key(ct)].add(ct.archetype_id)
        by_family[ct.family].add(ct.archetype_id)
    clones = {k: sorted(v) for k, v in by_key.items() if len(v) > 1}
    per_family = {f: len(s) for f, s in by_family.items()}
    return {"clones": clones, "per_family": per_family}


def generate_corpus(registry: Iterable[CellFactory], *, strict: bool = True,
                    resource_overrides: dict | None = None) -> CorpusOutput:
    """Build the corpus: for each cell, build (Ct, Model) → run the gate → emit only conforming samples.
 strict=True (default) raises ConformanceError on any internal-tier failure (the by-construction guarantee).
 CG-C12 heterogenization is a POOL-level DISCLOSED check, run + reported after the per-cell gate.

 new_full_resource)] — when set, the pat_* builders substitute the graded resource at the FACTORY level
 (consistent co-variation by construction), producing variant cells DIRECTLY (rendered with the graded
 resource) instead of the NL string-sed `apply_name` that could desync profile from contents. Set as a
 scoped module-level on `patterns` (single-threaded generation ⇒ no race); cleared in `finally`."""
    from . import patterns as _P
    _P._RESOURCE_OVERRIDES = resource_overrides
    # (patterns.GateKindResolutionError) — the full-canon clause fallback is an answer-key leak (RP-1), so a
    # canonical build may never silently take it. Non-strict (dev) builds keep the conservative fallback.
    _P._STRICT_GATE_KIND = strict
    try:
        return _generate_corpus(registry, strict=strict)
    finally:
        _P._RESOURCE_OVERRIDES = None
        _P._STRICT_GATE_KIND = False


def _generate_corpus(registry: Iterable[CellFactory], *, strict: bool = True) -> CorpusOutput:
    out = CorpusOutput()
    built: list[tuple[Ct, Model]] = []
    # gate (verdict-preservation empirically verified per-cell; op-keyed deciders exempted — see
    # rem_rebalance.py docstring). Import-local to avoid a cycle; no-op when maps empty.
    from .rem_rebalance import swap_cell, ACQ_DROP, RETIRE_AUDIT_V17
    for factory in registry:
        for ct, m in factory():
            if ct.cell_id in ACQ_DROP:
                continue
            if ct.cell_id in RETIRE_AUDIT_V17:
                continue
            ct = swap_cell(ct, m)
            result = conformance.run(ct, m)
            if not result.passed:
                out.rejected.append(ct.cell_id)
                if strict:
                    raise ConformanceError(ct, result)
                continue
            built.append((ct, m))
            out.structured.append(ct.to_dict())
            out.nl.extend(render_nl.render_cell(ct, m))
    out.heterogenization = report_heterogenization(built)   # CG-C12: disclosed (tradeoff, not a violation)
    return out


def write_corpus(out: CorpusOutput, data_dir: Path | str,
                 structured_name: str = "src_corpus.jsonl",
                 nl_name: str = "src_corpus_nl.jsonl") -> tuple[Path, Path]:
    """Write the structured Ct + NL corpora as JSONL."""
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    sp = data_dir / structured_name
    np = data_dir / nl_name
    with sp.open("w") as f:
        for row in out.structured:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    with np.open("w") as f:
        for row in out.nl:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    return sp, np


def default_registry() -> list[CellFactory]:
    """The archetype registry (archetypes.REGISTRY) — imported lazily so generate.py loads standalone."""
    from . import archetypes
    return list(archetypes.REGISTRY)
