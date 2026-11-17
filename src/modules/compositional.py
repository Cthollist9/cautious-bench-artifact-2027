"""Compositional checks (`ms`) — Lean §16 (MS2 aggregate / MS4 provenance) + §26 (MS7 cross-session).

Each is a non-circular function of verdict-free inputs (acts' args / the world's labeled memory / Π),
composed under `&&` into L (Step 4 conjunction, L_cross_noncircular). The acts carry their
contributions directly (aggregate qty / provenance tokens) — equivalent to reading them via the
(default identity-projection) effect fn, and still verdict-free.
"""
from __future__ import annotations

from ..model import Act, Ctx, Policy


def ms2_aggregate(qty_key: str = "aggregate_qty", bound_key: str = "default"):
    """Lean §16/§22 MS2: the sum of a per-step quantity over τ ≤ the Π-declared bound."""
    def ms(τ: tuple[Act, ...], π: Policy, ctx: Ctx) -> bool:
        total = sum(int((a.args or {}).get(qty_key, 0)) for a in τ)
        bound = π.aggregate_bounds.get(bound_key, total)   # absent bound ⇒ no constraint (permissive)
        return total <= bound
    ms.__doc__ = f"MS2 aggregate ({qty_key} ≤ bound[{bound_key}])"
    return ms


def ms2_distinct_count(bound_key: str = "default"):
    """ ms2_aggregate (a SUM of quantities): here the guard collects the item-lists carried by each `read` step's body,
 DEDUPS them, and counts the DISTINCT items — variety ≠ quantity (duplicates hide the distinct count). The twin's
 distinct-variety exceeds the bound (an over-variety aggregate violation a sum-budget guard misses)."""
    def ms(τ: tuple[Act, ...], π: Policy, ctx: Ctx) -> bool:
        items: list[str] = []
        for a in τ:
            if a.op == "read" and a.body:                  # only the read step carries the item-list in its body
                items.extend(str(a.body).split(","))
        distinct = len({it for it in items if it})
        bound = π.distinct_limits.get(bound_key, distinct)   # absent bound ⇒ no constraint
        return distinct <= bound
    ms.__doc__ = f"MS2d distinct-count (variety ≤ bound[{bound_key}])"
    return ms



def ms2_exact_composition():
    """ composition is wrong — missing required items or having extra ones — is a wrong-composition violation). DISTINCT
 PROPERTY + DECIDER from ms2_aggregate (sum ≤ ceiling), ms2_distinct_count (variety ≤ limit — ANY items within
 the count): here a SET-EQUALITY (set(items) == required) — the COMPOSITION must be
 exactly right (WHICH items), not just the count. A guard doing distinct-count (any N distinct ≤ N) MISSES a
 composition-error (wrong items)."""
    def ms(τ: tuple[Act, ...], π: Policy, ctx: Ctx) -> bool:
        if not π.required_composition:
            return True  # no required-set → no constraint
        items: set[str] = set()
        for a in τ:
            if a.op == "read" and a.body:
                items.update(x for x in str(a.body).split(",") if x)
        return items == π.required_composition
    ms.__doc__ = "MS2x exact-composition (set(items) == required_composition)"
    return ms


def ms4_provenance(τ: tuple[Act, ...], π: Policy, ctx: Ctx) -> bool:
    """Lean §16 MS4: every Π-declared provenance token is carried by some step of τ."""
    carried = {tok for a in τ for tok in (a.args or {}).get("provenance_tokens", ())}
    return π.declared_provenance <= carried


def ms7_cross_session(τ: tuple[Act, ...], π: Policy, ctx: Ctx) -> bool:
    """Lean §26 MS7 / §12 cross_session_check: every memory item's write-time ORIGIN is authorized
 (the attr_lookup table). Scores by origin (not content/lineage) ⇒ laundering-invariant (sound).
 The contrast (origin label) is oracle-internal ⇒ ValidFP=false ⇒ a U sample (Axis-2)."""
    return all(π.origin_auth.get(item.origin, False) for item in ctx.world.memory)



def ms2_ratio(label: str = "default"):
    """ concentration limit, in percent). DISTINCT DECIDER (division) from ms2_aggregate (sum), ms2_distinct_count (variety),
 ms2_exact_composition (set==): a proportion a sum/variety/composition
 guard misses (a batch of qty=6 <= cap=10 PASSES budget but ratio-A=83% > 50% FAILS ratio)."""
    def ms(tau, pi, ctx):
        cap = pi.ratio_caps.get(label)
        if cap is None:
            return True
        items = [it.strip() for a in tau if a.op == "read" and a.body
                 for it in str(a.body).split(",") if it.strip()]
        total = len(items)
        if total == 0:
            return True
        labeled = sum(1 for it in items if it == label)
        return labeled * 100 / total <= cap
    ms.__doc__ = f"MS2r ratio ({label}-proportion <= cap)"
    return ms

def combine_ms(*checks):
    """Compose compositional checks under AND (Step 4 conjunction)."""
    def ms(τ: tuple[Act, ...], π: Policy, ctx: Ctx) -> bool:
        return all(c(τ, π, ctx) for c in checks)
    ms.__doc__ = "ms = " + " ∧ ".join(getattr(c, "__doc__", c.__name__) or "check" for c in checks)
    return ms
