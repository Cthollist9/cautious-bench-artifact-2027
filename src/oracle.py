"""Oracle L — the non-circular label function — mirrors lean/NoncircularClosure.lean §4 (L_noncircular).

L_τ = (∧ per-step verdicts) ∧ MS(τ, Π). Neither conjunct reads `s.vstar`: L is a function of
(π, w0, τ, prompt) ALONE (L_factors_through_inputs — prompt is verdict-free). This is the central property:
a verdict field present in the context CANNOT reach the label — the decider is non-circular by
construction (the type signatures take no Verdict; the running world + acc + prompt are verdict-free).
The src L below literally does not reference `s.vstar`; test_oracle swaps vstar and asserts L is
unchanged (the L_noncircular mirror).
"""
from __future__ import annotations

from .model import ALLOW_VERDICT, Ctx, Model, Sys, Verdict, _all_true, verdicts


def L(m: Model, s: Sys) -> Verdict:
    """Lean §4 L = allTrue(verdicts m s) && ms τ π ctx. Reads π, w0, τ, prompt — NEVER s.vstar."""
    return _all_true(verdicts(m, s)) and m.ms(s.τ, s.π, Ctx(s.w0, s.prompt, s.consents))


def is_within(m: Model, s: Sys) -> bool:
    """Lean §7 isWithin: L = allow (the benign half's contract)."""
    return L(m, s) == ALLOW_VERDICT


def is_out(m: Model, s: Sys) -> bool:
    """Lean §7 isOut: L ≠ allow (the twin half's contract)."""
    return L(m, s) != ALLOW_VERDICT
