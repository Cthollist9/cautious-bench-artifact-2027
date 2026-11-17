"""CCR (controlled counterfactual) — mirrors lean/NoncircularClosure.lean §7 (CCR/CCRValid),
§7b (CCR_C, environment channel), §17 (CCR_π, profile channel), §8 (CGC24 non-stray), §34 (single-channel).

A CCR is a (benign, twin) pair of system contexts that share everything EXCEPT exactly one declared
contrast channel (CG-D5, ExactlyOneChannelDiff §34). The contrast channel is the fp_grade carrier
(A/B/C/D); the declared axis is the authorization axis the twin's OUT must be CAUSED by (CG-C24).

 * CCRValid (§7, CG-F8): benign → WITHIN, twin → OUT.
 * CGC24 (§8/§8b): the twin's OUT is an ATTRIBUTED deny on the declared axis (non-stray) — the deny
 is COMPUTED from the twin's trajectory (decisions), not a free parameter (audit B(iii)).
 * same-surface (§18 CG-C1): benign/twin share the scary surface.

The per-channel equality invariants (sameπ for B; same w0 for C; same op/resource for D; same
non-prompt fields for A) are enforced in construction.py (the gate). This module provides the
structure + the validity predicates computed over the oracle L.
"""
from __future__ import annotations

from dataclasses import dataclass

from .channels import Channel
from .decision import Axis, Decision
from .model import Ctx, Model, Sys
from . import oracle

# Compositional axes: the twin's OUT comes from the `ms` check failing (MS2 aggregate / MS7 cross-session),
# NOT from a per-step deny. Per-step axes (role-scope/consent/precondition/data-isolation/seal/integrity/
# provenance-via-F11/cred-via-MS3) attribute via the computed decision sequence.
COMPOSITIONAL_AXES = frozenset({Axis.AGGREGATE, Axis.CROSS_SESSION})


@dataclass(frozen=True)
class CCR:
    """A controlled counterfactual (CG-D5). benign/twin share all but the single `contrast_channel`;
 the twin's OUT must be caused by `declared_axis` (CG-C24)."""

    benign: Sys
    twin: Sys
    contrast_channel: Channel        # CG-D5: the single channel the contrast lives in (⇒ ValidFP if A-D)
    declared_axis: Axis              # CG-C24: the axis the twin's OUT must be on (non-stray)


def ccr_valid(m: Model, c: CCR) -> bool:
    """Lean §7 CCRValid (CG-F8): benign → WITHIN, twin → OUT."""
    return oracle.is_within(m, c.benign) and oracle.is_out(m, c.twin)


def twin_decisions(m: Model, c: CCR) -> tuple[Decision, ...]:
    """Lean §8b sysDecisions: the twin's computed Decision sequence (from its trajectory)."""
    from .model import decisions
    return decisions(m, c.twin)


def twin_denies_on_axis(m: Model, c: CCR) -> bool:
    """Lean §8b decidesOnTraj: the twin's computed decisions contain a deny on the declared axis.
 This is the COMPUTED (audit B(iii)) form of the twin OUT — the deny is derived from the trajectory,
 not a parameter."""
    return any(d.denies_on(c.declared_axis) for d in twin_decisions(m, c))


def first_deny_step(m: Model, c: CCR) -> int | None:
    """CG-C24b: the index of the twin's FIRST non-allow decision in τ (the step the contrast turns at),
 or None if the twin's per-step decisions are all allow (an OUT-by-`ms` compositional cell). Used by the
 gate item C15b + `audit_full.chk_deny_localizes_to_sink` to assert the deny localizes to the declared
 sink (not a decorative prefix step)."""
    for i, d in enumerate(twin_decisions(m, c)):
        if not d.is_allow:
            return i
    return None


def _ms(m: Model, s: Sys) -> bool:
    return m.ms(s.τ, s.π, Ctx(s.w0, s.prompt, s.consents))


def twin_ms_fails(m: Model, c: CCR) -> bool:
    """For a compositional axis: the twin's OUT is the `ms` check failing (aggregate over budget, or a
 cross-session unauthorized origin)."""
    return not _ms(m, c.twin)


def benign_clean(m: Model, c: CCR) -> bool:
    """The benign trajectory has NO per-step deny AND its ms passes (it is WITHIN). A benign with a stray
 deny / a failing ms would be a mislabeled cell (the contrast must turn the verdict, not a coincidental deny)."""
    from .model import decisions
    ds = decisions(m, c.benign)
    return all(d.is_allow for d in ds) and _ms(m, c.benign) and oracle.is_within(m, c.benign)


def cgc24(m: Model, c: CCR) -> bool:
    """Lean §8 CGC24 (non-stray): the twin is OUT AND the OUT is CAUSED by the declared axis.
 * per-step axis ⇒ a computed deny on that axis (decidesOnTraj);
 * compositional axis (MS2/MS7) ⇒ the ms check fails on the twin, AND the twin has no stray per-step
 deny (so the OUT is purely the compositional check, not a coincidental deny on another axis)."""
    if not oracle.is_out(m, c.twin):
        return False
    if c.declared_axis in COMPOSITIONAL_AXES:
        twin_no_stray_per_step = all(d.is_allow for d in twin_decisions(m, c))
        return twin_no_stray_per_step and twin_ms_fails(m, c) and _ms(m, c.benign)
    return twin_denies_on_axis(m, c)


def verify_ccr(m: Model, c: CCR) -> bool:
    """The full CCR validity: CCRValid (benign WITHIN / twin OUT) ∧ CGC24 (twin OUT non-stray on the
 declared axis) ∧ benign_clean (no stray benign deny). This is what the generator's gate asserts
 before emitting a sample — conformance by construction."""
    return ccr_valid(m, c) and cgc24(m, c) and benign_clean(m, c)
