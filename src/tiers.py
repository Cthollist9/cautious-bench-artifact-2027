"""
Six tiers, coordinated across two vocabularies: truth-maker kind (what the rule rests on) and
enforcement locus (how/where it is applied). The DEEP DIVIDE is internal-vs-external:

 * INTERNAL tiers carry label-validity (challengeable only at their base; certain above it):
 formal-decider / definitional / construction-invariant
 * EXTERNAL tiers are the disclosed open surface (supported, never load-bearing for the label):
 formal-proxy / normative / accepted-tradeoff

open-external into the closed formal system, reduced to a computable structural property over the
observable trajectory. The signature benchmark move is the FURTHER promotion formal →
construction-invariant: not only mechanical, but enforced IN THE BUILDER, so a violating sample
"""
from __future__ import annotations

from enum import Enum


class Tier(str, Enum):
    """The six enforcement tiers. `internal` marks where label-validity rests."""

    FORMAL_DECIDER = "formal-decider"
    # Decides the label — closed, mechanical. Π modules, the oracle O, verify_ccr.
    # Truth-maker: formal (a theorem of the policy). A violation = an internal bug.

    DEFINITIONAL = "definitional"
    # A stipulated concept we CONSTITUTE. The channel taxonomy A/B/C/D; the CCR primitive;
    # non-circular FP-validity. A violation = fails to meet the concept.

    CONSTRUCTION_INVARIANT = "construction-invariant"
    # Enforced AT BUILD TIME — a sample CANNOT be generated wrong w.r.t. these. Build-time checks
    # (construction.CONSTRUCTION_CHECKS, 9): same-surface (CG-C1), contrast-observable (CG-C2),
    # non-circular scope (CG-C3), single-channel contrast (CG-D5), pre-action observability (CG-C8),
    # action-inferrability (CG-C9), determinism (CG-C11), establishment (CG-F9), narrative-present.
    # NOTE: least-privilege (CG-C6/C20/C21) is NOT build-time — enforced by the disclosed per-cell
    # audit (audit_full.chk_least_privilege, marked 'gap — not in gate'), i.e. formal-proxy/normative,

    FORMAL_PROXY = "formal-proxy"
    # A necessary-not-sufficient pattern detector — formal-in-FORM, inductive-in-CONTENT. Catches
    # KNOWN unfaithfulness shapes; a novel shape is not caught. The choice of which patterns to
    # catch is the inductive element, disclosed. (CG-P1..P7: env_not_stub, is_recoverable, etc.)

    NORMATIVE = "normative"
    # The owned residual with NO mechanical oracle. CG-N1 non-contestability (would a careful
    # guard defensibly refuse the scary surface?) — irreducibly a judgment. Its content-scary
    # sub-part stays here; realism (CG-N2) is normative, declared.

    ACCEPTED_TRADEOFF = "accepted-tradeoff"
    # A disclosed out-of-distribution, NOT enforced. multi-step representativeness;
    # compositional axes not yet in Π. Recorded as a tradeoff, never double-counted as a violation.

    @property
    def internal(self) -> bool:
        """Label-validity rests here — challengeable only at the base, certain above it ."""
        return self in (Tier.FORMAL_DECIDER, Tier.DEFINITIONAL, Tier.CONSTRUCTION_INVARIANT)


# A component's tier is recorded alongside it (Tiered.tier) so the conformance gate can verify the
# internal tiers hold and the external tiers are merely disclosed, not load-bearing.
class Tiered:
    """Mixin: a formal component that carries its tier ."""

    tier: Tier = Tier.DEFINITIONAL  # overridden per component

    @property
    def tier_label(self) -> str:
        return self.tier.value


# (heterogenization, realism-as-implementation-choice). A conflict is recorded as an ACCEPTED
# TRADEOFF, disclosed — never silently violated, never inflated into a violation.
