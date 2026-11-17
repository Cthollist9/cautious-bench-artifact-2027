"""Ct — the structured corpus row (the FP-C4 schema) — benchmark/fp-c4 §1 + subvariants §1 item 31.

The structured Ct carries the narrative schema {principal, policy, prior_state, objective} + the
controlled counterfactual (CCR) + the FP-C4 tags. It is what `render_nl` projects to the AgentDoG-native
{profile, contents} delivery (CG-C25). The narrative fields are DERIVED from the formal Π+trajectory
(CG-C4: Ct from Π; CG-C7: profile from Π) — never verdict-fed-back (CG-C5 non-circular delivery).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ccr import CCR


@dataclass(frozen=True)
class Ct:
    """A corpus sample = the structured Ct (FP-C4 schema) + its CCR + tags."""

    # -- identity / family --------------------------------------------------
    cell_id: str
    archetype_id: str
    family: str                 # §3.x family (role_scope / consent / …)

    # -- FP-C4 narrative schema (item 31: principal/policy/prior_state/objective) -------------
    principal: str              # who/what acts (the role/principal)
    prior_state: str            # the prior world state (establishment / precondition)
    objective: str              # the user's objective (the prompt's intent)

    # -- the controlled counterfactual --------------------------------------
    ccr: CCR                    # benign/twin Sys + contrast_channel + declared_axis
    attribution: str            # NL: WHY the twin is OUT (the non-stray reason — grounded in the declared axis)

    # -- FP-C4 tags (item 32/33/34) -----------------------------------------
    decidable: str = "D"        # "D" (decidable_by_NL, native + faithful-in-τ) | "U" (cross-session/laundering)
    contested: bool = False     # D_contested (content-scary: a careful guard could defensibly refuse on content)
    realism_declared: bool = True       # CG-N2 (normative — realism is an implementation choice, disclosed)
    shareable_data_declared: bool = False   # CG-N5 (where a sink, the data is shareable post-seal)
    establishment_required: bool = False     # CG-F9: benign resource present / twin genuine-absence
    sink_step: int | None = None            # CG-C24b: the τ step the contrast turns at (None ⇒ last step)
    # guard-visible). The default benign attribution ("the declared {axis} authorization is present and
    # covers this action") is untrue for cells whose benign allow-basis is the ABSENCE of any non-request
    # channel directive (no origin token delivered anywhere) — the override states the truthful basis.
    benign_attribution_override: str = ""
    # trajectory's COMPLETE message tail (delivery-side, guard-visible, IDENTICAL both halves). The
    # default complete echoes the objective; the f1 rewrite retires the objective's projection/purpose
    # echo from the delivery face ("Completed: the export from {table}." / "Completed: read {path}.")
    # while the objective METADATA keeps the full authored form. Empty ⇒ objective echo (unchanged).
    complete_override: str = ""

    # -- derived (for serialization / the audit report) ---------------------
    @property
    def contrast_channel(self):
        return self.ccr.contrast_channel

    @property
    def declared_axis(self):
        return self.ccr.declared_axis

    @property
    def grade(self) -> str:
        """fp_grade = the contrast carrier. C(lbl) provenance → 'C(lbl)'; oracleInternal → '∅'."""
        ch = self.contrast_channel
        if self.declared_axis.value in ("provenance", "crossSession") and ch.value == "C":
            return "C(lbl)"
        return ch.fp_grade

    def to_dict(self) -> dict:
        """Structured serialization (the formal corpus row). NL delivery is render_nl's job."""
        from .model import decisions  # local to avoid import cycle at module load
        from . import oracle  # noqa: F401  (documented; verdicts re-derived by the caller)
        b, t = self.ccr.benign, self.ccr.twin
        return {
            "cell_id": self.cell_id,
            "archetype_id": self.archetype_id,
            "family": self.family,
            "principal": self.principal,
            "prior_state": self.prior_state,
            "objective": self.objective,
            "contrast_channel": self.contrast_channel.value,
            "declared_axis": self.declared_axis.value,
            "grade": self.grade,
            "decidable": self.decidable,
            "contested": self.contested,
            "sink_step": self.sink_step,
            "attribution": self.attribution,
            "benign": _sys_dict(b),
            "twin": _sys_dict(t),
        }


def _sys_dict(s) -> dict:
    """A compact structured view of a Sys (for the corpus row; the verdict field vstar is EXCLUDED —
 the label is non-circular and not serialized as ground truth)."""
    return {
        "role": s.π.role,
        "prompt": s.prompt,
        "consents": sorted(s.consents),
        "tau": [{"op": a.op, "resource": a.resource, "target": a.target,
                 "body": (str(a.body) if a.body is not None else None), "secret": a.secret,
                 "origin": a.origin, "args": dict(a.args)} for a in s.τ],
        "world_facts": sorted(s.w0.facts),
        "resources_present": sorted(s.w0.resources_present),
    }
