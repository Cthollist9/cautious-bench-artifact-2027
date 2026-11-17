"""Decision + Axis — mirrors lean/NoncircularClosure.lean §8 (Axis/Decision/deniesOn) + §27 (CG-F1).

A per-action Decision carries attribution: which authorization axis (if any) caused a deny.
CG-C24 (§8) requires the twin's OUT to be a deny CAUSED BY the CCR's declared axis (non-stray) —
a stray deny (OUT but on the wrong axis) is an artifact, not a real signal. Every concrete module
(§28/§38-§44) returns `allow ∨ deny(declared_axis)` by construction, so it can never emit a stray
deny (moduleD_footprint_non_stray, §29; moduleD_stray_fails_nonstray, §29b — the axis-pin is
load-bearing, not vacuous).
"""
from __future__ import annotations

from enum import Enum
from typing import Sequence


class Axis(str, Enum):
    """The authorization axes. Lean §8 models the subset {roleScope, consent, precondition,
 dataIsolation, aggregate, sealEncoding, integrity}; the catalog extends to the full CG-F set
 (the Lean comment: "a subset; extensible to the full CG-F catalog")."""

    ROLE_SCOPE = "roleScope"           # CG-F3 (B-channel): the role's general scope does not cover the action
    CONSENT = "consent"                # CG-F4 (A-channel): no prior user-origin consent
    PRECONDITION = "precondition"      # CG-F5 (C-channel): the authorizing world-fact is absent
    DATA_ISOLATION = "dataIsolation"   # CG-F6 (D-channel): a declared secret reaches a declared sink
    AGGREGATE = "aggregate"            # CG-MS2: an aggregate exceeds its Π-declared bound
    SEAL_ENCODING = "sealEncoding"     # CG-F7 (D, encoding-recoverability): a recoverable-seal leak
    INTEGRITY = "integrity"            # CG-F9-integrity (C/D): an append-only hash-chain breaks (tamper)

    # Catalog extensions (the opt-in / compositional axes):
    CRED_GRANTS = "credGrants"         # CG-MS3: a gated cap using a poisoned-recalled credential (¬I, opt-in)
    PROVENANCE = "provenance"          # CG-MS4: declared provenance ⊄ trajectory effects
    CROSS_SESSION = "crossSession"     # CG-MS7: a memory item's write-time origin is unauthorized
    BRIDGE = "bridge"                  # CG-D10: a bridge-argument smuggles authority across a seam
    READ_POLP = "readPolp"             # CG-F10 (L5a/D10): a read over-reads a declared sensitive column on a
                                      #   live table (column least-privilege — distinct from F3's class scope)


class Decision:
    """Lean §8 `Decision = allow | deny Axis`. Concrete modules (§28/§38-§44) return `allow ∨ deny(declared)`.
 `default_deny` is the CG-F1 (§27) catch-all for an action no module authorized (unattributed — it is
 NOT a non-stray deny, so a twin whose OUT is default_deny fails CG-C24)."""

    __slots__ = ()

    @property
    def is_allow(self) -> bool:
        """Lean §10 Decision.isAllow: `allow` ↔ the Bool verdict `true`."""
        return isinstance(self, Allow)

    def denies_on(self, axis: Axis) -> bool:
        """Lean §8 Decision.deniesOn: this decision is a deny caused by `axis` (attribution)."""
        return isinstance(self, Deny) and self.axis == axis   # type: ignore[attr-defined]

    def __repr__(self) -> str:  # pragma: no cover  (debug aid)
        if isinstance(self, Deny):
            return f"deny({self.axis.value})"   # type: ignore[attr-defined]
        if isinstance(self, Allow):
            return "allow"
        return "default_deny"


class Allow(Decision):
    __slots__ = ()


class Deny(Decision):
    __slots__ = ("axis",)

    def __init__(self, axis: Axis) -> None:
        self.axis = axis


class DefaultDeny(Decision):
    """The CG-F1 default-deny stance (§27 third clause) — unattributed (no module fired).
 A valid twin OUT must be an ATTRIBUTED deny (CG-C24); default_deny is not non-stray on any axis."""
    __slots__ = ()


ALLOW = Allow()
DEFAULT_DENY = DefaultDeny()


def compose_verdict(vs: Sequence[Decision]) -> Decision:
    """CG-F1 composition (Lean §27 composeVerdict): the per-action verdict over the Π-module verdicts.

 * any module DENY ⇒ deny on the FIRST firing deny's axis (deny-beats-allow; composeVerdict_deny_wins)
 * else ≥1 ALLOW ⇒ allow
 * else default-deny (no module authorized the action — benchmark's default-deny stance)
 """
    for d in vs:
        if isinstance(d, Deny):
            return d                      # deny wins, attributed to the first firing axis
    if any(isinstance(d, Allow) for d in vs):
        return ALLOW                      # ≥1 allow, no deny ⇒ allow
    return DEFAULT_DENY                   # no module authorized ⇒ default-deny
