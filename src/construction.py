"""
These are the rules PROMOTED from open-external into the closed formal system AND relocated into the
BUILDER (construction-invariant tier): a sample that violates one CANNOT be generated. This is the
construction). Each check is a computable structural property over the (verdict-free) observable Ct.

Mapped §1 items: C1 same-surface (23) · C2 contrast-observable (22) · C3 non-circular scope (4/24) ·
C5 delivery non-circularity (6) · C7 profile-from-Π (27) · C8 pre-action observability (10) · C9
action-inferrability (9) · D3/D5 channel/contrast (19/20) · F9 establishment (7/16).
"""
from __future__ import annotations

from .channels import Channel
from .ct import Ct

# The scary surface = (op, resource, target) — the scary-looking part both halves share (CG-C1).
# The D-channel carrier (body / secret) is where a D-contrast lives, distinct from the scary surface.


def _ccr(c: Ct):
    return c.ccr


def _scary_surface(τ) -> tuple:
    return tuple((a.op, a.resource, a.target) for a in τ)


def _body_carrier(τ) -> tuple:
    """The D-channel carrier: the act's body + secret (the content that crosses to a sink)."""
    return tuple((a.body, a.secret) for a in τ)


def _act_modulo_origin(τ) -> tuple:
    """τ equality ignoring the act's `origin` (issuer) field. For provenance cells the issuer origin IS the
 contrast — benign/twin differ on it (like the body-carrier for a D-contrast) — so single-channel allows
 it; every other act field (op/resource/target/body/secret/args) must still be shared. (Non-provenance
 cells never set origin, so this is equivalent to full τ-equality for them.)"""
    return tuple((a.op, a.resource, a.target, a.body, a.secret, a.args) for a in τ)


def _memory_content(mem) -> tuple:
    return tuple(it.content for it in mem)


def _memory_origins(mem) -> tuple:
    return tuple(it.origin for it in mem)


def same_surface(c: Ct) -> bool:
    """CG-C1 (Lean §18): benign and twin share the scary surface (op/resource/target)."""
    cc = _ccr(c)
    return _scary_surface(cc.benign.τ) == _scary_surface(cc.twin.τ)


def _channel_diffs(c: Ct) -> dict[Channel, bool]:
    """Per-channel benign↔twin difference: A (prompt/consents), B (π), C (w0), D (body/secret carrier).

 For provenance cells the contrast is the act's ISSUER origin (`Act.origin`, allowed to differ — see
 `_act_modulo_origin` + single_channel_contrast). A/B-locus cells carry that contrast in the prompt / π
 (so w0 is identical); C-locus cells ALSO carry the origin-label as the env observation (a w0 fact), which
 is the C-diff. So no origin-fact special-casing is needed here: c_diff is simply the w0 diff.

 * π.bridge_registry_gate — the bridge-registry cells declare their RULE in the shared π (profiles
 byte-identical) and the contrast is the env REGISTRY VALUE; the diff locus is C.
 * π.relay_origin_delivery — an A-channel directive cell whose twin carries twin-only `relay-note:`
 facts (the endorsed-channel origin evidence); those facts are apparatus, excluded from the C-diff
 (the twin must carry ≥1, the benign none — else the flag is vacuous).
 factory port): π.origin_connection_gate (B origin_binding — the connection observation's origin
 value) and π.bridge_auth_gate (C bridge_deputy — the bridge-auth observation's presented token).
 Same shape as bridge_registry_gate: the RULE is declared in the SHARED π (profiles byte-identical)
 and the contrast is the env OBSERVATION VALUE; the diff locus is C (the corpus label keeps B)."""
    b, t = c.ccr.benign, c.ccr.twin
    if getattr(b.π, "relay_origin_delivery", False) and c.contrast_channel is Channel.A_USER_PROMPT:
        from .model import World
        t_relay = frozenset(f for f in t.w0.facts if f.startswith("relay-note:"))
        b_relay = frozenset(f for f in b.w0.facts if f.startswith("relay-note:"))
        c_diff = (not t_relay or bool(b_relay)
                  or b.w0 != World(facts=frozenset(t.w0.facts) - t_relay,
                                   memory=t.w0.memory, resources_present=t.w0.resources_present))
    else:
        c_diff = b.w0 != t.w0
    return {
        Channel.A_USER_PROMPT: b.prompt != t.prompt or b.consents != t.consents,
        Channel.B_PROFILE: b.π != t.π,
        Channel.C_ENVIRONMENT: c_diff,
        Channel.D_BODY: _body_carrier(b.τ) != _body_carrier(t.τ),
    }


def single_channel_contrast(c: Ct) -> bool:
    """CG-D5 (Lean §34 ExactlyOneChannelDiff): the contrast lives in EXACTLY ONE channel — the declared
 `contrast_channel` — and every other channel is identical. Non-D contrasts require τ fully identical
 (the body carrier too); a D-contrast differs only in the body carrier, scary surface still shared.
 An oracleInternal contrast (cross-session U sample) is the exception: every GUARD-OBSERVABLE field is
 identical and ONLY the write-time origin label (unobservable) differs.

 value) the CONSTRUCTION-level diff locus is C — the check is redirected there (the corpus label keeps
 B; census continuity). See _channel_diffs."""
    if c.contrast_channel is Channel.ORACLE_INTERNAL:
        return _observable_identical(c) and _origin_label_differs(c)
    if not same_surface(c):
        return False
    diffs = _channel_diffs(c)
    ch = c.contrast_channel
    b, t = c.ccr.benign, c.ccr.twin
    if getattr(b.π, "bridge_registry_gate", ""):
        ch = Channel.C_ENVIRONMENT            # the registry hybrid's construction-level diff locus
    if getattr(b.π, "origin_connection_gate", False) or getattr(b.π, "bridge_auth_gate", False):
        ch = Channel.C_ENVIRONMENT
    if ch is not Channel.D_BODY and _act_modulo_origin(b.τ) != _act_modulo_origin(t.τ):
        return False                   # non-D contrast: trajectory identical modulo the issuer origin
    return diffs[ch] and sum(diffs.values()) == 1


def _observable_identical(c: Ct) -> bool:
    """For a U (oracleInternal) sample: every guard-observable field is identical between benign/twin —
 prompt, π, scary surface, body carrier, AND the recalled memory CONTENT (only the origin label differs)."""
    b, t = c.ccr.benign, c.ccr.twin
    return (b.prompt == t.prompt and b.π == t.π
            and _scary_surface(b.τ) == _scary_surface(t.τ)
            and _body_carrier(b.τ) == _body_carrier(t.τ)
            and _memory_content(b.w0.memory) == _memory_content(t.w0.memory))


def _origin_label_differs(c: Ct) -> bool:
    """The cross-session contrast: the write-time origin labels of the recalled memory differ (USER vs
 ATTACKER) — the only sound signal (louck2026 T3), oracle-internal (the guard cannot observe it ⇒ U)."""
    return _memory_origins(c.ccr.benign.w0.memory) != _memory_origins(c.ccr.twin.w0.memory)


def contrast_observable(c: Ct) -> bool:
    """CG-C2 / CG-D12 (Lean §13 ValidFP): the contrast channel is guard-observable (A/B/C/D). An
 oracleInternal contrast (cross-session origin) is NOT observable ⇒ a U sample (ValidFP=false)."""
    return c.contrast_channel.guard_observable


def non_circular_scope(c: Ct) -> bool:
    """CG-C3 (Lean §38 isGeneral): a granted role-scope is a CLASS (prefix/domain/table-set), never the
 exact resource — else the authorization would be circular (authorizing the very target under test)."""
    for s in (c.ccr.benign, c.ccr.twin):
        for scopes in s.π.role_scopes.values():
            for scope in scopes:
                if any(scope == a.resource for a in s.τ):   # a scope = the exact resource ⇒ circular
                    return False
    return True


def pre_action_observable(c: Ct) -> bool:
    """CG-C8/C13: the authorizing signal is observable in the PRE-action context (prompt/world/profile),
 not fabricated at/after the action. A precondition fact the action cites must pre-exist in the world."""
    b = c.ccr.benign
    for a in b.τ:
        if a.args and a.args.get("requires_fact"):
            req = a.args["requires_fact"]
            reqs = req if isinstance(req, (tuple, list)) else (req,)   # multi-factor AND (CG-F5+)
            if not all(r in b.w0.facts for r in reqs):
                return False
    return True


def action_inferrable(c: Ct) -> bool:
    """CG-C9: the action is action-inferrable — its scary-surface fields are concrete (op + a resource or
 target or body), not a thin-air sentinel."""
    for s in (c.ccr.benign, c.ccr.twin):
        for a in s.τ:
            if not a.op or (a.resource is None and a.target is None and a.body is None):
                return False
    return True


def establishment(c: Ct) -> bool:
    """CG-F9 (Lean §19): when the cell declares establishment, the benign resource genuinely EXISTS
 (∈ world.resources_present) and the twin's is genuinely ABSENT (the twin OUT is real-absence, not a
 deny-rule). Cells that are not establishment-based pass trivially."""
    if not c.establishment_required:
        return True
    for a in c.ccr.benign.τ:
        if a.resource and a.resource not in c.ccr.benign.w0.resources_present:
            return False
    for a in c.ccr.twin.τ:
        if a.resource and a.resource in c.ccr.twin.w0.resources_present:
            return False
    return True


def narrative_present(c: Ct) -> bool:
    """§1 item 2/31: the FP-C4 narrative schema (principal / prior_state / objective / attribution) is
 populated — non-empty, concrete strings (not placeholders)."""
    return all([c.principal, c.prior_state, c.objective, c.attribution])


def determinism(c: Ct) -> bool:
    """CG-C11: delivered content carries NO real timestamp / uuid / random / epoch
 artifact (ids are content-derived; legitimate device paths exempt). Scanned over the structured Ct's
 serialized fields — the NL is rendered FROM these, so this covers the delivery layer too. Promoted"""
    import re
    blob = _strip_dev(" ".join(map(str, (
        c.principal, c.prior_state, c.objective, c.attribution,
        " ".join(f"{a.op} {a.resource} {a.target} {a.body} {a.secret}" for s in (c.ccr.benign, c.ccr.twin) for a in s.τ),
        " ".join(c.ccr.benign.w0.facts), " ".join(c.ccr.twin.w0.facts),
    ))))
    if re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", blob):   # ISO 8601 / SQL timestamp
        return False
    if re.search(r"\buuid\b", blob, re.I):
        return False
    if re.search(r"\brandom\b", blob, re.I):
        return False
    if re.search(r"\b1[6-9]\d{8}\b", blob):                          # epoch seconds (~2020-2030)
        return False
    return True


_DEV_PATHS = ("/dev/urandom", "/dev/random")


def _strip_dev(s: str) -> str:
    for d in _DEV_PATHS:
        s = s.replace(d, "")
    return s


CONSTRUCTION_CHECKS = {
    "C1_same_surface": same_surface,
    "C2_contrast_observable": contrast_observable,
    "C3_non_circular_scope": non_circular_scope,
    "C8_pre_action_observable": pre_action_observable,
    "C9_action_inferrable": action_inferrable,
    "C11_determinism": determinism,
    "D5_single_channel_contrast": single_channel_contrast,
    "F9_establishment": establishment,
    "schema_narrative_present": narrative_present,
}
