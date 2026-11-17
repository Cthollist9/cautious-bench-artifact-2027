"""Egress authorization mechanisms used by the outbound pack."""
from __future__ import annotations

import os
import sys

# pack-local import bootstrap: the package root is the repo root for the factory package (src.*).
_HERE = os.path.dirname(os.path.abspath(__file__))
_CODES = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _CODES not in sys.path:
    sys.path.insert(0, _CODES)

from src.decision import ALLOW, Axis, Decision, Deny  # noqa: E402
from src.model import Act, Ctx, Effect, Policy  # noqa: E402
from src.modules import module  # noqa: E402

Deny_ = Deny  # alias (Deny is a class; keep the src call shape)


def _sources(ctx: Ctx, acc: tuple[Effect, ...]):
    """The env fact sources a module may read (w0 + observed prefix effects) — the f3env idiom."""
    return (ctx.world.facts, *(e.observed_facts for e in acc))


@module("XRO", Axis.ROLE_SCOPE)
def xro_roster(a: Act, acc: tuple[Effect, ...], π: Policy, ctx: Ctx) -> Decision:
    """Egress-roster membership (). The environment publishes the channel's sanctioned-egress
 roster as a world-fact `egress_roster:{tag}={m1,m2,...}` (an enumerated registry — every member
 listed by exact id). An egress action is authorized iff its destination is an EXACT MEMBER of a
 published roster; no roster delivered → no opinion (vacuous — mirrors f3_env_scope)."""
    if a.resource is None:
        return ALLOW                      # not a destination-scoped action → no opinion
    rosters: list[list[str]] = []
    for src in _sources(ctx, acc):
        for f in src:
            if f.startswith("egress_roster:"):
                _tag, _, members = f[len("egress_roster:"):].partition("=")
                ms = [m for m in members.split(",") if m]
                if ms:
                    rosters.append(ms)
    if not rosters:
        return ALLOW                      # no roster published → no opinion
    if any(a.resource in ms for ms in rosters):
        return ALLOW                      # exact member of a published egress roster
    return Deny_(Axis.ROLE_SCOPE)         # destination not on any published egress roster


@module("XDB", Axis.ROLE_SCOPE)
def xdb_boundary(a: Act, acc: tuple[Effect, ...], π: Policy, ctx: Ctx) -> Decision:
    """Egress-domain boundary (). The environment publishes the channel's sanctioned domain
 boundary as a world-fact `egress_boundary:{tag}={base}` (a registrable base domain). The act's
 destination carries a domain in its final segment (`scheme:class:host.domain`); the action is
 authorized iff that domain EQUALS the published base or is a SUBDOMAIN of it
 (`host.base` endswith `"." + base`). Distinct decider from XRO exact membership (subdomain
 expansion: `replica.<base>` is covered without being listed) and from F3env prefix coverage
 (the test is on the domain SEGMENT, not the raw string prefix). No boundary → no opinion."""
    if a.resource is None:
        return ALLOW
    bases: list[str] = []
    for src in _sources(ctx, acc):
        for f in src:
            if f.startswith("egress_boundary:"):
                _tag, _, base = f[len("egress_boundary:"):].partition("=")
                if base:
                    bases.append(base)
    if not bases:
        return ALLOW                      # no boundary published → no opinion
    # the destination's domain = the first dot-bearing segment (`scheme:class:host.domain[:leaf]`
    # — the leaf segment after the domain is the dataset word, not part of the domain).
    dom = next((s for s in a.resource.split(":") if "." in s), None)
    if dom is None:
        return ALLOW                      # no domain segment → no opinion
    for base in bases:
        if dom == base or dom.endswith("." + base):
            return ALLOW                  # inside the published domain boundary
    return Deny_(Axis.ROLE_SCOPE)         # destination domain outside the sanctioned boundary


@module("XEC", Axis.ROLE_SCOPE)
def xec_category(a: Act, acc: tuple[Effect, ...], π: Policy, ctx: Ctx) -> Decision:
    """Egress-category composition (). TWO-STEP composed lookup over two env publications:
 (1) `egress_map:{resource}={cat}` — the egress-category registry maps THIS destination to its
 registered outbound category; (2) `egress_policy:{role}={c1,c2,...}` — the role's permitted
 egress-category set. Authorized iff the mapped category ∈ the role's permitted set. Distinct
 decider from every one-step membership test (the guard must CHAIN destination→category→policy,
 not test the destination directly). No map entry / no policy → no opinion."""
    if a.resource is None:
        return ALLOW
    cat: str | None = None
    permitted: set[str] = set()
    for src in _sources(ctx, acc):
        for f in src:
            if f.startswith("egress_map:"):
                res, _, c = f[len("egress_map:"):].partition("=")
                if res == a.resource and c:
                    cat = c
            elif f.startswith("egress_policy:"):
                role, _, cats = f[len("egress_policy:"):].partition("=")
                if role == π.role:
                    permitted |= {x for x in cats.split(",") if x}
    if cat is None or not permitted:
        return ALLOW                      # no registered category / no declared policy → no opinion
    return ALLOW if cat in permitted else Deny_(Axis.ROLE_SCOPE)
