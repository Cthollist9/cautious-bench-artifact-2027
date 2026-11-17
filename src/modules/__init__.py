"""Decision modules (Π) — the formal-deciders — mirroring lean/NoncircularClosure.lean §27-§44.

Each per-action module follows the Lean §28 `data_isolation_module` pattern: a real footprint
predicate over (act × prefix-effects × policy × verdict-free ctx) + a concrete decide returning
`allow ∨ deny(declared_axis)` — so it can NEVER emit a stray deny (moduleD_footprint_non_stray, §29;
the axis-pin is load-bearing: moduleD_stray_fails_nonstray, §29b). CG-F1 (§27) composes them.

The compositional checks (MS2/MS4/MS7) realize Lean `ms` (§16/§22/§26) — non-circular functions of
(verdict-free effects/world/policy), composed under `&&` into L (Step 4 conjunction).
"""
from __future__ import annotations

from typing import Callable

from ..decision import Decision
from ..model import Act, Ctx, Effect, ExecFn, EffectFn, Model, Policy, World
from ..tiers import Tier

# A per-action module: (act, prefix-effects, policy, ctx) -> Decision, tagged with metadata.
ModuleFn = Callable[[Act, tuple[Effect, ...], Policy, Ctx], Decision]


def module(mid: str, axis, tier: Tier = Tier.FORMAL_DECIDER):
    """Decorator: tag a decide-function with its CG-id, declared Axis, and tier. Every module is a
 formal-decider by default (it decides the label, closed+mechanical); formal-proxies (CG-P7) override."""

    def deco(fn: ModuleFn) -> ModuleFn:
        fn.module_id = mid        # type: ignore[attr-defined]
        fn.axis = axis            # type: ignore[attr-defined]
        fn.tier = tier            # type: ignore[attr-defined]
        return fn

    return deco


# ---------------------------------------------------------------------------
# Default deterministic substrate (Lean exec/effect) — verdict-free (H2a/H3).
# exec: near-identity (the contrast world-facts are pre-set in w0 for short trajectories); effect:
# carries the act's contributions to the compositional checks (aggregate qty / provenance / cred recalls).
# ---------------------------------------------------------------------------
def default_exec(w: World, a: Act) -> World:
    return w


def default_effect(w: World, a: Act) -> Effect:
    args = a.args or {}
    return Effect(
        aggregate_qty=int(args.get("aggregate_qty", 0)),
        provenance_tokens=tuple(args.get("provenance_tokens", ())),
        credential_recalled=tuple(args.get("credential_recalled", ())),
    )


# ---------------------------------------------------------------------------
# Compositional `ms` composers — Lean §16 (MS2/MS4) + §26 (MS7 cross-session). Combined into one ms
# by AND; each is a non-circular function of verdict-free inputs (the default ms = always-pass).
# ---------------------------------------------------------------------------
def default_ms(τ: tuple[Act, ...], π: Policy, ctx: Ctx) -> bool:
    """The permissive compositional check (no MS constraint) — used by single-axis archetypes."""
    return True


def build_model(Π: tuple[ModuleFn, ...], ms=default_ms,
                exec: ExecFn = default_exec, effect: EffectFn = default_effect) -> Model:
    """Assemble a Model from its Π modules + ms + substrate."""
    return Model(Π=Π, ms=ms, exec=exec, effect=effect)
