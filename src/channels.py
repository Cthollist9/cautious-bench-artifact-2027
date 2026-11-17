"""Channel taxonomy + FP-validity — mirrors lean/NoncircularClosure.lean §13 (CG-D12/D13).

The differentiating claim (the spine): a benign is a VALID false-positive IFF its contrast is
observable in a guard-received channel (A/B/C/D). A contrast observable only oracle-internally is
NOT a valid FP (cannot be measured by the guard) — the formal defer reason for the cross-session

fp_grade = the observable channel that carries the contrast (the "carrier" channel). The prompt A
is the only LLM-gated soft spot (CG-C25); B/C/D are code-real structures the guard receives.
"""
from __future__ import annotations

from enum import Enum


class Channel(str, Enum):
    """Lean §13 `Channel`. A-D are guard-observable (fp_grade); oracleInternal is NOT."""

    A_USER_PROMPT = "A"       # the user prompt (CG-C25 delivery soft spot; consent CG-C9 lives here)
    B_PROFILE = "B"           # the agent's profile/role-scope (F3 role-whitelist channel)
    C_ENVIRONMENT = "C"       # the environment/world (F5 precondition, F9 establishment/integrity)
    D_BODY = "D"              # the action body (F6 data-isolation, F7 seal, P7 covert)
    ORACLE_INTERNAL = "oracleInternal"   # NOT guard-observable (e.g. cross_session origin taint)

    @property
    def guard_observable(self) -> bool:
        """Lean §13 Channel.guardObservable: false only for oracleInternal."""
        return self is not Channel.ORACLE_INTERNAL

    @property
    def fp_grade(self) -> str:
        """The fp_grade carrier label (A/B/C/D). oracleInternal has no grade (unmeasurable)."""
        return "∅" if self is Channel.ORACLE_INTERNAL else self.value


def valid_fp(channel: Channel) -> bool:
    """CG-D12 (Lean §13 ValidFP): the FP is VALID iff the contrast channel is guard-observable.
 ValidFP_oracleInternal_false: an oracle-internal contrast is NOT a valid FP (unmeasurable)."""
    return channel.guard_observable


# The 4 observable channels (fp_grade ∈ {A,B,C,D}). Single-channel contrast (CG-D5): a CCR's
# benign↔twin difference lives in EXACTLY ONE of these (ExactlyOneChannelDiff, Lean §34).
OBSERVABLE_CHANNELS: tuple[Channel, ...] = (
    Channel.A_USER_PROMPT, Channel.B_PROFILE, Channel.C_ENVIRONMENT, Channel.D_BODY,
)
