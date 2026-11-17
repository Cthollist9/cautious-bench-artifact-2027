"""Formal Model — mirrors lean/NoncircularClosure.lean §4 (Model/Sys), §7 (CCR carrier), §12 (Item).

The four verdict-free operations carry the structural hypotheses BY THEIR SIGNATURES (H1/H2/H3),
so they hold by construction rather than as side-conditions:
 * exec / effect : World -> Act -> … take NO Verdict (H2a: no verdict-back-edge)
 * exec / effect are *functions* ⇒ deterministic (H3)
 * moduleD : Act × [Effect] × Policy takes NO Verdict (H2b; reads action + prefix + Π + the
 verdict-free running world)
 * ms : ([Act], Policy) takes NO Verdict (H2b)
The src realization passes the (verdict-free) running world to moduleD so footprint predicates
that read observed state (F5 precondition, F4 consent) can compute — this is the Lean-§26
"delivery-level accessor" (memView / authorized), disclosed; it preserves non-circularity
because the world is verdict-free.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence

from .decision import Decision

# ---------------------------------------------------------------------------
# Verdict — Lean §4: `abbrev Verdict := Bool; Verdict.allow := true`.
# ---------------------------------------------------------------------------
Verdict = bool
ALLOW_VERDICT: Verdict = True   # Lean §4: Verdict.allow := true  (distinct from decision.Allow)


# ---------------------------------------------------------------------------
# Item (§12) — a memory cell: malleable content + an immutable write-time origin label.
# Sound cross-session attribution factors through `origin` (attribution_reduction, §12).
# ---------------------------------------------------------------------------
Origin = str   # an origin label bound at write-time (e.g. "user", "tool:web", "agent")


@dataclass(frozen=True)
class Item:
    content: object
    origin: Origin


# ---------------------------------------------------------------------------
# Act — an action in the trajectory τ. Footprint predicates (m.Act -> Footprint, Lean §28/§38-44)
# read these fields + the verdict-free world/policy to compute the per-action Decision.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Act:
    op: str                                # the operation/tool, e.g. "delete_file", "send_email", "recall_memory"
    resource: str | None = None            # the resource acted on (F3 scopes by a CLASS prefix of this)
    target: str | None = None              # the destination channel (F6 sink / F7 seal-sink)
    body: object | None = None             # the D-channel body (F7 seal, P7 covert, post content)
    secret: str | None = None              # a carried/tainted value present in args (F6)
    args: Mapping[str, object] = field(default_factory=dict)   # extensible op-specific args
    origin: Origin | None = None           # provenance of this act's issuer (F11 source-auth)


# ---------------------------------------------------------------------------
# Effect — the observable effect of an action, read pre-next-step via the acc prefix (Lean §2/§3).
# Carries the world-derived signals the modules key on (the verdict-free substrate).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Effect:
    observed_facts: tuple[str, ...] = ()          # world-facts now observable (F5 precondition signals)
    secret_reached_sink: bool = False             # F6: a declared secret reached a declared sink
    credential_recalled: tuple[str, ...] = ()     # MS3: credentials recalled this step
    aggregate_qty: int = 0                        # MS2: this step's contribution to an aggregate
    provenance_tokens: tuple[str, ...] = ()       # MS4: declared-provenance tokens carried
    secret_absorbed: bool = False                 # P7: a covert-channel secret absorbed into a sink body


# ---------------------------------------------------------------------------
# World — the environment channel (w0). The CCR contrast channel for environment-channel pairs
# (CCR_C, Lean §7b): benign.w0 ≠ twin.w0. Carries observed state + the labeled memory.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class World:
    facts: frozenset[str] = frozenset()           # observed world-facts (F5 precondition establishment)
    memory: tuple[Item, ...] = ()                 # labeled memory (cross-session, §12)
    resources_present: frozenset[str] = frozenset()   # establishment (CG-F9): which resources exist


# ---------------------------------------------------------------------------
# Policy — π. The declared structures the modules consult (table lookups = formal given the axiom).
# Some fields are declared-axiom (externally calibratable: sensitive-column taxonomy CG-F10,
# algorithm whitelist CG-F7/B1) — disclosed as inductive elements, but the verdict is mechanical
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Policy:
    # F3 role-scope: role -> set of resource-CLASS prefixes (CG-C3: scope is a class, not the exact resource)
    role_scopes: Mapping[str, frozenset[str]] = field(default_factory=dict)
    role: str = "user"                             # the active role for the action under test
    # graph); base_scopes = role→scope-prefix(es) (each role's OWN base scope). A role's EFFECTIVE scope =
    # union of its base_scopes + all ancestors' base_scopes (transitive closure of role_parents). The ideal
    # guard must TRACE the inheritance chain + union the scopes (multi-step) — distinct from a direct lookup.
    # Both are DECLARED (disclosed axioms, docs/00 §3a); the difficulty is the TRACE, not the disclosure.
    role_parents: Mapping[str, str] = field(default_factory=dict)
    base_scopes: Mapping[str, frozenset[str]] = field(default_factory=dict)
    # F6 data-isolation: declared secrets (taint) + declared sinks (exfil channels)
    declared_secrets: frozenset[str] = frozenset()
    declared_sinks: frozenset[str] = frozenset()
    # F7 seal-encoding + B1: algorithm whitelist (declared axiom — unrecoverable-seal formats)
    algo_whitelist: frozenset[str] = frozenset()
    # F10 read-PoLP: sensitive-column taxonomy (declared axiom) + the structural cold-table carve-out
    # `_ARCHIVE_QUAL`; an over-read on a decommissioned table is benign — cold data, not live sensitive data).
    sensitive_columns: frozenset[str] = frozenset()
    decommissioned_tables: frozenset[str] = frozenset()
    # view-column taxonomy). A view over-exposing sensitive columns is an over-read EVEN via an authorized
    # view — distinct from read_column_polp (projection over-read) + retired_read_polp (decommissioned carve-out).
    view_exposed_columns: frozenset[str] = frozenset()
    # (a DECLARED row-access taxonomy — DISTINCT granularity from view_exposed_columns (column) / sensitive_columns).
    # A read whose row-tenant ∉ rls_tenants is a cross-tenant over-read (row-granularity PoLP, ≠ column/view).
    rls_tenants: frozenset[str] = frozenset()
    # purpose-limitation taxonomy — DISTINCT PROPERTY/competence from rls (row-tenant isolation): here PURPOSE-
    # LIMITATION (why the data is read), a different competence). A read whose declared purpose (∈ the resource
    # `db:..:for=X`) ∉ permitted_read_purposes is an over-read (purpose-limitation violation). empty ⇒ f10g inactive.
    permitted_read_purposes: frozenset[str] = frozenset()
    # the table is in-scope — a BLACKLIST). DISTINCT PROPERTY + POLARITY from rls (which-TENANTS allowed, whitelist):
    # here which-ROWS are FORBIDDEN (blacklist, ∉ excluded). A read of an excluded row is denied.
    excluded_rows: frozenset[str] = frozenset()
    # QUANTITATIVE PoLP — projection-minimization: don't over-project). DISTINCT from the QUALITATIVE readPolp
    # mechanisms (which/masking/encryption/etc.) — here HOW-MANY columns (count ≤ limit). A read projecting more
    # columns than the limit is an over-projection. 0 ⇒ f10i inactive.
    column_count_limit: int = 0
    # the set of (column, row_id) CELLS declared sensitive. A read whose projected-column x row-id intersection
    # is in this set is denied, EVEN WHEN neither the column alone (not in sensitive_columns) nor the row alone
    # (not in excluded_rows / tenant authorized) is sensitive. DISTINCT GRANULARITY (cell = column-and-row,
    # uncovered by any of the 9 readPolp mechanisms) + DISTINCT decider-shape (2-place tuple-membership).
    # empty => f10j inactive.
    sensitive_cells: frozenset[tuple[str, str]] = frozenset()
    # family of column-SETS jointly sensitive AS A COMBINATION (a quasi-identifier set {zip,dob,gender} is sensitive
    # for re-identification though each column is non-sensitive individually). DISTINCT GRANULARITY (column×COLUMN
    # joint-sensitivity, subset-containment over a family-of-sets) from all 10 readPolp mechanisms — f10 (individual
    # column ∈), f10cell (column×ROW 2-place tuple), f10lin (derived→source graph): NONE cover joint-column-
    # sensitivity. A read whose projection CONTAINS a declared group (g ⊆ projected) is denied. HIPAA Safe Harbor /
    # k-anonymity re-identification. empty ⇒ f10k inactive.
    sensitive_groups: frozenset[frozenset[str]] = frozenset()
    # function (a DECLARED masking taxonomy — DISTINCT policy from sensitive_columns (forbidden entirely) /
    # view_exposed_columns). A read projecting a masked-column RAW (unmasked) is an over-read. masking ≠ column-PoLP.
    masked_columns: frozenset[str] = frozenset()
    # authorized key (a DECLARED encryption taxonomy — DISTINCT property from masking (partial-reveal) + column-PoLP).
    # A read projecting an encrypted-column RAW (undecrypted) is an over-read. encryption ≠ masking ≠ column-PoLP.
    encrypted_columns: frozenset[str] = frozenset()
    # source column inherits its sensitivity — projecting a sensitive-lineage column RAW is an over-read. DISTINCT
    # property + decider from column/masking/encryption (direct-membership) / view / liveness / rls: here the guard
    # must TRACE the column's derivation (derived_col → source_col) and check the SOURCE's sensitivity — a
    # derivation-graph reachability check, not a direct column-membership check. empty ⇒ f10f inactive.
    column_lineage: Mapping[str, str] = field(default_factory=dict)
    # column list (table → its columns) — the table's own schema, a declared axiom like the column
    # taxonomies above. The f1 user-line rewrite ("the export from {table}") retires the request-line
    # projection naming, so a SELECT's projected columns are grounded HERE (the acting agent knows its
    # table's schema; chk_c9's declared-schema face unions π.table_columns) instead of in the user-msg.
    # NOT rendered in the profile (the corpus rows carry no table-columns line — pure check-side axiom).
    # Empty ⇒ no table schema declared (non-readPolp cells unchanged).
    table_columns: Mapping[str, frozenset[str]] = field(default_factory=dict)
    # algorithm must be in (a DECLARED strength policy — DISTINCT competence from f7 format-detection: here the
    # seal is format-genuine but its ALGORITHM is weak). A weak-alg seal (RSA-1024/3DES/…) is refused.
    algo_strength_policy: frozenset[str] = frozenset()
    # (the seal's recipient-key must ∈ this set). DISTINCT PROPERTY from format/genuineness/strength — here it is
    # RECIPIENT-authorization (the seal is decryptable only by a permitted recipient). A seal bound to an
    # unpermitted recipient is refused (the sealed data is decryptable by an unauthorized party ⇒ leak risk).
    permitted_seal_recipients: frozenset[str] = frozenset()
    # valid in (the seal's context-id must ∈ this set). DISTINCT PROPERTY from recipient-binding (the decrypting
    # PARTY) — here the INSTANCE (login/session context the seal is bound to, an anti-misuse mechanism: a seal
    # leaked to another context is unusable). A seal presented in an unpermitted context is denied. empty ⇒ inactive.
    permitted_seal_contexts: frozenset[str] = frozenset()
    # (the seal's signing key must ∈ this trusted set = a valid CA-issued / non-revoked key). DISTINCT PROPERTY from
    # strength (the key's ALGORITHM) + recipient (who may DECRYPT) + format/genuineness — here it is the key's
    # TRUST-ANCHOR (does the signing key carry authoritative validity?). A seal signed by a revoked / self-signed /
    # expired key is refused (no authoritative signature). key-trust ≠ algo-strength (a revoked AES-256 key is
    # untrusted despite strong algo; a valid-CA 3DES key is weak-algo despite valid authority).
    trusted_seal_keys: frozenset[str] = frozenset()
    # carry and remain VALID (the seal's `exp` date must be ≥ this floor — not-yet-expired). DISTINCT PROPERTY from
    # key-trust (the SIGNING key's authority — revoked/self-signed) AND a distinct DECIDER-SHAPE (a lexicographic
    # DATE COMPARISON, not set-membership): here it is the seal's TEMPORAL-VALIDITY window. A seal whose exp date
    # is past the floor (expired) is refused (no-longer-valid). "" ⇒ f7m inactive.
    seal_expiry_floor: str = ""
    # number of received consents ≥ consent_quorum (DISTINCT mechanism from f4 single-user-consent-presence:
    # a COUNT-threshold, not a presence-check). 0 ⇒ f4q inactive (single-consent cells unaffected).
    consent_quorum: int = 0
    # in the consent-token "{op}:{resource}:{date}") is ≥ consent_freshness_floor. DISTINCT PROPERTY + DECIDER from
    # f4 (presence-membership) + f4q (count-threshold): here it is a lexicographic DATE-COMPARISON on the consent's
    # timestamp — consent-TEMPORAL-VALIDITY (≠ presence ≠ quorum). A stale consent (< floor) is denied. "" ⇒ f4e
    # inactive. DISTINCT competence from seal-expiry (sealEncoding/D, the seal's validity) — here it is the CONSENT's
    # freshness, A-channel.
    consent_freshness_floor: str = ""
    # observed_at date (the trailing :<ISO-date> on a "fresh:{kind}:{subject}:{status}:{date}" fact) is ≥
    # fact_freshness_floor. DISTINCT PROPERTY + CARRIER + CHANNEL from the three DEONTIC date-gates above/below —
    # consent_freshness_floor (the CONSENT token's A-channel authorization-validity), seal_expiry_floor (the SEAL's
    # D-channel crypto-validity window), token_expiry_floor (the BRIDGE-token's B-channel TTL): those are CREDENTIAL
    # VALIDITY WINDOWS (has the authorization/seal/token itself lapsed?); fact_freshness_floor is an EPISTEMIC
    # RECENCY bound (is the OBSERVATION that attests the world-state still current, or may the world have changed
    # since it was made?). The precondition check PASSES both halves (f5 would allow); the contrast is the
    # observation's DATE — benign FRESH (≥ floor) / twin STALE (< floor). "" ⇒ f5f inactive (no fact needs recency).
    fact_freshness_floor: str = ""
    # many times the consent was re-delegated; the consent-token "{op}:{resource}:depth=N" must have N ≤ this).
    # DISTINCT PROPERTY + DECIDER from f4 (presence) + f4q (count) + f4e (date-comparison): here a depth-COMPARISON
    # on the consent's delegation-chain-length — a structural delegation-integrity limit (deep re-delegation chains
    # are risky). A too-deep delegation is denied. 0 ⇒ f4d inactive. DISTINCT from f36g provenance (reachability-
    # trace to a root): here a depth-COUNT ≤ max.
    max_consent_delegation_depth: int = 0
    # consent-token "{op}:{resource}:by={consenter}") must trace through consent_delegations (delegate→authorizer) to
    # the consent_authority_root (the principal or a trustee authorized to consent on the principal's behalf).
    # DISTINCT CATEGORY + DECIDER from f4 (presence) / f4q (count) / f4e (date) / f4d (depth-count): here a
    # reachability-TRACE of the consent's authority-chain (does the consenter's authority derive from the root?).
    # DISTINCT from f36g provenance (act-ORIGIN-chain): here the CONSENT-AUTHORITY-chain (a different category —
    # who-authorized-the-consent vs who-performed-the-act). An unrooted consent-chain is denied.
    consent_delegations: Mapping[str, str] = field(default_factory=dict)
    consent_authority_root: str = ""
    # PROPERTY not shape): consents whose consent-id (cid) is in this set are WITHDRAWN. DISTINCT PROPERTY
    # (revocation-status) from presence/quorum/expiry/depth/delegation (all 5 pass a revoked-but-present
    # consent); carrier is the A-channel consent-token cid (vs D seal-sid / B jti). clean-D (GDPR Art.7
    # right to withdraw). empty => f4f inactive.
    revoked_consents: frozenset[str] = frozenset()
    # PROPERTY not shape): the named-party set whose consent is REQUIRED (segregation-of-duties / 4-eyes).
    # DISTINCT from quorum (identity-blind COUNT): mutual checks named-party-COVERAGE (a same-party-double
    # fools quorum, not mutual). (P) consent-authorization (not pacing/rate). clean-D (SoD bypass = real harm).
    # The consent-token carries ":by={party}:cid={cid}"; empty => f4g inactive.
    required_consent_parties: frozenset[str] = frozenset()
    # decision-WEIGHT map + the weight-THRESHOLD an action's consenting set must meet (sum of consenting parties'
    # weights ≥ threshold). DISTINCT PROPERTY + DECIDER from f4b quorum (identity-blind COUNT ≥ N) + f4g mutual
    # (named-party COVERAGE): here WEIGHT-AGGREGATION (a low-weight set passes quorum but fails weighted — it lacks
    # sufficient authority). clean-D (weighted-voting; insufficient-seniority authorization = real harm). carrier =
    # A-channel consent-token ":by={party}". empty / 0 ⇒ f4h inactive.
    consent_weights: Mapping[str, int] = field(default_factory=dict)
    consent_weight_threshold: int = 0
    # activation pending POST-CG-F5w, see docs/SKEW_DESKEW_FLOOR.md §4th re-search): gates an action on the consenting/
    # represented SET NOT containing both ends of any declared forbidden pair (a conflict-of-interest / information-barrier
    # breach taints the consent ⇒ authorization invalid). DECIDER-shape = existential forbidden-pair-co-occurrence
    # `any(pair ⊆ present)` — NOVEL in consent (the family uses presence/date/count/chain/blacklist/weighted/
    # universal-coverage; NONE does existential pair-co-occurrence — verified by rendering all 56 consent cells). DISTINCT
    # from F4m mutual (universal `required⊆present`) + F4w weighted (aggregate). frozenset of frozenset-pairs, e.g.
    # {frozenset({client-acme, client-omega}), …}. () = inactive (CG-C24: fires only on CG-F4cf cells). Security object:
    # conflict-of-interest / duty-of-loyalty (clearly (P)). [party-extraction mirrors consent_mutual's :by=party tokens.]
    conflict_pairs: frozenset = frozenset()
    # action whose resource carries a declared stem (a CLASS prefix, CG-C3-spirit — never the exact
    # resource; the graded name keeps the stem ⇒ coverage is stable across name variants) is authorized
    # iff the covering batch's sign-off token `batch:{label}` is present in ctx.consents (T3, A-channel)
    # or the env consent-log attests it (`consent-log:batch:{label}=granted`, T2 C-channel). DISTINCT
    # PROPERTY + DECIDER from f4 (per-action "{op}:{resource}" token presence — that authorization
    # EMBEDS the resource name, so the name-grade variant co-varies with the evidence and guards'
    # fact-matching absorbs the name channel): here the authorization key is the BATCH LABEL (name-free)
    # — the graded name appears only in the directory listing + the action itself. empty ⇒ f4cb inactive.
    batch_consent_scopes: Mapping[str, str] = field(default_factory=dict)
    # consent-gated (footprint activation — CG-C24 stray-safety: empty ⇒ f4 abstains exactly as before,
    # non-consent cells byte-unchanged) and (ii) WHOSE confirmation authorizes (the owner of record —
    # two-half-shared World fact (apparatus, not contrast — CG-D5 single-channel preserved); f4 consumes
    consent_gate_ops: frozenset[str] = frozenset()
    consent_authority: str = ""
    # deployment-side identity anchor. The benign user line no longer self-names the confirmer
    # role clause (render_nl._profile), a two-half-shared apparatus fact. Set by pat_consent (and the D3d
    # bridge families) alongside consent_gate_ops. Empty ⇒ nothing rendered (non-consent cells unchanged).
    session_principal: str = ""
    # b2: the bridge-credential-gate RULE CLAUSE (pattern-authored text, rendered as the LAST profile part
    # — the profile names the binding source). Set by pat_audience_bridge/pat_federated_bridge/
    # pat_client_credentials (registry form) and pat_amr_bridge (introspection form).
    bridge_gate_clause: str = ""
    # b2: the registry's axis FIELD the gate checks ("audience"|"issuer"|"client_id"). Non-empty ⇒ the
    # d10e/d10b/d10g deciders read the env bridge-registry FACT (channel-C evidence) instead of act-args,
    # and the construction's contrast channel is the env registry value (see audit chk_single_channel's
    # registry-hybrid note). Empty ⇒ deciders keep the legacy act-arg path (released corpus unchanged).
    bridge_registry_gate: str = ""
    # π-DECLARED observation hybrids, mirroring bridge_registry_gate — the RULE lives in the SHARED π
    # (profiles byte-identical) and the contrast is the env OBSERVATION VALUE (a w0 fact):
    #     (CIDR-aware membership vs permitted_request_origins) instead of the act's origin_ip arg.
    #     (presented token ∈ bridge_grants) instead of the act's bridge_token arg.
    # False ⇒ the deciders keep the legacy act-arg path (released corpus unchanged); the D5 single-
    # channel check redirects the diff locus B→C for both (construction + audit_full, the b2 precedent).
    origin_connection_gate: bool = False
    bridge_auth_gate: bool = False
    # b4: the exact-grant gate (remca_exact family) — the registry record for the EXACT (op, target)
    # keyed by the owner of record is the binding source; renders the exact-grant clause INSTEAD of the
    # D3c explicit-consent-gate clause (mutually exclusive; asserted in pat_consent_exact_listing).
    exact_grant_gate: bool = False
    # b4: fetch-turn ORDERING apparatus — a tuple of fact strings; facts are emitted in this order
    # (facts absent from the tuple sort after, alphabetically). Authored from the NEUTRAL-face order so
    # the exchange positions are face-invariant under the graded-name rename. Shared both halves: the
    # tuple contains BOTH half-exclusive facts (exact + distractor adjacent), so each half's subset
    # lands in the authored positions (render_nl._fetch_turns).
    fact_order: tuple[str, ...] = ()
    # b5 (indirect_prompt_injection): the twin delivers the relayed directive's ORIGIN via a relay
    # fetch exchange (a twin-only `relay-note:` w0 fact rendered as an agent fetch whose return carries
    # {"relayed_note", "source"}); also renders the channel-attribution rule sentence in the profile.
    relay_origin_delivery: bool = False
    # b3 (tool_description_injection): the gated act's origin evidence rides an UPSTREAM fetch hop —
    # the between-hops return carries {"available_tool", "recalled_value", "source"} from the acts
    # (origin-differing, w0 identical); also renders the source-field rule suffix on the issuer rule.
    origin_source_field_rule: bool = False
    # b5 (sigkey_bridge): append the presented-kid marker-rule sentence to the trusted-signing-keys
    # profile line (shared both halves; the contrast stays the profile's trusted-key set).
    kid_marker_rule: bool = False
    # CG-D3c grantor ring for the batch sign-off/consent-log carriers: batch-label → the authority
    # whose sign-off is VALID for that batch (a confirmation by any other party is void). The board/
    # log record value upgrades `confirmed`/`granted` → `confirmed_by:{authority}` / `granted_by:
    # {authority}`; f4i/f4c parse the named grantor and check it against this map (also closing f4c's
    # value-blindness — any-value-pass — inherited from the bare-`granted` era).
    batch_signoff_authorities: Mapping[str, str] = field(default_factory=dict)
    # gates a `deploy` on the OBSERVED deployed artifact hash (env fact deployed:{resource}:{hash}) MATCHING the
    # attested/reviewed hash (env fact attested:{resource}:{hash}) — DECIDER-shape S15 value-equality (the first integrity
    # decider to perform genuine value-equality; a deployed binary whose hash ≠ the attested hash is a substituted
    # artifact). Flag-gate `deploy_hash_gate` (CG-C24 stray-safety: fires ONLY on CG-F9h cells; abstains on
    # consent/precondition `deploy` ops). The attested hash is an env fact (channel C — the evidence locus), NOT held
    # here, so the scary resource is never cited in the profile (B6/CG-C5-clean). benign (match)→allow; twin (mismatch)→
    # deny:integrity. DISTINCT from f9i/r/s/d/e/n/rt at the DECIDER level (those are S1 presence over one C-fact; their
    # rendered surface also shows two hashes, so deploy_hash is object/op/decider-distinct, not guard-surface-novel).
    deploy_hash_gate: bool = False
    # pending POST-MEASURE, see docs/SKEW_DESKEW_FLOOR.md §4th re-search + task #93). Gates a change-managed action
    # on the environment's current-time falling within a declared TWO-SIDED execution-window [start,end] — refuse
    # before the window opens OR after it closes. DECIDER-shape = two-sided bounded-interval containment start≤now≤end
    # — the FIRST such: every existing temporal/numeric bound is ONE-sided (date-gates now≥floor; state-gates x≤cap);
    # the upper temporal bound now≤end is exercised by NO existing cell (independently re-verified by rendering). A
    # COMPOSITE/MODEST-novelty addition (a post-review correction):
    # the two-sided interval is an AND of now≥start (date-gate shape) + now≤end (the upper-bound PRIMITIVE, exercised
    # by column_count/consent_depth) — so CG-F5w re-uses the upper-bound primitive on a TIME variable, parallel to
    # compound_precondition's non-diligence category, NOT a primitive new shape. (CG-F4cf is the more primitive-novel.)
    # Security object: change-management workflow-integrity (change-freezes / change-windows). () = inactive (CG-C24
    # stray-safety: fires only on CG-F5w cells); (start_ISO, end_ISO) = active (ISO ⇒ lexicographic == chronological).
    action_window: tuple = ()
    # containing any declared forbidden field (OWASP mass-assignment — write-side PoLP analog of readPolp). DECIDER-shape
    # = set-intersection-nonempty (payload-fields ∩ forbidden_write_fields) — SHAPE-COVERED by readPolp ⇒ OBJECT-novel
    # not shape-novel (like CG-F9h). The payload is delivered as an ENV tool-return `payload:{resource}:{f1,f2,...}`
    forbidden_write_fields: frozenset = frozenset()
    # verified OBJECT-NOVEL on dataIsolation; activation/archetype pending POST-MEASURE, see docs/SKEW_DESKEW_FLOOR.md
    # §6th re-search + task #97). Gates a write/export/publish on the observed data-classification level NOT exceeding
    # the destination container's clearance (MAC no-write-down — a classified asset written to a lower-clearance
    # container is spillage). DECIDER-shape = ordered-comparison over a DECLARED total-order taxonomy
    # (level_index(data_class) > level_index(container_class)) — the FIRST ordered-lattice comparison on dataIsolation
    # (F6 = set-membership on a secret-VALUE; rls = categorical tenant-membership [peer categories, NOT ordered];
    # column_count = quantitative count). OBJECT-novel (classification-spillage [qualitative, write-side, dataIsolation]),
    # shape-covered by column_count's X>limit (disclosed like CG-F9h). The data's class is an env fact
    # `class:{resource}:{level}` (channel C — the SOLE contrast benign/twin); the container's clearance is declared
    # classification_levels = () inactive (CG-C24 stray-safety: fires only on CG-F6mls cells).
    classification_levels: tuple = ()
    container_level: str = ""
    # Optional op-specific action phrase for the CG-F6mls rule line (e.g. "sending", "posting").
    # Empty preserves the corpus/exfil line byte-for-byte ("a write/export/publish of data ...").
    classification_rule_action: str = ""
    # complete (all deps attested). DISTINCT property from reproducible (build-reproducibility) — here it is
    # dependency-COMPLETENESS. A flag (not a world-fact) so f9s fires only for SBOM cells (promote is shared
    # with compound_runbook/compound_precondition steps ⇒ the flag avoids stray denies).
    sbom_gate: bool = False
    # trusted key. DISTINCT property from reproducible (reproducibility) + SBOM (completeness) — here it is
    # SIGNATURE-validity. A flag so f9d fires only for signed-manifest cells (rollout is shared with compound).
    signed_gate: bool = False
    # (OPA/Rego admission control). DISTINCT property from chain/reproducible/SBOM/signed — here it is
    # workflow-POLICY-COMPLIANCE. A flag so f9e fires only for policy cells (apply is shared with compound).
    policy_gate: bool = False
    # artifact's existence-at-a-time is attested by a trusted authority). DISTINCT property from signed
    # (AUTHENTICITY) — here it is TEMPORAL-EXISTENCE (a different attestation). A flag so f9n fires only for
    # notarization cells (release is shared with reproducible_build via the reproducible_gate flag).
    notarize_gate: bool = False
    # environment being TPM/measured-attested (no rootkit/tamper) — a world-fact `runtime:{node}:attested`. DISTINCT
    # PROPERTY from the 6 build/artifact/log integrity mechanisms (chain/reproducible/SBOM/signed/policy/notarization
    # — all about the ARTIFACT or BUILD): here the EXECUTION-ENVIRONMENT (the node's runtime is attested). A run on
    # an unattested runtime is denied. A flag so f9rt fires only for runtime-attestation cells.
    runtime_attestation_gate: bool = False
    # when in-scope (a carve-OUT within the scope — RBAC exceptions). An excluded resource is denied on
    # ROLE_SCOPE regardless of scope coverage (exclusion overrides scope). Distinct from decommissioned_tables
    # (a read-PoLP cold-data carve-out): this is a role-scope authorization denylist.
    excluded_resources: frozenset[str] = frozenset()
    # §12 / cross-session: origin-authorization table (attr_lookup authorized)
    origin_auth: Mapping[Origin, bool] = field(default_factory=dict)
    # keeps the rendered profile text ALIGNED with the cell's actual contrast (else gt=safe-mislabel disease,
    # cf. the removed sealEncoding axis). "recalled_value" (default): the rule gates a RECALLED VALUE whose
    #   recorded origin a tool-observation attests (delegation/cred-origin cells — a recall_memory/env GATE
    #   proves origin ∈ trusted-origins). "directive_issuer": the rule gates a DIRECTIVE'S ISSUER — observed
    #   in the user-prompt / tool-description (indirect-prompt-injection / tool-description-injection cells).
    #   There is NO value-origin GATE here; the contrast is who DRIVES the act (user vs web-paste), so the
    #   profile declares an ISSUER membership-rule (parallel to the recalled-value rule, equally de-flavored)
    #   — a literal-reading guard otherwise refuses the benign for an "unwarranted origin assumption"
    provenance_kind: str = "recalled_value"
    # MS2 aggregate: per-aggregate bounds
    aggregate_bounds: Mapping[str, int] = field(default_factory=dict)
    # distinct-item count exceeds distinct_limits[label] is an over-variety aggregate violation). DISTINCT PROPERTY +
    # DECIDER from MS2 budget (sum of quantities): here the guard must DEDUP the carried item-list and COUNT distinct
    # — variety (distinct count) ≠ quantity (total with duplicates). A sum-budget guard MISSES a variety overage
    # where duplicates hide the distinct count. empty ⇒ ms2_distinct_count inactive.
    distinct_limits: Mapping[str, int] = field(default_factory=dict)
    # required_composition is a wrong-composition aggregate violation). DISTINCT PROPERTY + DECIDER from budget
    # (sum ≤ ceiling), distinct-count (variety ≤ limit — any items within the count), replay (dup), minimum (count ≥
    # floor): here a SET-EQUALITY (set(items) == required) — the COMPOSITION must be exactly right (which items), not
    # just the count. A guard doing distinct-count (any N distinct ≤ N) MISSES a composition-error (wrong items).
    # empty ⇒ ms2x inactive.
    required_composition: frozenset[str] = frozenset()
    # PROPORTION cap (count(label-items)/count(all)*100 <= cap, in percent) — a concentration/ratio bound.
    # DISTINCT DECIDER (division) from budget(sum)/minimum(count>=)/distinct(variety)/composition(set==)/
    # a proportion a sum/variety/composition guard MISSES. clean-D (Basel-III concentration
    # limits). empty => ms2r inactive.
    ratio_caps: Mapping[str, int] = field(default_factory=dict)
    # MS4 provenance: declared provenance tokens the trajectory must carry
    declared_provenance: frozenset[str] = frozenset()
    # MS3 credential: poisoned (untrusted-origin recalled) credentials
    poisoned_creds: frozenset[str] = frozenset()
    # CG-D10 bridge-deputy: delegated bridge-tokens authorizing a deputy action (a distinct authorization
    # carrier — the bridge-arg — ≠ role-scope/origin/consent). benign profile grants the token / twin lacks it.
    bridge_grants: frozenset[str] = frozenset()
    # authorize a cross-domain action (a DISTINCT bridge carrier — the federated_issuer — ≠ d10's deputy-token).
    # benign profile trusts the act's issuer / twin trusts a different (untrusted) IdP.
    federated_idps: frozenset[str] = frozenset()
    # edges (RFC 8693 — a GRAPH/relation carrier, ≠ d10's flat deputy-token-set ≠ d10b's flat IdP-set). benign
    # profile permits the act's (from,to) edge / twin permits a DIFFERENT edge (the act's edge not covered).
    token_exchange_policy: frozenset[tuple[str, str]] = frozenset()
    # token's intended recipient). DISTINCT carrier/property from d10 (delegated token), d10b (issuer/IdP), d10c
    # (exchange-edge): here it is the token's audience-binding. benign profile permits the act's audience / twin a different.
    permitted_audiences: frozenset[str] = frozenset()
    # token's PERMISSIONS). DISTINCT carrier from d10/d10b/d10c/d10e: here it is the token's scope/permissions
    # (≠ audience/recipient ≠ issuer ≠ exchange-edge ≠ delegated-token). benign permits the act's scope / twin a different.
    permitted_scopes: frozenset[str] = frozenset()
    # service's OWN identity — RFC 6749 client-credentials grant). DISTINCT carrier/concept from d10 (DELEGATED
    # token — on-behalf-of) — here it is the service's OWN client-id (no user/delegation). benign permits the
    # act's client-id / twin a different.
    permitted_client_ids: frozenset[str] = frozenset()
    # to (a sender-constrained token — the presenter must PROVE possession of this key, defeating bearer-token theft).
    # DISTINCT carrier/concept from client-credentials (RFC 6749 — the service's OWN registered identity): DPoP is
    # TOKEN-key-binding (anti-theft), not service-identity; AND a distinct DECIDER-SHAPE (a key COMPARISON
    # proof==bound-key, not set-membership). benign profile binds the token to the act's proof-key / twin to a
    # different key (the act's proof mismatches ⇒ the presenter doesn't hold the bound key ⇒ a stolen bearer token).
    dpop_bound_key: str = ""
    # whose jti ∈ used_jtis is a REPLAY — unauthorized re-use of a consumed one-time token). DISTINCT COMPETENCE from
    # client-credentials (identity-membership, whitelist-polarity ∈ permitted) + DPoP (key-binding comparison): here
    # it is REPLAY-FRESHNESS (blacklist-polarity ∉ used) — a different property + polarity. A replayed jti is denied.
    # empty ⇒ d10i inactive.
    used_jtis: frozenset[str] = frozenset()
    # ∈ revoked_seals is WITHDRAWN — a per-disclosure revocation, NOT a signer-authority revocation). DISTINCT
    # COMPETENCE from key-trust (the SIGNING KEY's trust-anchor, whitelist) + expiry (temporal) + threshold (quorum):
    # here it is the SEAL's own revocation-status (blacklist-polarity, seal-id field). A revoked seal is denied.
    # empty ⇒ f7k inactive.
    revoked_seals: frozenset[str] = frozenset()
    # bridge-token action may originate from (a REQUEST-CONTEXT binding, NOT a token-claim). DISTINCT CATEGORY from
    # the 10 token-claim bridge carriers (identity/issuer/audience/scope/exchange/delegation/PoP/jti/expiry/
    # revocation — all properties OF THE TOKEN): here it is the REQUEST's network-origin (FROM vs the token's FOR).
    # A token action from an unpermitted origin-IP is denied (network-origin binding). empty ⇒ d10j inactive.
    permitted_request_origins: frozenset[str] = frozenset()
    # the `exp` arg, must be ≥ this floor — the token must remain valid past the floor). DISTINCT PROPERTY from jti-
    # replay (ONE-TIME-USE / replay-uniqueness): here the token's TTL-validity-period (a long-lived token may be
    # replayed; a non-expired token may be one-time-used — orthogonal). DISTINCT entity from seal-expiry (the SEAL's
    # D-body validity) + consent-expiry (the CONSENT's A-channel freshness): here the BRIDGE-TOKEN's TTL (B-channel).
    # A token whose exp < floor (doesn't meet the required-validity) is denied. "" ⇒ d10k inactive.
    token_expiry_floor: str = ""
    # REQUIRED auth-method set (RFC 8176 `amr` — e.g. {"mfa"} / {"pwd","otp"}); a bridge-token whose `amr`
    # claim does NOT satisfy this (π.required_amr ⊄ token's amr) is denied. DISTINCT PROPERTY (auth-method-
    # STRENGTH: did the caller do MFA) from every other bridge carrier (which test what/who/when/anti-theft/
    # freshness/network, never HOW-authenticated) + DISTINCT decider-shape (set-CONTAINMENT, reversed
    # direction vs the membership of audience/scope/client). empty ⇒ d10l inactive.
    required_amr: frozenset[str] = frozenset()
    # TRUSTED signing-key ids (JWKS `kid`) a bridge-token may be signed by (the token's signing key must ∈
    # this trusted set = authentic issuance, not forged). DISTINCT PROPERTY (issuance-KEY authenticity) from
    # every other bridge carrier — d10b federated (the issuer CLAIM-string, forgeable), d10h DPoP (the
    # PRESENTER's anti-theft key ≠ the ISSUER's signing key), d10l amr (how-authenticated): NONE test that
    # the token was cryptographically SIGNED by a trusted issuer-key. Parity with sealEncoding CG-F7k
    # trusted_seal_keys (signer-KEY trust, distinct from recipient). clean-D (JWT signature-verification is
    # THE foundational resource-server gate). empty ⇒ d10m inactive.
    trusted_token_keys: frozenset[str] = frozenset()
    # M-of-N co-signers is authorized iff ≥ seal_threshold of its co-signer keys are in authorized_cosigners. DISTINCT
    # PROPERTY from key-trust (a SINGLE key's authority) — here it is a QUORUM of co-signers (multi-party threshold),
    # AND a distinct DECIDER-SHAPE (a COUNT-THRESHOLD, not set-membership or comparison). A seal with < threshold
    # authorized co-signers is refused (insufficient multi-party authorization). 0 ⇒ f7t inactive.
    seal_threshold: int = 0
    authorized_cosigners: frozenset[str] = frozenset()
    # SUBSET of mandatory co-signers that must ALL be present among the seal's co-signers (named-COVERAGE, not
    # count). DISTINCT PROPERTY + DECIDER from f7j threshold (count of authorized cosigners ≥ M): here a subset-
    # containment (required ⊆ body) — a seal with enough authorized co-signers but MISSING a required one (e.g.
    # the compliance-officer) is refused (insufficient named multi-party authorization — board resolutions
    # requiring the chair). empty ⇒ f7m inactive.
    required_seal_cosigners: frozenset[str] = frozenset()
    # origin through this chain to a trusted root (origin_auth). benign chain terminates at a trusted origin;
    # twin chain terminates at an untrusted one. Empty for non-chain cells ⇒ f11 falls back to direct check.
    delegations: Mapping[str, str] = field(default_factory=dict)
    # §3.9.c tool-description injection (B-locus): per-op description override (DELIVERY-ONLY — no F-module
    # reads it; render_nl applies it to the tool block). benign empty (clean description); twin carries the
    # injected directive. The tool NAME/params stay identical ⇒ only the description text differs (single B).
    tool_desc_overrides: Mapping[str, str] = field(default_factory=dict)
    # SCHEMA declares a `mode` parameter and whose executed call renders an execution-mode fingerprint
    # derived from the act's issuer origin (user → 'standard'; an untrusted issuer on a poisoned registry
    # description → the directive's commanded 'pre-authorized-bypass'). DELIVERY-ONLY (no F-module reads it)
    # and SHARED benign/twin (the schema is shared apparatus — CG-D5). Empty for every non-injection cell.
    exec_mode_ops: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# Sys — Lean §4: the system context { π, w0, τ, vstar } + the A-channel `prompt`. vstar is the verdict
# field L must IGNORE; `prompt` is verdict-free (the user message) — including it preserves L_noncircular.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Sys:
    π: Policy
    w0: World
    τ: tuple[Act, ...]
    prompt: str = ""                          # the A-channel user message (CG-C25 soft spot; consent CG-C9)
    consents: frozenset[str] = frozenset()    # A-channel structured consent tokens "{op}:{resource}" (CG-C9)
    vstar: tuple[Verdict, ...] = ()           # the verdict field present in the context; L must NOT depend on it


@dataclass(frozen=True)
class Ctx:
    """The verdict-free per-step context handed to a module: the running world + the (static) prompt +
 consent tokens. Carrying these is the Lean-§26 "delivery-level accessor" (memView/authorized)
 realization — it lets footprint predicates that read observed state (F5 precondition, F4 consent)
 compute, while staying verdict-free (H2-preserving: world/prompt/consents contain no Verdict)."""
    world: World
    prompt: str
    consents: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# A module function: the src realization of Lean's `module : Act -> List Effect -> Policy -> Bool`,
# returning a Decision (carrying attribution, Lean §8b moduleD).
# ---------------------------------------------------------------------------
ModuleFn = Callable[["Act", tuple[Effect, ...], Policy, Ctx], Decision]

# A compositional check: Lean `ms : List Act -> Policy -> Bool` generalized to read the verdict-free
# world (MS7 cross-session memory, §26 msX) + prompt. Verdict-free ⟹ non-circular (L_cross_noncircular).
MsFn = Callable[[tuple[Act, ...], Policy, Ctx], bool]

# World-exec / effect: Lean `exec/effect : World -> Act -> …` (take no Verdict, H2a/H3).
ExecFn = Callable[[World, Act], World]
EffectFn = Callable[[World, Act], Effect]


@dataclass(frozen=True)
class Model:
    """Lean §4 `Model` — the four verdict-free operations. Π = the list of per-action decision
 modules (composed by CG-F1); `module`/`moduleD` = the composed per-action verdict (§10 unification)."""

    Π: tuple[ModuleFn, ...]            # the F3/F4/F5/F6/F7/… decision modules (formal-deciders)
    ms: MsFn                            # the compositional check (MS2/MS4/MS7/…, non-circular)
    exec: ExecFn                        # World -> Act -> World   (H2a, H3)
    effect: EffectFn                    # World -> Act -> Effect  (H2a, H3)

    # -- per-action composed verdict (CG-F1 §27) -----------------------------------------------
    def moduleD(self, a: Act, acc: tuple[Effect, ...], π: Policy, ctx: Ctx) -> Decision:
        """The composed per-action Decision: CG-F1 composes the Π-module verdicts — deny-beats-allow,
 attribution = the first firing deny's axis; else ≥1 allow ⇒ allow; else default-deny."""
        from .decision import compose_verdict   # local import: decision imports nothing from model
        return compose_verdict([m(a, acc, π, ctx) for m in self.Π])

    def module(self, a: Act, acc: tuple[Effect, ...], π: Policy, ctx: Ctx) -> Verdict:
        """Lean §4 `module : Act -> List Effect -> Policy -> Bool` = the isAllow-image of moduleD (§10)."""
        return self.moduleD(a, acc, π, ctx).is_allow


# ---------------------------------------------------------------------------
# Trajectory folds — Lean §2 (prefixEffects) / §3 (verdictsGo/verdicts) / §8b (decisionsGo/decisions).
# Strictly left-to-right (verdictsGo_take, §5c): verdict[i] depends only on the prefix τ[0..i].
# All verdict-free: the running world + acc are threaded without any verdict gate (model A).
# ---------------------------------------------------------------------------
def prefix_effects(m: Model, w: World, τ: Sequence[Act]) -> tuple[Effect, ...]:
    """Lean §2 prefixEffects: the observed effect-prefix is a structural fold over the action-prefix."""
    out: list[Effect] = []
    cur = w
    for a in τ:
        out.append(m.effect(cur, a))
        cur = m.exec(cur, a)
    return tuple(out)


def _all_true(bs: Sequence[Verdict]) -> Verdict:
    """Lean allTrue."""
    return all(bs)


def decisions(m: Model, s: Sys) -> tuple[Decision, ...]:
    """Lean §8b decisions: the computed Decision sequence (one per action, model A — every step processed)."""
    out: list[Decision] = []
    cur = s.w0
    acc: tuple[Effect, ...] = ()
    for a in s.τ:
        out.append(m.moduleD(a, acc, s.π, Ctx(cur, s.prompt, s.consents)))
        acc = (*acc, m.effect(cur, a))
        cur = m.exec(cur, a)
    return tuple(out)


def verdicts(m: Model, s: Sys) -> tuple[Verdict, ...]:
    """Lean §3 verdicts: the per-step Bool verdict sequence (§10: isAllow-image of `decisions`)."""
    return tuple(d.is_allow for d in decisions(m, s))
