# ADR-0011: v2 wire contracts and logical-event conversion

**Status:** Proposed
**Date:** 2026-07-14
**Issue/PR:** ROADMAP Week 2 ("Establish wire and compatibility contracts")

## Context

The target data plane (`ARCHITECTURE.md`, `docs/LLD.md`) fixes three wire
surfaces: a public **protobuf** control contract (LLD §22), an internal
**FlatBuffer** telemetry frame (LLD §23), and an analytical **Arrow** logical
schema and browser stream (LLD §9.2, §24). Today the shipped gateway speaks
only the v1 `aegis.proto`/`soc.proto`/`admin.proto` control surface plus REST
models; there is no v2 skeleton, no FlatBuffer/Arrow schema, and no
cross-format conversion corpus. ROADMAP Week 2 requires these contracts to be
**defined and frozen** — field numbers reserved, opaque payloads mapped to
`Bytes`, and a differential corpus proving equality across representations —
before any typed-service extraction (Week 3, now landed) or shadow ingest
depends on them.

Per repository law (`CLAUDE.md`, `docs/architecture.md`), target-module
additions enter only as **unwired prototypes under a Proposed ADR** until
accepted. This ADR governs that prototype phase for all three wire surfaces.

## Decision

Introduce the v2 wire contracts as unwired prototypes, phased so each format
lands with its own round-trip/malformed gate rather than in one drop:

1. **protobuf v2 control skeleton (this increment).** Add
   `lib/api/proto/aegis_v2.proto` in package `aegis.v2`, transcribed from
   LLD §22, with **permanent `reserved` field-number ranges** on every message.
   Generate it beside the wired v1 protos through a **separate**
   `tonic_build::configure()` call so v1 output stays byte-identical, and map
   `IngestFrame.flatbuffer_frame` and `ArrowChunk.ipc_message` to
   `::prost::bytes::Bytes` via `.bytes([...])` (LLD §22) to avoid a forced
   `Vec<u8>` clone on the ingest/query streaming paths. Expose generated types
   under `aegis_api::grpc::aegis_v2`; nothing serves or dials them.
2. **FlatBuffer telemetry v2 (follow-on).** Transcribe LLD §23
   (`aegis.wire.v2.SecurityEvent`, `file_identifier "AEF2"`), with generated
   verification, bounded length/depth limits, and defined verifier error codes,
   introducing the `flatbuffers` build/runtime dependency under this ADR.
3. **Arrow logical schema (follow-on).** Define the LLD §9.2 event schema, its
   schema fingerprint, and the `AAS2` browser envelope, introducing the
   `arrow` dependencies under this ADR.
4. **Logical-event conversion corpus (follow-on, spans 1–3).** A single neutral
   logical event with converters to/from REST model, protobuf v2, FlatBuffer,
   and Arrow, gated on round-trip/differential equality plus malformed
   length/depth/version fuzz rejection without allocation spikes.

`ConsumeApprovalRequest` is defined here as a minimal message
(`approval_id`, `request_id`, `nonce`); LLD §22 names it in `DecisionService`
but does not spell out its fields, so the shape is the smallest that satisfies
approval consumption and is itself reserved forward.

## Consequences

- The public control contract is pinned and reviewable now, before any code
  depends on it; field numbers cannot silently drift because every message
  reserves its unused range.
- `Bytes` payload mapping removes a copy on the hot ingest/query paths but means
  those fields carry no schema of their own at the protobuf layer — their
  integrity is delegated to the FlatBuffer/Arrow verifiers landing in phases 2–3.
- Carrying v1 and v2 side by side widens the generated surface of `aegis-api`
  and adds a second `configure()` call to maintain. This is the cost of a
  non-breaking migration; v1 remains the only wired contract.
- `flatbuffers` and `arrow` are heavy new dependencies. They are deferred to
  their own increments so each can be audited (`cargo deny`/`cargo audit`) at
  introduction rather than bundled here.

## Alternatives considered

- **Define all three formats in one change.** Rejected: it would bundle two
  large dependency introductions with the protobuf skeleton, making the
  security/licensing review and the conversion-corpus gate harder to reason
  about, and would violate the "smallest reviewable increment" preference.
- **Edit the existing `aegis.proto` in place to v2.** Rejected: v1 is wired into
  the shipped gateway; renumbering or repackaging it would break the public
  contract. A new package is additive and non-breaking.
- **Skip reserved ranges, add fields as needed.** Rejected: reserving numbers at
  freeze time is the only mechanism that prevents a future contributor from
  reusing a retired number and silently corrupting compatibility.

## Revisit when

The protobuf skeleton needs its first typed `QueryRequest` predicate (before
GA, replacing the opaque `tenant_scoped_plan` bytes), or when a wire surface
must change shape — either requires a new ADR and a supersedes link, not an
edit here.

## Security consequences

This touches the **public API contract** and the **telemetry/evidence carrier**
trust boundaries. In this increment the prototype is unwired, carries no
production traffic, and cannot mint `allow` or a receipt, so the immediate
attacker surface is unchanged. The gates that matter land with the code:
proto3 zero-values resolve to the fail-closed/unspecified enum arm
(`DECISION_UNSPECIFIED`, `TRUST_UNSPECIFIED`) so an absent or zeroed field never
reads as a permissive decision or an elevated trust; malformed length prefixes
and truncated varints are rejected by the decoder without reserving the
advertised capacity. FlatBuffer/Arrow phases carry their own verification-limit
and tenant-binding requirements (LLD §23: frame tenant compared to authenticated
stream context) and require security review before shadow wiring.

## Verification

- `cargo test -p aegis-api --lib wire_v2` — round-trip equality for
  `AuthorizeRequest`/`AuthorizeResponse`, `Bytes`-typed opaque payloads,
  malformed length/varint rejection, and fail-closed enum defaults.
- `cargo check -p aegis-api` — v2 generation compiles beside v1 with no change
  to v1 output.
- Follow-on phases add FlatBuffer verifier fuzz seeds, Arrow schema fingerprint
  stability, and the four-way conversion-corpus differential as their gates.

## References

- `docs/LLD.md` §9.2 (Arrow logical event schema), §22 (protobuf skeleton),
  §23 (FlatBuffer telemetry), §24 (browser Arrow stream)
- `ARCHITECTURE.md` — target wire/performance contract
- `ROADMAP.md` Week 2 — wire and compatibility contracts
- `docs/Implementation_Status.md` — v2 migration ledger
- Prior art: ADR-0006..0010 (event-fabric unwired prototypes under Proposed ADRs)
