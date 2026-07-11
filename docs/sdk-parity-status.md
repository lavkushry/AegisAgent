# SDK parity status

> **Status:** Python and TypeScript integrity/receipt paths are production-ready. Go is beta because prompt/model emission parity remains incomplete; all three pass canonicalization and receipt verification corpora.

AegisAgent ships three first-class SDKs. All canonicalize the action with the
**`aegis-jcs-1`** scheme byte-identically (locked by `tests/canonical_action_vectors.json`
+ `tests/receipt_chain_vectors.json` and a 4-language CI gate), and all enforce the
**fail-closed** contract: refuse to execute on hash mismatch, expired/consumed approval,
or unreachable gateway for a mutating/high-risk action.

| Capability | Python (`sdk-python`) | Go (`sdk-go`) | TypeScript (`sdk-typescript`) |
|---|---|---|---|
| `aegis-jcs-1` canonicalizer | ✅ `canon.py` | ✅ `canon/canon.go` | ✅ `src/canon.ts` |
| Cross-language byte-parity (CI) | ✅ | ✅ | ✅ |
| Authorize / approval client | ✅ `client.py` | ✅ `aegis/client.go` | ✅ `src/client.ts` |
| Fail-closed `protect` wrapper | ✅ `@protect_tool` + `async_protect_tool` | ✅ `aegis.Protect` | ✅ `protect()` |
| Approval polling (+ backoff) | ✅ exponential backoff | ✅ | ✅ |
| Action-hash verification (3 phases) | ✅ | ✅ | ✅ |
| Single-use atomic consume | ✅ | ✅ | ✅ |
| Hash-chained receipt verifier | ✅ `receipts.py` | ✅ `aegis/receipts.go` | ✅ `src/receipts.ts` (shared corpus) |
| Approve/reject a pending approval | ✅ | ✅ (#1183) | ✅ (#1182) |
| SOC query methods (alerts/incidents/summary) | ✅ | ✅ (#1183) | ✅ (#1182) |
| Context-based cancellation on every client call | n/a (Python uses per-call `timeout`) | ✅ (#1183, `context.Context` first param) | n/a (JS uses `AbortSignal` internally) |
| Prompt/model capture emission | ✅ prompt emit | 🟡 incomplete | 🟡 incomplete |

**Reference oracle:** Python is the reference implementation; Go and TS are verified against
the same shared corpus. Any divergence fails CI (`Go SDK canon byte-parity`, `TS SDK canon
byte-parity`, `Corpus byte-equality gate`).

The TypeScript SDK parity goal — client + fail-closed `protect()` + canon, with a strict
`tsc` build and a passing `node --test` suite — is complete; this document records that the
`track/ts-sdk` task stubs are satisfied by the shipped code.

The Go SDK parity goal — `canon` + `aegis.Client` + fail-closed `aegis.Protect` + the receipt
chain verifier, all under `sdk-go/` with `go test ./...` green and the `Go SDK canon byte-parity`
CI gate — is likewise complete; this document records that the `track/go-sdk` task stubs are
satisfied by the shipped code.

## Verification

```bash
python3 -m unittest discover -s sdk-python/tests
(cd sdk-go && go test ./...)
(cd sdk-typescript && npm test && npx tsc --noEmit)
```

Parity requires shared corpus success, not only language-local tests. Compare canonical UTF-8 bytes and receipt verification results across all implementations.

## References

[SDK Guide](components/SDK.md) · [SDK Onboarding](onboarding/For_SDK_Developer.md) · [Canonicalization ADR](adr/0003-aegis-jcs-1-canonicalization.md) · [Implementation Status](Implementation_Status.md)
