package canon

import (
	"encoding/json"
	"os"
	"testing"
)

// loadCorpus decodes a shared corpus file with UseNumber() so JSON numbers are
// preserved as json.Number (not coerced to float64) — exactly how the SDK must
// treat tool-call/receipt numbers to stay byte-identical with Python/Rust.
func loadCorpus(t *testing.T, path string) map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return m
}

// TestCanonicalActionVectors is the cross-language contract: the Go
// canonicalizer MUST reproduce every `canonical` string in the shared corpus
// byte-for-byte (this is what guarantees action_hash parity with the gateway).
func TestCanonicalActionVectors(t *testing.T) {
	data := loadCorpus(t, "../../tests/canonical_action_vectors.json")
	vectors, ok := data["vectors"].([]any)
	if !ok {
		t.Fatal("corpus has no `vectors` array")
	}
	if len(vectors) == 0 {
		t.Fatal("corpus has zero vectors")
	}
	for _, v := range vectors {
		vec := v.(map[string]any)
		name, _ := vec["name"].(string)
		want, _ := vec["canonical"].(string)
		got, err := Canonicalize(vec["tool_call"])
		if err != nil {
			t.Fatalf("%s: Canonicalize: %v", name, err)
		}
		if got != want {
			t.Errorf("%s: canonical mismatch\n got:  %s\n want: %s", name, got, want)
		}
	}
}

// TestReceiptChainVectors validates the canonicalizer + SHA-256 end-to-end: for
// each shared receipt vector, SHA-256(canonicalize(body)) — where body is every
// field except `receipt_hash` — MUST equal the pinned `receipt_hash`.
func TestReceiptChainVectors(t *testing.T) {
	data := loadCorpus(t, "../../tests/receipt_chain_vectors.json")
	receipts, ok := data["receipts"].([]any)
	if !ok {
		t.Fatal("corpus has no `receipts` array")
	}
	if len(receipts) == 0 {
		t.Fatal("corpus has zero receipts")
	}
	for _, r := range receipts {
		rec := r.(map[string]any)
		want, _ := rec["receipt_hash"].(string)
		body := make(map[string]any, len(rec))
		for k, val := range rec {
			if k == "receipt_hash" {
				continue
			}
			body[k] = val
		}
		got, err := CanonicalHash(body)
		if err != nil {
			t.Fatalf("receipt %v: CanonicalHash: %v", rec["event_id"], err)
		}
		if got != want {
			t.Errorf("receipt %v: hash mismatch\n got:  %s\n want: %s", rec["event_id"], got, want)
		}
	}
}

// TestNonFiniteFloatRejected confirms the fail-closed number rule.
func TestNonFiniteFloatRejected(t *testing.T) {
	if _, err := Canonicalize(map[string]any{"x": math_Inf()}); err == nil {
		t.Error("expected error for non-finite float, got nil")
	}
}

func math_Inf() float64 { return 1.0 / zero() }
func zero() float64     { return 0.0 }
