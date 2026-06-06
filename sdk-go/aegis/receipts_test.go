package aegis_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/lavkushry/aegisagent/sdk-go/aegis"
)

// loadReceiptCorpus loads the shared receipt_chain_vectors.json corpus.
// UseNumber() ensures JSON numbers survive as json.Number, preserving the
// exact byte representation expected by the canonicalizer.
func loadReceiptCorpus(t *testing.T) []map[string]any {
	t.Helper()
	f, err := os.Open("../../tests/receipt_chain_vectors.json")
	if err != nil {
		t.Fatalf("open receipt corpus: %v", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.UseNumber()
	var data map[string]any
	if err := dec.Decode(&data); err != nil {
		t.Fatalf("decode receipt corpus: %v", err)
	}
	raw, ok := data["receipts"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatal("corpus has no receipts array")
	}
	receipts := make([]map[string]any, len(raw))
	for i, r := range raw {
		receipts[i] = r.(map[string]any)
	}
	return receipts
}

// ---------- VerifyReceipt corpus gate ----------------------------------------

// TestVerifyReceipt_CorpusVectors asserts that every receipt in the shared
// corpus verifies — i.e. the Go canonicalizer produces the same receipt_hash
// byte-for-byte as Python and the gateway.
func TestVerifyReceipt_CorpusVectors(t *testing.T) {
	receipts := loadReceiptCorpus(t)
	for _, receipt := range receipts {
		id, _ := receipt["event_id"].(string)
		ok, err := aegis.VerifyReceipt(receipt)
		if err != nil {
			t.Errorf("receipt %s: VerifyReceipt error: %v", id, err)
			continue
		}
		if !ok {
			got, _ := aegis.ComputeReceiptHash(receipt)
			want, _ := receipt["receipt_hash"].(string)
			t.Errorf("receipt %s: hash mismatch\n  got:  %s\n  want: %s", id, got, want)
		}
	}
}

// ---------- VerifyChain corpus gate ------------------------------------------

// TestVerifyChain_CorpusVectors asserts the whole corpus chain verifies —
// confirming that prev_receipt_hash linkage is correct end-to-end.
func TestVerifyChain_CorpusVectors(t *testing.T) {
	receipts := loadReceiptCorpus(t)
	ok, err := aegis.VerifyChain(receipts, aegis.GenesisPrev)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !ok {
		t.Error("VerifyChain returned false on the shared corpus — chain is broken")
	}
}

// ---------- VerifyReceipt unit cases -----------------------------------------

func TestVerifyReceipt_MissingHash_ReturnsFalse(t *testing.T) {
	receipt := map[string]any{
		"event_id": "test-no-hash",
		"decision": "allow",
		// no receipt_hash field
	}
	ok, err := aegis.VerifyReceipt(receipt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false for receipt with no receipt_hash")
	}
}

func TestVerifyReceipt_TamperedHash_ReturnsFalse(t *testing.T) {
	receipt := map[string]any{
		"event_id":     "tampered",
		"decision":     "allow",
		"receipt_hash": "0000000000000000000000000000000000000000000000000000000000000000",
	}
	ok, err := aegis.VerifyReceipt(receipt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false for receipt with incorrect receipt_hash")
	}
}

// ---------- VerifyChain unit cases -------------------------------------------

func TestVerifyChain_Empty_ReturnsTrue(t *testing.T) {
	ok, err := aegis.VerifyChain(nil, aegis.GenesisPrev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("empty chain should verify as true")
	}
}

func TestVerifyChain_BrokenLink_ReturnsFalse(t *testing.T) {
	receipts := loadReceiptCorpus(t)
	if len(receipts) < 2 {
		t.Skip("need at least 2 corpus receipts")
	}
	// Deep-copy first two receipts, then break the link in the second.
	first := copyReceipt(receipts[0])
	second := copyReceipt(receipts[1])
	second["prev_receipt_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
	// Recompute receipt_hash so the individual receipt still self-verifies.
	h, err := aegis.ComputeReceiptHash(second)
	if err != nil {
		t.Fatalf("recompute hash: %v", err)
	}
	second["receipt_hash"] = h

	chain := []map[string]any{first, second}
	ok, err := aegis.VerifyChain(chain, aegis.GenesisPrev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("chain with broken prev_receipt_hash link should not verify")
	}
}

// copyReceipt makes a shallow copy so tests can mutate without affecting the
// shared corpus slice.
func copyReceipt(r map[string]any) map[string]any {
	c := make(map[string]any, len(r))
	for k, v := range r {
		c[k] = v
	}
	return c
}
