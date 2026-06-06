// Package aegis — verifiable action receipts (scheme aegis-jcs-1).
//
// A receipt is a tamper-evident record of one agent-action decision. Receipts
// form a per-tenant hash chain:
//
//	receipt_hash = SHA-256(canonicalize(body))
//
// where body is every field of the receipt EXCEPT receipt_hash, and INCLUDES
// prev_receipt_hash. Because the previous link is inside the hashed body,
// altering any field or re-ordering the chain is detectable.
//
// This file is the Go reference verifier; see docs/action-receipt-spec.md for
// the open receipt format and sdk-python/aegisagent/receipts.py for the Python
// reference implementation.
package aegis

import "github.com/lavkushry/aegisagent/sdk-go/canon"

const (
	// GenesisPrev is the prev_receipt_hash value expected for the first receipt
	// in a chain.
	GenesisPrev = ""

	receiptHashField = "receipt_hash"
	prevHashField    = "prev_receipt_hash"
)

// receiptBody returns the hashed portion of a receipt: all fields except
// receipt_hash.
func receiptBody(receipt map[string]any) map[string]any {
	body := make(map[string]any, len(receipt))
	for k, v := range receipt {
		if k != receiptHashField {
			body[k] = v
		}
	}
	return body
}

// ComputeReceiptHash returns the SHA-256 hex of the canonical body of receipt
// (all fields except receipt_hash). Returns an error if canonicalization fails.
func ComputeReceiptHash(receipt map[string]any) (string, error) {
	return canon.CanonicalHash(receiptBody(receipt))
}

// VerifyReceipt reports whether the receipt's stored receipt_hash matches its
// recomputed hash. Returns (false, nil) when the receipt_hash field is absent
// or empty; returns (false, err) when canonicalization fails.
func VerifyReceipt(receipt map[string]any) (bool, error) {
	stored, _ := receipt[receiptHashField].(string)
	if stored == "" {
		return false, nil
	}
	got, err := ComputeReceiptHash(receipt)
	if err != nil {
		return false, err
	}
	return got == stored, nil
}

// VerifyChain verifies a slice of receipts that form a hash chain. It returns
// true only when every receipt's receipt_hash verifies AND each receipt's
// prev_receipt_hash equals the prior receipt's receipt_hash (with the first
// receipt's prev_receipt_hash compared against genesisPrev, which is usually
// GenesisPrev/""). An empty chain returns true.
func VerifyChain(receipts []map[string]any, genesisPrev string) (bool, error) {
	prev := genesisPrev
	for _, receipt := range receipts {
		ok, err := VerifyReceipt(receipt)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		p, _ := receipt[prevHashField].(string)
		if p != prev {
			return false, nil
		}
		prev, _ = receipt[receiptHashField].(string)
	}
	return true, nil
}
