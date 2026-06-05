// Package canon implements the AegisAgent canonicalization scheme aegis-jcs-1.
//
// Output MUST be byte-identical to sdk-python/aegisagent/canon.py and the Rust
// gateway, because both action_hash (approval integrity) and receipt_hash
// (verifiable receipts) are SHA-256 over this canonical string. A divergence
// here silently breaks the fail-closed guarantee — locked by the shared corpus
// in tests/canonical_action_vectors.json and tests/receipt_chain_vectors.json.
//
// Scheme aegis-jcs-1:
//   - object keys sorted by Unicode code point
//   - compact separators (no spaces): "," and ":"
//   - raw UTF-8 — no \uXXXX escaping of non-ASCII
//   - non-finite floats (NaN/Inf) rejected
//   - null for absent values
//
// Go-specific correctness notes (the footguns this package handles):
//   - we do NOT use encoding/json for serialization: its default HTML-escaping
//     turns < > & into <>&, and it escapes U+2028/U+2029 — both
//     diverge from Python's json.dumps(ensure_ascii=False). We hand-roll string
//     escaping to match Python exactly.
//   - map keys are sorted with sort.Strings, whose byte-wise order equals
//     Unicode code-point order for valid UTF-8 (e.g. a < z < é).
package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Version is the canonicalization scheme identifier.
const Version = "aegis-jcs-1"

// Canonicalize returns the deterministic aegis-jcs-1 JSON string for v.
//
// Accepts the types produced by encoding/json with Decoder.UseNumber() (nil,
// bool, string, json.Number, map[string]any, []any) plus Go-native numeric
// types. Unknown types fail closed with an error.
func Canonicalize(v any) (string, error) {
	var b strings.Builder
	if err := writeValue(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// SHA256Hex returns the lowercase hex SHA-256 of s encoded as UTF-8.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// CanonicalHash returns the SHA-256 hex of the canonical serialization of v.
func CanonicalHash(v any) (string, error) {
	s, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(s), nil
}

func writeValue(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x)
	case json.Number:
		// Emit the literal number text exactly as parsed. This preserves the
		// int/float distinction byte-for-byte and sidesteps float-format drift
		// for any value that originated as JSON.
		b.WriteString(string(x))
	case int:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int8:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int16:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint, uint8, uint16, uint32, uint64:
		b.WriteString(fmt.Sprintf("%d", x))
	case float32:
		return writeFloat(b, float64(x))
	case float64:
		return writeFloat(b, x)
	case map[string]any:
		return writeObject(b, x)
	case []any:
		return writeArray(b, x)
	default:
		return fmt.Errorf("canon: unsupported type %T (aegis-jcs-1)", v)
	}
	return nil
}

func writeObject(b *strings.Builder, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Byte-wise order of valid UTF-8 == Unicode code-point order.
	sort.Strings(keys)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(b, k)
		b.WriteByte(':')
		if err := writeValue(b, m[k]); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

func writeArray(b *strings.Builder, a []any) error {
	b.WriteByte('[')
	for i, e := range a {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := writeValue(b, e); err != nil {
			return err
		}
	}
	b.WriteByte(']')
	return nil
}

// writeString matches Python's json.dumps(ensure_ascii=False) escaping exactly:
// escape only " \ and C0 control chars (short forms for \b \t \n \f \r, \u00xx
// otherwise); everything else — including all non-ASCII, /, <, >, &, U+2028,
// U+2029 — is written as raw UTF-8.
func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				b.WriteString(`\u`)
				b.WriteString(fmt.Sprintf("%04x", r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// writeFloat formats a finite float64. Non-finite values are rejected
// (aegis-jcs-1). NOTE: finite-float formatting is NOT yet corpus-locked across
// SDKs; prefer integers, strings, or JSON-origin numbers (json.Number) for
// action parameters until float vectors + RFC 8785 number formatting land.
func writeFloat(b *strings.Builder, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canon: non-finite float not allowed (aegis-jcs-1)")
	}
	b.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}
