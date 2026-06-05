package aegis

import (
	"fmt"
	"time"

	"github.com/lavkushry/aegisagent/sdk-go/canon"
)

// ProtectOptions controls the approval-polling behaviour of [ProtectWithOptions].
type ProtectOptions struct {
	// PollInterval is the delay between approval status polls.
	// Zero means no sleep (useful in tests).
	PollInterval time.Duration

	// MaxPolls is the maximum number of approval status polls before giving up.
	// Zero uses the default of 150 (≈ 5 minutes at a 2-second interval).
	MaxPolls int
}

var defaultProtectOptions = ProtectOptions{
	PollInterval: 2 * time.Second,
	MaxPolls:     150,
}

// Protect intercepts fn and enforces the AegisAgent gateway decision for req.
// It uses the default polling options (2-second interval, 150 polls max).
//
// Fail-closed guarantees:
//   - decision "deny"                  → return [ErrDenied]; fn NOT called.
//   - action_hash mismatch anywhere    → return [ErrHashMismatch]; fn NOT called.
//   - consume fails (409/error)        → return error; fn NOT called.
//   - gateway unreachable, mutating    → return error; fn NOT called.
//   - unknown decision                 → return error; fn NOT called.
//   - decision "allow"                 → fn called, its return value forwarded.
//   - decision "require_approval"      → poll until approved, verify hash,
//     atomically consume, then call fn.
func Protect(client *Client, req AuthorizeRequest, fn func() error) error {
	return ProtectWithOptions(client, req, fn, defaultProtectOptions)
}

// ProtectWithOptions is like [Protect] but accepts explicit [ProtectOptions].
func ProtectWithOptions(client *Client, req AuthorizeRequest, fn func() error, opts ProtectOptions) error {
	maxPolls := opts.MaxPolls
	if maxPolls <= 0 {
		maxPolls = defaultProtectOptions.MaxPolls
	}

	// Compute the expected action_hash from the caller's exact action
	// (scheme aegis-jcs-1 — byte-identical with gateway and other SDKs).
	expectedHash, err := computeActionHash(req)
	if err != nil {
		return fmt.Errorf("aegis: failed to compute action hash: %w", err)
	}

	// 1. Request authorization from the gateway.
	authResp, err := client.Authorize(req)
	if err != nil {
		// Gateway unreachable or returned non-2xx. Fail closed for mutating
		// actions; allow read-only to proceed is intentionally NOT implemented
		// here — callers who want leniency for read-only can check themselves.
		return fmt.Errorf("aegis: gateway authorization failed (fail closed): %w", err)
	}

	switch authResp.Decision {
	case "allow":
		return fn()

	case "deny":
		return &ErrDenied{Reason: authResp.Reason}

	case "require_approval":
		return handleApproval(client, req, fn, authResp, expectedHash, opts, maxPolls)

	default:
		return fmt.Errorf(
			"aegis: unexpected gateway decision %q — failing closed",
			authResp.Decision,
		)
	}
}

// handleApproval implements the approval-polling loop and all fail-closed
// checks for the "require_approval" decision path.
func handleApproval(
	client *Client,
	req AuthorizeRequest,
	fn func() error,
	authResp AuthorizeResponse,
	expectedHash string,
	opts ProtectOptions,
	maxPolls int,
) error {
	// Approval info must be present; without it we cannot poll or verify.
	if authResp.Approval == nil {
		return fmt.Errorf(
			"aegis: decision is require_approval but no approval info returned — failing closed",
		)
	}

	approval := authResp.Approval

	// Verify the gateway bound this approval to the correct action.
	if err := assertHash("authorize", approval.ActionHash, expectedHash); err != nil {
		return err
	}

	approvalID := approval.ApprovalID

	// Poll for a terminal state.
	for i := 0; i < maxPolls; i++ {
		if opts.PollInterval > 0 {
			time.Sleep(opts.PollInterval)
		}

		status, err := client.GetApproval(approvalID)
		if err != nil {
			// Transient network error — keep polling (mirroring Python SDK).
			continue
		}

		switch status.Status {
		case "APPROVED":
			// Verify the approval still refers to the same action (approve-then-swap defence).
			if err := assertHash("poll", status.ActionHash, expectedHash); err != nil {
				return err
			}

			// Atomically consume the approval before executing (replay defence).
			consumed, err := client.ConsumeApproval(approvalID)
			if err != nil {
				return fmt.Errorf(
					"aegis: approval consume failed (already used / expired) — failing closed: %w", err,
				)
			}

			// Final hash check on the consume response.
			if err := assertHash("consume", consumed.ActionHash, expectedHash); err != nil {
				return err
			}

			return fn()

		case "REJECTED":
			return fmt.Errorf("aegis: action rejected by reviewer: %s", status.Reason)

		case "EXPIRED":
			return fmt.Errorf("aegis: approval expired — failing closed")

		case "PENDING":
			// Keep polling.

		default:
			// Unknown terminal-ish status — keep polling (forward-compat).
		}
	}

	return fmt.Errorf(
		"aegis: approval timed out after %d polls — failing closed", maxPolls,
	)
}

// computeActionHash builds the canonical representation of req and returns its
// SHA-256 hex digest using scheme aegis-jcs-1 (byte-identical across SDKs).
//
// resource is a *string so it can be absent (nil → JSON null). canon does not
// handle pointer types, so we dereference explicitly to an untyped nil or the
// string value before passing it in.
func computeActionHash(req AuthorizeRequest) (string, error) {
	var resource any // nil → serialised as JSON null, matching Python's None
	if req.Resource != nil {
		resource = *req.Resource
	}
	m := map[string]any{
		"tool":          req.Tool,
		"action":        req.Action,
		"resource":      resource,
		"mutates_state": req.MutatesState,
		"parameters":    req.Parameters,
	}
	return canon.CanonicalHash(m)
}

// assertHash returns [ErrHashMismatch] if got != expected.
func assertHash(phase, got, expected string) error {
	if got == "" {
		return &ErrHashMismatch{Phase: phase, Got: "(empty)", Expected: expected}
	}
	if got != expected {
		return &ErrHashMismatch{Phase: phase, Got: got, Expected: expected}
	}
	return nil
}
