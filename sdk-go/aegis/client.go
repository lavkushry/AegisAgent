// Package aegis provides the AegisAgent Go SDK client and tool-protection
// wrapper. The two exported entry points are:
//
//   - [Client] — HTTP client for the AegisAgent gateway (authorize, poll
//     approval status, atomically consume an approval).
//   - [Protect] / [ProtectWithOptions] — fail-closed wrapper that intercepts a
//     tool-call function and enforces gateway decisions.
package aegis

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// defaultTimeout is applied to every outbound HTTP request so that a slow or
// hung gateway cannot block the caller indefinitely.
const defaultTimeout = 5 * time.Second

// ClientOptions configures a [Client].
type ClientOptions struct {
	// BaseURL is the AegisAgent gateway base URL, e.g. "http://127.0.0.1:8080".
	// A trailing slash is stripped.
	BaseURL string

	// AgentToken is the bearer token obtained after agent registration.
	AgentToken string

	// TenantID is forwarded as the X-Aegis-Tenant-ID header on every request.
	TenantID string

	// SigningKey, when non-empty, enables HMAC-SHA256 request signing.
	// Every POST /v1/authorize call will include an
	// X-Aegis-Request-Signature: sha256=<hex> header.
	SigningKey string

	// HTTPClient overrides the default http.Client (useful in tests).
	HTTPClient *http.Client
}

// Client is an HTTP client for the AegisAgent gateway. All exported methods
// return errors; no method panics.
type Client struct {
	baseURL    string
	agentToken string
	tenantID   string
	signingKey string
	http       *http.Client
}

// NewClient constructs a [Client] from the given options.
func NewClient(opts ClientOptions) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{
		baseURL:    strings.TrimRight(opts.BaseURL, "/"),
		agentToken: opts.AgentToken,
		tenantID:   opts.TenantID,
		signingKey: opts.SigningKey,
		http:       hc,
	}
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

// AuthorizeRequest is the payload sent to POST /v1/authorize.
type AuthorizeRequest struct {
	// Tool is the tool key, e.g. "github".
	Tool string `json:"tool"`
	// Action is the action key, e.g. "merge_pr".
	Action string `json:"action"`
	// Resource is an optional resource identifier.
	Resource *string `json:"resource,omitempty"`
	// MutatesState indicates the action changes durable state. Used by
	// [Protect] to decide fail-closed behaviour on a gateway error.
	MutatesState bool `json:"mutates_state"`
	// Parameters are the typed parameters for the tool call.
	Parameters map[string]any `json:"parameters"`
	// SourceTrust is the 6-level trust label of the triggering content.
	SourceTrust string `json:"source_trust,omitempty"`
}

// ApprovalInfo is embedded in an [AuthorizeResponse] when the decision is
// "require_approval".
type ApprovalInfo struct {
	ApprovalID    string `json:"approval_id"`
	ActionHash    string `json:"action_hash"`
	ApproverGroup string `json:"approver_group,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

// AuthorizeResponse is the decoded body of a 200 from POST /v1/authorize.
type AuthorizeResponse struct {
	Decision   string        `json:"decision"`
	ActionHash string        `json:"action_hash"`
	Reason     string        `json:"reason,omitempty"`
	Approval   *ApprovalInfo `json:"approval,omitempty"`
}

// ApprovalStatus is the decoded body of a 200 from GET /v1/approvals/:id.
type ApprovalStatus struct {
	Status     string `json:"status"`
	ActionHash string `json:"action_hash"`
	Reason     string `json:"reason,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// ConsumeResponse is the decoded body of a 200 from POST /v1/approvals/:id/consume.
type ConsumeResponse struct {
	ActionHash string `json:"action_hash"`
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

// ErrDenied is returned by [Protect] when the gateway decision is "deny".
type ErrDenied struct {
	Reason string
}

func (e *ErrDenied) Error() string {
	return fmt.Sprintf("aegis: action denied by gateway: %s", e.Reason)
}

// ErrHashMismatch is returned when the approval's bound action_hash does not
// match the hash of the action about to execute (approve-then-swap defence).
type ErrHashMismatch struct {
	Phase    string // "authorize", "poll", or "consume"
	Got      string
	Expected string
}

func (e *ErrHashMismatch) Error() string {
	return fmt.Sprintf(
		"aegis: action_hash mismatch at %s phase (got %s, expected %s) — failing closed",
		e.Phase, e.Got, e.Expected,
	)
}

// ErrGateway is returned when the gateway responds with a non-2xx status.
type ErrGateway struct {
	StatusCode int
	Body       string
}

func (e *ErrGateway) Error() string {
	return fmt.Sprintf("aegis: gateway error %d: %s", e.StatusCode, e.Body)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// addHeaders attaches the Authorization and tenant headers used by all requests.
func (c *Client) addHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.agentToken)
	req.Header.Set("X-Aegis-Tenant-ID", c.tenantID)
	req.Header.Set("Content-Type", "application/json")
}

func readBody(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 2048))
	return string(b)
}

// ---------------------------------------------------------------------------
// Authorize
// ---------------------------------------------------------------------------

// Authorize sends an authorization request to POST /v1/authorize and returns
// the parsed response. On any network or non-2xx error it returns a non-nil
// error; callers (i.e. [Protect]) treat this as fail-closed for mutating
// actions.
func (c *Client) Authorize(payload AuthorizeRequest) (AuthorizeResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return AuthorizeResponse{}, fmt.Errorf("aegis: marshal authorize request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/v1/authorize", bytes.NewReader(body))
	if err != nil {
		return AuthorizeResponse{}, fmt.Errorf("aegis: build authorize request: %w", err)
	}
	c.addHeaders(req)

	if c.signingKey != "" {
		mac := hmac.New(sha256.New, []byte(c.signingKey))
		mac.Write(body)
		req.Header.Set("X-Aegis-Request-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return AuthorizeResponse{}, fmt.Errorf("aegis: authorize network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AuthorizeResponse{}, &ErrGateway{
			StatusCode: resp.StatusCode,
			Body:       readBody(resp.Body),
		}
	}

	var out AuthorizeResponse
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return AuthorizeResponse{}, fmt.Errorf("aegis: decode authorize response: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// GetApproval
// ---------------------------------------------------------------------------

// GetApproval fetches the current status of an approval from
// GET /v1/approvals/:id. Returns an error on network failure or non-2xx
// response.
func (c *Client) GetApproval(approvalID string) (ApprovalStatus, error) {
	url := c.baseURL + "/v1/approvals/" + approvalID
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ApprovalStatus{}, fmt.Errorf("aegis: build get-approval request: %w", err)
	}
	c.addHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return ApprovalStatus{}, fmt.Errorf("aegis: get-approval network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ApprovalStatus{}, &ErrGateway{
			StatusCode: resp.StatusCode,
			Body:       readBody(resp.Body),
		}
	}

	var out ApprovalStatus
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ApprovalStatus{}, fmt.Errorf("aegis: decode approval status: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// ConsumeApproval
// ---------------------------------------------------------------------------

// ConsumeApproval atomically consumes an APPROVED approval via
// POST /v1/approvals/:id/consume so it cannot be reused (replay defence).
// Returns an error — including [ErrGateway] with status 409 — if the approval
// is already consumed, expired, or not in the approved state.
func (c *Client) ConsumeApproval(approvalID string) (ConsumeResponse, error) {
	url := c.baseURL + "/v1/approvals/" + approvalID + "/consume"
	req, err := http.NewRequest(http.MethodPost, url, http.NoBody)
	if err != nil {
		return ConsumeResponse{}, fmt.Errorf("aegis: build consume request: %w", err)
	}
	c.addHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return ConsumeResponse{}, fmt.Errorf("aegis: consume network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ConsumeResponse{}, &ErrGateway{
			StatusCode: resp.StatusCode,
			Body:       readBody(resp.Body),
		}
	}

	var out ConsumeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ConsumeResponse{}, fmt.Errorf("aegis: decode consume response: %w", err)
	}
	return out, nil
}
