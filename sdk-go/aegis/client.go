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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

// ApprovalDecisionResponse is the decoded body of a 200 from
// POST /v1/approvals/:id/approve|reject.
type ApprovalDecisionResponse struct {
	Status     string `json:"status"`
	ApprovalID string `json:"approval_id"`
}

// SocAlert is a single SOC detection alert (GET /v1/alerts).
type SocAlert struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	Rule          string `json:"rule"`
	Severity      string `json:"severity"`
	AgentID       string `json:"agent_id"`
	SourceEventID string `json:"source_event_id"`
	Summary       string `json:"summary"`
	CreatedAt     string `json:"created_at"`
}

// SocIncident is a single SOC correlation incident (GET /v1/incidents).
type SocIncident struct {
	ID             string  `json:"id"`
	TenantID       string  `json:"tenant_id"`
	Kind           string  `json:"kind"`
	Severity       string  `json:"severity"`
	AgentID        string  `json:"agent_id"`
	Summary        string  `json:"summary"`
	SourceEventIDs string  `json:"source_event_ids"`
	OpenedAt       string  `json:"opened_at"`
	Status         string  `json:"status"`
	ClosedAt       *string `json:"closed_at"`
}

// SocSummary is the tenant-scoped aggregate SOC counts from GET /v1/soc/summary.
type SocSummary struct {
	AlertsTotal     int64 `json:"alerts_total"`
	AlertsHigh      int64 `json:"alerts_high"`
	IncidentsTotal  int64 `json:"incidents_total"`
	IncidentsOpen   int64 `json:"incidents_open"`
	IncidentsClosed int64 `json:"incidents_closed"`
}

// ListAlertsOptions filters GET /v1/alerts. Zero values are omitted from the
// query string.
type ListAlertsOptions struct {
	Limit    int
	Offset   int
	Severity string
	AgentID  string
}

// ListIncidentsOptions filters GET /v1/incidents. Zero values are omitted
// from the query string.
type ListIncidentsOptions struct {
	Limit    int
	Offset   int
	Status   string
	Severity string
	AgentID  string
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
// actions. ctx controls cancellation/timeout of the underlying HTTP request.
func (c *Client) Authorize(ctx context.Context, payload AuthorizeRequest) (AuthorizeResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return AuthorizeResponse{}, fmt.Errorf("aegis: marshal authorize request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/authorize", bytes.NewReader(body))
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
// response. ctx controls cancellation/timeout of the underlying HTTP request.
func (c *Client) GetApproval(ctx context.Context, approvalID string) (ApprovalStatus, error) {
	reqURL := c.baseURL + "/v1/approvals/" + approvalID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
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
// is already consumed, expired, or not in the approved state. ctx controls
// cancellation/timeout of the underlying HTTP request.
func (c *Client) ConsumeApproval(ctx context.Context, approvalID string) (ConsumeResponse, error) {
	reqURL := c.baseURL + "/v1/approvals/" + approvalID + "/consume"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, http.NoBody)
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

// ---------------------------------------------------------------------------
// Approve / Reject
// ---------------------------------------------------------------------------

// Approve decides a pending approval via POST /v1/approvals/:id/approve.
// reason may be empty. Returns [ErrGateway] (e.g. 409) if the approval was
// already decided or has expired.
func (c *Client) Approve(ctx context.Context, approvalID, approverUserID, reason string) (ApprovalDecisionResponse, error) {
	return c.decideApproval(ctx, "approve", approvalID, approverUserID, reason)
}

// Reject decides a pending approval via POST /v1/approvals/:id/reject.
// reason may be empty. Returns [ErrGateway] (e.g. 409) if the approval was
// already decided or has expired.
func (c *Client) Reject(ctx context.Context, approvalID, approverUserID, reason string) (ApprovalDecisionResponse, error) {
	return c.decideApproval(ctx, "reject", approvalID, approverUserID, reason)
}

func (c *Client) decideApproval(ctx context.Context, decision, approvalID, approverUserID, reason string) (ApprovalDecisionResponse, error) {
	body, err := json.Marshal(map[string]any{
		"approver_user_id": approverUserID,
		"reason":           nilIfEmpty(reason),
	})
	if err != nil {
		return ApprovalDecisionResponse{}, fmt.Errorf("aegis: marshal %s request: %w", decision, err)
	}

	reqURL := c.baseURL + "/v1/approvals/" + approvalID + "/" + decision
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return ApprovalDecisionResponse{}, fmt.Errorf("aegis: build %s request: %w", decision, err)
	}
	c.addHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return ApprovalDecisionResponse{}, fmt.Errorf("aegis: %s network error: %w", decision, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ApprovalDecisionResponse{}, &ErrGateway{
			StatusCode: resp.StatusCode,
			Body:       readBody(resp.Body),
		}
	}

	var out ApprovalDecisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ApprovalDecisionResponse{}, fmt.Errorf("aegis: decode %s response: %w", decision, err)
	}
	return out, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---------------------------------------------------------------------------
// Agent lifecycle: FreezeAgent / UnfreezeAgent / RevokeAgent
// ---------------------------------------------------------------------------

// FreezeAgent freezes an agent via POST /v1/agents/:id/freeze. reason may be
// empty. A frozen agent is denied on its next /v1/authorize call.
func (c *Client) FreezeAgent(ctx context.Context, agentID, reason string) error {
	var body io.Reader = http.NoBody
	if reason != "" {
		b, err := json.Marshal(map[string]any{"reason": reason})
		if err != nil {
			return fmt.Errorf("aegis: marshal freeze request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	return c.postAgentLifecycle(ctx, agentID, "freeze", body)
}

// UnfreezeAgent restores a frozen agent to active status via
// POST /v1/agents/:id/unfreeze.
func (c *Client) UnfreezeAgent(ctx context.Context, agentID string) error {
	return c.postAgentLifecycle(ctx, agentID, "unfreeze", http.NoBody)
}

// RevokeAgent permanently revokes an agent via POST /v1/agents/:id/revoke.
// Not reversible via the API.
func (c *Client) RevokeAgent(ctx context.Context, agentID string) error {
	return c.postAgentLifecycle(ctx, agentID, "revoke", http.NoBody)
}

func (c *Client) postAgentLifecycle(ctx context.Context, agentID, action string, body io.Reader) error {
	reqURL := c.baseURL + "/v1/agents/" + agentID + "/" + action
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, body)
	if err != nil {
		return fmt.Errorf("aegis: build %s request: %w", action, err)
	}
	c.addHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("aegis: %s network error: %w", action, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &ErrGateway{StatusCode: resp.StatusCode, Body: readBody(resp.Body)}
	}
	return nil
}

// ---------------------------------------------------------------------------
// SOC query layer: ListAlerts / ListIncidents / GetSocSummary
// ---------------------------------------------------------------------------

// ListAlerts fetches SOC detection alerts via GET /v1/alerts, tenant-scoped
// and optionally filtered by opts.
func (c *Client) ListAlerts(ctx context.Context, opts ListAlertsOptions) ([]SocAlert, error) {
	q := url.Values{}
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Offset > 0 {
		q.Set("offset", strconv.Itoa(opts.Offset))
	}
	if opts.Severity != "" {
		q.Set("severity", opts.Severity)
	}
	if opts.AgentID != "" {
		q.Set("agent_id", opts.AgentID)
	}

	reqURL := c.baseURL + "/v1/alerts"
	if encoded := q.Encode(); encoded != "" {
		reqURL += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("aegis: build list-alerts request: %w", err)
	}
	c.addHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aegis: list-alerts network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &ErrGateway{StatusCode: resp.StatusCode, Body: readBody(resp.Body)}
	}

	var out []SocAlert
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("aegis: decode list-alerts response: %w", err)
	}
	return out, nil
}

// ListIncidents fetches SOC correlation incidents via GET /v1/incidents,
// tenant-scoped and optionally filtered by opts.
func (c *Client) ListIncidents(ctx context.Context, opts ListIncidentsOptions) ([]SocIncident, error) {
	q := url.Values{}
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Offset > 0 {
		q.Set("offset", strconv.Itoa(opts.Offset))
	}
	if opts.Status != "" {
		q.Set("status", opts.Status)
	}
	if opts.Severity != "" {
		q.Set("severity", opts.Severity)
	}
	if opts.AgentID != "" {
		q.Set("agent_id", opts.AgentID)
	}

	reqURL := c.baseURL + "/v1/incidents"
	if encoded := q.Encode(); encoded != "" {
		reqURL += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("aegis: build list-incidents request: %w", err)
	}
	c.addHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aegis: list-incidents network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &ErrGateway{StatusCode: resp.StatusCode, Body: readBody(resp.Body)}
	}

	var out []SocIncident
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("aegis: decode list-incidents response: %w", err)
	}
	return out, nil
}

// GetSocSummary fetches tenant-scoped aggregate SOC counts via
// GET /v1/soc/summary.
func (c *Client) GetSocSummary(ctx context.Context) (SocSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/soc/summary", nil)
	if err != nil {
		return SocSummary{}, fmt.Errorf("aegis: build soc-summary request: %w", err)
	}
	c.addHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return SocSummary{}, fmt.Errorf("aegis: soc-summary network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return SocSummary{}, &ErrGateway{StatusCode: resp.StatusCode, Body: readBody(resp.Body)}
	}

	var out SocSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return SocSummary{}, fmt.Errorf("aegis: decode soc-summary response: %w", err)
	}
	return out, nil
}
