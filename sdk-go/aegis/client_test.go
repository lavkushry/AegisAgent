package aegis_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lavkushry/aegisagent/sdk-go/aegis"
)

// newTestClient returns a Client configured to talk to the given test server.
func newTestClient(serverURL string) *aegis.Client {
	return aegis.NewClient(aegis.ClientOptions{
		BaseURL:    serverURL,
		AgentToken: "test-token",
		TenantID:   "tenant-abc",
	})
}

// serveJSON is a helper that writes a JSON response body with status code.
func serveJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ---------- Client.Authorize -------------------------------------------------

func TestAuthorize_Allow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/authorize" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		// Verify tenant header is forwarded
		if r.Header.Get("X-Aegis-Tenant-ID") != "tenant-abc" {
			t.Errorf("missing or wrong tenant header: %q", r.Header.Get("X-Aegis-Tenant-ID"))
		}
		serveJSON(w, http.StatusOK, map[string]any{
			"decision":    "allow",
			"action_hash": "deadbeef",
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	resp, err := client.Authorize(context.Background(), aegis.AuthorizeRequest{
		Tool:   "github",
		Action: "list_prs",
		Parameters: map[string]any{
			"repo": "lavkushry/aegis",
		},
	})
	if err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected decision=allow, got %q", resp.Decision)
	}
}

func TestAuthorize_NetworkError_ReturnsError(t *testing.T) {
	// Point at an unreachable port
	client := aegis.NewClient(aegis.ClientOptions{
		BaseURL:    "http://127.0.0.1:1", // nothing listening
		AgentToken: "tok",
		TenantID:   "tid",
	})
	_, err := client.Authorize(context.Background(), aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "push",
		Parameters:   map[string]any{},
		MutatesState: true,
	})
	if err == nil {
		t.Fatal("expected error for unreachable gateway, got nil")
	}
}

func TestGetApproval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/approvals/appr-001" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		serveJSON(w, http.StatusOK, map[string]any{
			"status":      "APPROVED",
			"action_hash": "abc123",
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	status, err := client.GetApproval(context.Background(), "appr-001")
	if err != nil {
		t.Fatalf("GetApproval error: %v", err)
	}
	if status.Status != "APPROVED" {
		t.Errorf("expected APPROVED, got %q", status.Status)
	}
	if status.ActionHash != "abc123" {
		t.Errorf("expected action_hash=abc123, got %q", status.ActionHash)
	}
}

func TestConsumeApproval_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/approvals/appr-999/consume" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		serveJSON(w, http.StatusOK, map[string]any{
			"action_hash": "hashxyz",
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	resp, err := client.ConsumeApproval(context.Background(), "appr-999")
	if err != nil {
		t.Fatalf("ConsumeApproval error: %v", err)
	}
	if resp.ActionHash != "hashxyz" {
		t.Errorf("expected action_hash=hashxyz, got %q", resp.ActionHash)
	}
}

func TestConsumeApproval_409_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, http.StatusConflict, map[string]any{
			"error": "already consumed",
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.ConsumeApproval(context.Background(), "appr-dup")
	if err == nil {
		t.Fatal("expected error on 409, got nil")
	}
}

// ---------- Request signing (#1403) -----------------------------------------

func TestAuthorize_WithSigningKey_SendsSignatureHeader(t *testing.T) {
	const signingKey = "test-signing-secret"
	var gotSig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Aegis-Request-Signature")
		serveJSON(w, http.StatusOK, map[string]any{
			"decision":    "allow",
			"action_hash": "abc",
		})
	}))
	defer srv.Close()

	client := aegis.NewClient(aegis.ClientOptions{
		BaseURL:    srv.URL,
		AgentToken: "tok",
		TenantID:   "tid",
		SigningKey: signingKey,
	})
	_, err := client.Authorize(context.Background(), aegis.AuthorizeRequest{
		Tool:       "github",
		Action:     "list_prs",
		Parameters: map[string]any{"repo": "aegis"},
	})
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("expected X-Aegis-Request-Signature to start with sha256=, got %q", gotSig)
	}
}

func TestAuthorize_WithSigningKey_SignatureIsCorrect(t *testing.T) {
	const signingKey = "my-hmac-key"
	var capturedBody []byte
	var capturedSig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		capturedSig = r.Header.Get("X-Aegis-Request-Signature")
		serveJSON(w, http.StatusOK, map[string]any{"decision": "allow", "action_hash": "x"})
	}))
	defer srv.Close()

	client := aegis.NewClient(aegis.ClientOptions{
		BaseURL:    srv.URL,
		AgentToken: "tok",
		TenantID:   "tid",
		SigningKey: signingKey,
	})
	_, err := client.Authorize(context.Background(), aegis.AuthorizeRequest{
		Tool:       "s3",
		Action:     "delete_bucket",
		Parameters: map[string]any{"bucket": "prod"},
	})
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write(capturedBody)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if capturedSig != expected {
		t.Errorf("signature mismatch: got %q, want %q", capturedSig, expected)
	}
}

func TestAuthorize_WithoutSigningKey_NoSignatureHeader(t *testing.T) {
	var gotSig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Aegis-Request-Signature")
		serveJSON(w, http.StatusOK, map[string]any{"decision": "allow", "action_hash": "y"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.Authorize(context.Background(), aegis.AuthorizeRequest{
		Tool:       "github",
		Action:     "list_prs",
		Parameters: map[string]any{},
	})
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	if gotSig != "" {
		t.Errorf("expected no signature header, got %q", gotSig)
	}
}

// ---------- Approve / Reject (#1183) ----------------------------------------

func TestApprove_Success(t *testing.T) {
	var capturedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/approvals/appr-1/approve" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&capturedBody)
		serveJSON(w, http.StatusOK, map[string]any{"status": "success", "approval_id": "appr-1"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	resp, err := client.Approve(context.Background(), "appr-1", "user-42", "looks safe")
	if err != nil {
		t.Fatalf("Approve error: %v", err)
	}
	if resp.Status != "success" || resp.ApprovalID != "appr-1" {
		t.Errorf("unexpected response: %+v", resp)
	}
	if capturedBody["approver_user_id"] != "user-42" || capturedBody["reason"] != "looks safe" {
		t.Errorf("unexpected request body: %+v", capturedBody)
	}
}

func TestApprove_409_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, http.StatusConflict, map[string]any{"error": "Approval already decided"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.Approve(context.Background(), "appr-decided", "user-1", "")
	if err == nil {
		t.Fatal("expected error on 409, got nil")
	}
}

func TestReject_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/approvals/appr-2/reject" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		serveJSON(w, http.StatusOK, map[string]any{"status": "success", "approval_id": "appr-2"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	resp, err := client.Reject(context.Background(), "appr-2", "user-7", "")
	if err != nil {
		t.Fatalf("Reject error: %v", err)
	}
	if resp.Status != "success" || resp.ApprovalID != "appr-2" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

// ---------- FreezeAgent / UnfreezeAgent / RevokeAgent (#1183) ---------------

func TestFreezeAgent_Success(t *testing.T) {
	var capturedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/agents/agent-1/freeze" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&capturedBody)
		serveJSON(w, http.StatusOK, map[string]any{"status": "frozen"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	if err := client.FreezeAgent(context.Background(), "agent-1", "suspicious activity"); err != nil {
		t.Fatalf("FreezeAgent error: %v", err)
	}
	if capturedBody["reason"] != "suspicious activity" {
		t.Errorf("expected reason in body, got: %+v", capturedBody)
	}
}

func TestFreezeAgent_NoReason_SendsEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("expected empty body when no reason given, got: %s", body)
		}
		serveJSON(w, http.StatusOK, map[string]any{"status": "frozen"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	if err := client.FreezeAgent(context.Background(), "agent-1", ""); err != nil {
		t.Fatalf("FreezeAgent error: %v", err)
	}
}

func TestUnfreezeAgent_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/agents/agent-1/unfreeze" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		serveJSON(w, http.StatusOK, map[string]any{"status": "active"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	if err := client.UnfreezeAgent(context.Background(), "agent-1"); err != nil {
		t.Fatalf("UnfreezeAgent error: %v", err)
	}
}

func TestRevokeAgent_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/agents/agent-1/revoke" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		serveJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	if err := client.RevokeAgent(context.Background(), "agent-1"); err != nil {
		t.Fatalf("RevokeAgent error: %v", err)
	}
}

func TestRevokeAgent_404_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, http.StatusNotFound, map[string]any{"error": "agent not found"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	err := client.RevokeAgent(context.Background(), "missing-agent")
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
	var gwErr *aegis.ErrGateway
	if !errors.As(err, &gwErr) {
		t.Errorf("expected ErrGateway, got %T: %v", err, err)
	}
}

// ---------- ListAlerts / ListIncidents / GetSocSummary (#1183) -------------

func TestListAlerts_ReturnsParsedAlertsWithQueryParams(t *testing.T) {
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/alerts" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		capturedQuery = r.URL.RawQuery
		serveJSON(w, http.StatusOK, []map[string]any{
			{
				"id":              "alert-1",
				"tenant_id":       "tenant-test",
				"rule":            "deny_storm",
				"severity":        "high",
				"agent_id":        "agent-1",
				"source_event_id": "evt-1",
				"summary":         "5 denies in 60s",
				"created_at":      "2026-01-01T00:00:00Z",
			},
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	alerts, err := client.ListAlerts(context.Background(), aegis.ListAlertsOptions{
		Severity: "high",
		AgentID:  "agent-1",
	})
	if err != nil {
		t.Fatalf("ListAlerts error: %v", err)
	}
	if len(alerts) != 1 || alerts[0].ID != "alert-1" || alerts[0].AgentID != "agent-1" {
		t.Errorf("unexpected alerts: %+v", alerts)
	}
	if !strings.Contains(capturedQuery, "severity=high") || !strings.Contains(capturedQuery, "agent_id=agent-1") {
		t.Errorf("expected query to include filters, got: %q", capturedQuery)
	}
}

func TestListIncidents_ReturnsParsedIncidents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/incidents" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		serveJSON(w, http.StatusOK, []map[string]any{
			{
				"id":               "inc-1",
				"tenant_id":        "tenant-test",
				"kind":             "runaway",
				"severity":         "high",
				"agent_id":         "agent-1",
				"summary":          "20 calls in 10s",
				"source_event_ids": "[]",
				"opened_at":        "2026-01-01T00:00:00Z",
				"status":           "open",
				"closed_at":        nil,
			},
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	incidents, err := client.ListIncidents(context.Background(), aegis.ListIncidentsOptions{})
	if err != nil {
		t.Fatalf("ListIncidents error: %v", err)
	}
	if len(incidents) != 1 || incidents[0].Kind != "runaway" || incidents[0].ClosedAt != nil {
		t.Errorf("unexpected incidents: %+v", incidents)
	}
}

func TestGetSocSummary_ReturnsParsedSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/soc/summary" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		serveJSON(w, http.StatusOK, map[string]any{
			"alerts_total":     10,
			"alerts_high":      3,
			"incidents_total":  2,
			"incidents_open":   1,
			"incidents_closed": 1,
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	summary, err := client.GetSocSummary(context.Background())
	if err != nil {
		t.Fatalf("GetSocSummary error: %v", err)
	}
	if summary.AlertsTotal != 10 || summary.AlertsHigh != 3 || summary.IncidentsOpen != 1 {
		t.Errorf("unexpected summary: %+v", summary)
	}
}
