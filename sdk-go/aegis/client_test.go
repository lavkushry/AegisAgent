package aegis_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	resp, err := client.Authorize(aegis.AuthorizeRequest{
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
	_, err := client.Authorize(aegis.AuthorizeRequest{
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
	status, err := client.GetApproval("appr-001")
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
	resp, err := client.ConsumeApproval("appr-999")
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
	_, err := client.ConsumeApproval("appr-dup")
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
	_, err := client.Authorize(aegis.AuthorizeRequest{
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
	_, err := client.Authorize(aegis.AuthorizeRequest{
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
	_, err := client.Authorize(aegis.AuthorizeRequest{
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
