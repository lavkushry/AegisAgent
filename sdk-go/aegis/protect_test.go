package aegis_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lavkushry/aegisagent/sdk-go/aegis"
	"github.com/lavkushry/aegisagent/sdk-go/canon"
)

// hashAction computes the expected action_hash for an AuthorizeRequest,
// mirroring what Protect does internally so tests can supply correct hashes.
// resource is a *string; we dereference to an untyped nil or string value so
// that canon (which does not handle pointer types) receives a supported type.
func hashAction(t *testing.T, req aegis.AuthorizeRequest) string {
	t.Helper()
	var resource any
	if req.Resource != nil {
		resource = *req.Resource
	}
	h, err := canon.CanonicalHash(map[string]any{
		"tool":          req.Tool,
		"action":        req.Action,
		"resource":      resource,
		"mutates_state": req.MutatesState,
		"parameters":    req.Parameters,
	})
	if err != nil {
		t.Fatalf("hashAction: %v", err)
	}
	return h
}

// toolCallTracker wraps a bool to record whether the tool was executed.
type toolCallTracker struct {
	called bool
}

func (tc *toolCallTracker) tool() error {
	tc.called = true
	return nil
}

// ---------- Protect — instant allow -----------------------------------------

func TestProtect_Allow_ExecutesTool(t *testing.T) {
	req := aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "list_prs",
		Parameters:   map[string]any{"repo": "aegis"},
		MutatesState: false,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, http.StatusOK, map[string]any{
			"decision":    "allow",
			"action_hash": hashAction(t, req),
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	tracker := &toolCallTracker{}

	err := aegis.Protect(context.Background(), client, req, func() error {
		return tracker.tool()
	})
	if err != nil {
		t.Fatalf("expected no error on allow, got: %v", err)
	}
	if !tracker.called {
		t.Error("expected tool to be called on allow decision")
	}
}

// ---------- Protect — deny --------------------------------------------------

func TestProtect_Deny_RefusesAndDoesNotExecute(t *testing.T) {
	req := aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "force_push",
		Parameters:   map[string]any{"branch": "main"},
		MutatesState: true,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, http.StatusOK, map[string]any{
			"decision": "deny",
			"reason":   "forbidden by policy",
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	tracker := &toolCallTracker{}

	err := aegis.Protect(context.Background(), client, req, func() error {
		return tracker.tool()
	})
	if err == nil {
		t.Fatal("expected error on deny, got nil")
	}
	if tracker.called {
		t.Error("tool must NOT be executed on deny")
	}
	var deniedErr *aegis.ErrDenied
	if !errors.As(err, &deniedErr) {
		t.Errorf("expected ErrDenied, got %T: %v", err, err)
	}
}

// ---------- Protect — require_approval → approved ---------------------------

func TestProtect_ApprovalPoll_PendingThenApproved_ExecutesTool(t *testing.T) {
	req := aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "merge_pr",
		Parameters:   map[string]any{"pr": float64(42)},
		MutatesState: true,
	}
	approvalID := "appr-poll-001"
	actionHash := hashAction(t, req)

	var pollCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/authorize":
			serveJSON(w, http.StatusOK, map[string]any{
				"decision":    "require_approval",
				"action_hash": actionHash,
				"approval": map[string]any{
					"approval_id": approvalID,
					"action_hash": actionHash,
				},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/"+approvalID:
			n := atomic.AddInt32(&pollCount, 1)
			if n < 2 {
				// First poll: still pending
				serveJSON(w, http.StatusOK, map[string]any{
					"status":      "PENDING",
					"action_hash": actionHash,
				})
			} else {
				// Second poll: approved
				serveJSON(w, http.StatusOK, map[string]any{
					"status":      "APPROVED",
					"action_hash": actionHash,
				})
			}

		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals/"+approvalID+"/consume":
			serveJSON(w, http.StatusOK, map[string]any{
				"action_hash": actionHash,
			})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	tracker := &toolCallTracker{}

	opts := aegis.ProtectOptions{
		PollInterval: 0, // zero → no sleep in tests
		MaxPolls:     5,
	}
	err := aegis.ProtectWithOptions(context.Background(), client, req, func() error {
		return tracker.tool()
	}, opts)
	if err != nil {
		t.Fatalf("expected approval to succeed, got: %v", err)
	}
	if !tracker.called {
		t.Error("tool must be called after approval")
	}
}

// ---------- Protect — hash mismatch → refuse --------------------------------

func TestProtect_HashMismatch_RefusesAndDoesNotExecute(t *testing.T) {
	req := aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "delete_branch",
		Parameters:   map[string]any{"branch": "feature-x"},
		MutatesState: true,
	}
	approvalID := "appr-mismatch-001"
	badHash := "000000000000000000000000000000000000000000000000000000000000dead"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/authorize":
			// Return a mismatched action_hash in the approval
			serveJSON(w, http.StatusOK, map[string]any{
				"decision":    "require_approval",
				"action_hash": badHash,
				"approval": map[string]any{
					"approval_id": approvalID,
					"action_hash": badHash, // deliberately wrong
				},
			})

		default:
			// Should not reach polling or consume
			t.Errorf("unexpected request after hash mismatch: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	tracker := &toolCallTracker{}

	err := aegis.Protect(context.Background(), client, req, func() error {
		return tracker.tool()
	})
	if err == nil {
		t.Fatal("expected error on hash mismatch, got nil")
	}
	if tracker.called {
		t.Error("tool must NOT be called when action_hash mismatches")
	}
	var hashErr *aegis.ErrHashMismatch
	if !errors.As(err, &hashErr) {
		t.Errorf("expected ErrHashMismatch, got %T: %v", err, err)
	}
}

// ---------- Protect — hash mismatch on poll status → refuse -----------------

func TestProtect_HashMismatch_OnPollStatus_RefusesAndDoesNotExecute(t *testing.T) {
	req := aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "deploy",
		Parameters:   map[string]any{"env": "prod"},
		MutatesState: true,
	}
	approvalID := "appr-pollmismatch"
	correctHash := hashAction(t, req)
	tamperedHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/authorize":
			serveJSON(w, http.StatusOK, map[string]any{
				"decision":    "require_approval",
				"action_hash": correctHash,
				"approval": map[string]any{
					"approval_id": approvalID,
					"action_hash": correctHash,
				},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/"+approvalID:
			// Gateway returns APPROVED but with a tampered hash (approve-then-swap attack)
			serveJSON(w, http.StatusOK, map[string]any{
				"status":      "APPROVED",
				"action_hash": tamperedHash,
			})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	tracker := &toolCallTracker{}

	opts := aegis.ProtectOptions{PollInterval: 0, MaxPolls: 3}
	err := aegis.ProtectWithOptions(context.Background(), client, req, func() error {
		return tracker.tool()
	}, opts)
	if err == nil {
		t.Fatal("expected error on tampered poll hash, got nil")
	}
	if tracker.called {
		t.Error("tool must NOT be called when poll action_hash mismatches")
	}
}

// ---------- Protect — unreachable gateway, mutating → refuse ----------------

func TestProtect_UnreachableGateway_MutatingAction_Refuses(t *testing.T) {
	client := aegis.NewClient(aegis.ClientOptions{
		BaseURL:    "http://127.0.0.1:1", // nothing listening
		AgentToken: "tok",
		TenantID:   "tid",
	})

	req := aegis.AuthorizeRequest{
		Tool:         "filesystem",
		Action:       "delete_file",
		Parameters:   map[string]any{"path": "/etc/passwd"},
		MutatesState: true,
	}
	tracker := &toolCallTracker{}

	err := aegis.Protect(context.Background(), client, req, func() error {
		return tracker.tool()
	})
	if err == nil {
		t.Fatal("expected error when gateway is unreachable on mutating action, got nil")
	}
	if tracker.called {
		t.Error("tool must NOT be called when gateway is unreachable for mutating action")
	}
}

// ---------- Protect — consume 409 → refuse (single-use replay defense) ------

func TestProtect_ConsumeFails_409_RefusesAndDoesNotExecute(t *testing.T) {
	req := aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "push",
		Parameters:   map[string]any{"branch": "main"},
		MutatesState: true,
	}
	approvalID := "appr-replay-001"
	actionHash := hashAction(t, req)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/authorize":
			serveJSON(w, http.StatusOK, map[string]any{
				"decision":    "require_approval",
				"action_hash": actionHash,
				"approval": map[string]any{
					"approval_id": approvalID,
					"action_hash": actionHash,
				},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/"+approvalID:
			serveJSON(w, http.StatusOK, map[string]any{
				"status":      "APPROVED",
				"action_hash": actionHash,
			})

		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals/"+approvalID+"/consume":
			// Simulate already-consumed (replay attempt)
			serveJSON(w, http.StatusConflict, map[string]any{
				"error": "approval already consumed",
			})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	tracker := &toolCallTracker{}

	opts := aegis.ProtectOptions{PollInterval: 0, MaxPolls: 3}
	err := aegis.ProtectWithOptions(context.Background(), client, req, func() error {
		return tracker.tool()
	}, opts)
	if err == nil {
		t.Fatal("expected error when consume returns 409, got nil")
	}
	if tracker.called {
		t.Error("tool must NOT be called when consume fails")
	}
}

// ---------- Protect — approval rejected → refuse ----------------------------

func TestProtect_Rejected_Refuses(t *testing.T) {
	req := aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "close_issue",
		Parameters:   map[string]any{"issue": float64(99)},
		MutatesState: true,
	}
	approvalID := "appr-rejected-001"
	actionHash := hashAction(t, req)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/authorize":
			serveJSON(w, http.StatusOK, map[string]any{
				"decision":    "require_approval",
				"action_hash": actionHash,
				"approval": map[string]any{
					"approval_id": approvalID,
					"action_hash": actionHash,
				},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/"+approvalID:
			serveJSON(w, http.StatusOK, map[string]any{
				"status":      "REJECTED",
				"action_hash": actionHash,
				"reason":      "reviewer declined",
			})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	tracker := &toolCallTracker{}

	opts := aegis.ProtectOptions{PollInterval: 0, MaxPolls: 3}
	err := aegis.ProtectWithOptions(context.Background(), client, req, func() error {
		return tracker.tool()
	}, opts)
	if err == nil {
		t.Fatal("expected error on rejection, got nil")
	}
	if tracker.called {
		t.Error("tool must NOT be called when approval is rejected")
	}
}

// ---------- Protect — missing approval info → refuse (fail closed) -----------

func TestProtect_RequireApproval_MissingApprovalInfo_FailsClosed(t *testing.T) {
	req := aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "merge_pr",
		Parameters:   map[string]any{"pr": float64(7)},
		MutatesState: true,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Gateway says require_approval but does not include the approval object
		serveJSON(w, http.StatusOK, map[string]any{
			"decision": "require_approval",
			// no "approval" key
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	tracker := &toolCallTracker{}

	err := aegis.Protect(context.Background(), client, req, func() error {
		return tracker.tool()
	})
	if err == nil {
		t.Fatal("expected error when approval info missing, got nil")
	}
	if tracker.called {
		t.Error("tool must NOT be called when approval info is missing")
	}
}

// ---------- Protect — unknown decision → refuse (fail closed) ---------------

func TestProtect_UnknownDecision_FailsClosed(t *testing.T) {
	req := aegis.AuthorizeRequest{
		Tool:         "github",
		Action:       "list_prs",
		Parameters:   map[string]any{},
		MutatesState: false,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, http.StatusOK, map[string]any{
			"decision": "maybe", // not a recognised decision
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	tracker := &toolCallTracker{}

	err := aegis.Protect(context.Background(), client, req, func() error {
		return tracker.tool()
	})
	if err == nil {
		t.Fatal("expected error on unknown decision, got nil")
	}
	if tracker.called {
		t.Error("tool must NOT be called on unknown decision")
	}
}
