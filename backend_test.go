package secretsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// getTestBackend returns a started backend over in-memory storage.
func getTestBackend(tb testing.TB) (*graphqlBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatalf("unable to create backend: %v", err)
	}

	return b.(*graphqlBackend), config.StorageView
}

// mockGQL is an httptest-backed stand-in for graphql-server-go. It speaks
// just enough GraphQL-over-HTTP for the plugin: signIn / signOut /
// updatePassword, with live tokens tracked so revocation semantics are
// testable (unknown token on signOut -> 401, matching the real server).
type mockGQL struct {
	tb testing.TB

	mu      sync.Mutex
	creds   map[string]string // username -> password
	tokens  map[string]string // token -> username
	nextTok int

	Server *httptest.Server
}

func newMockGQL(tb testing.TB, creds map[string]string) *mockGQL {
	tb.Helper()
	m := &mockGQL{
		tb:     tb,
		creds:  creds,
		tokens: map[string]string{},
	}
	m.Server = httptest.NewServer(http.HandlerFunc(m.handle))
	tb.Cleanup(m.Server.Close)
	return m
}

// Endpoint returns the full GraphQL URL, as the plugin config expects.
func (m *mockGQL) Endpoint() string { return m.Server.URL + "/query" }

// LiveTokens reports how many issued tokens have not been signed out.
func (m *mockGQL) LiveTokens() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tokens)
}

func (m *mockGQL) handle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case strings.Contains(req.Query, "signIn"):
		username, _ := req.Variables["username"].(string)
		password, _ := req.Variables["password"].(string)
		stored, ok := m.creds[username]
		if !ok || stored != password {
			writeGQLErrors(w, "invalid credentials")
			return
		}
		m.nextTok++
		token := fmt.Sprintf("jwt-%s-%d", username, m.nextTok)
		m.tokens[token] = username
		writeGQLData(w, map[string]any{
			"signIn": map[string]any{
				"userId":   "usr_" + username,
				"username": username,
				"token":    token,
			},
		})

	case strings.Contains(req.Query, "signOut"):
		token := r.Header.Get("Authorization")
		if _, ok := m.tokens[token]; !ok {
			// Real server 401s on unknown/expired tokens; the plugin's
			// revoke path must treat this as success.
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		delete(m.tokens, token)
		writeGQLData(w, map[string]any{"signOut": true})

	case strings.Contains(req.Query, "updatePassword"):
		token := r.Header.Get("Authorization")
		username, ok := m.tokens[token]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		newPassword, _ := req.Variables["password"].(string)
		if newPassword == "" {
			writeGQLErrors(w, "password must not be empty")
			return
		}
		m.creds[username] = newPassword
		writeGQLData(w, map[string]any{"updatePassword": true})

	default:
		writeGQLErrors(w, "unknown operation")
	}
}

func writeGQLData(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func writeGQLErrors(w http.ResponseWriter, msgs ...string) {
	w.Header().Set("Content-Type", "application/json")
	errs := make([]map[string]string, 0, len(msgs))
	for _, m := range msgs {
		errs = append(errs, map[string]string{"message": m})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": errs})
}

// writeTestConfig points the backend at the mock server.
func writeTestConfig(tb testing.TB, b *graphqlBackend, s logical.Storage, m *mockGQL, username, password string) {
	tb.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Storage:   s,
		Data: map[string]any{
			"username": username,
			"password": password,
			"url":      m.Endpoint(),
		},
	})
	if err != nil {
		tb.Fatalf("writing config: %v", err)
	}
	if resp.IsError() {
		tb.Fatalf("writing config returned error response: %v", resp.Error())
	}
}

func TestBackendFactory(t *testing.T) {
	b, _ := getTestBackend(t)
	if b == nil {
		t.Fatal("expected backend, got nil")
	}
	// Secrets registration is load-bearing: lease issuance panics at the
	// core boundary without it.
	if b.Secret(graphqlTokenType) == nil {
		t.Fatalf("secret type %q is not registered", graphqlTokenType)
	}
}
