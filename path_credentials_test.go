package secretsengine

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// issueViaCreds is a helper that provisions config+role against the mock
// and reads creds/<role>, returning the leased response.
func issueViaCreds(t *testing.T, b *graphqlBackend, s logical.Storage, mock *mockGQL) *logical.Response {
	t.Helper()
	ctx := context.Background()

	writeTestConfig(t, b, s, mock, "admin", "changeme")

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/my-role",
		Storage:   s,
		Data: map[string]any{
			"username": "app-svc",
			"password": "s3cret",
			"ttl":      120,
			"max_ttl":  600,
		},
	}); err != nil {
		t.Fatalf("role write: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/my-role",
		Storage:   s,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("creds read failed: err=%v resp=%v", err, resp)
	}
	return resp
}

func TestCredsReadIssuesLeasedSecret(t *testing.T) {
	b, s := getTestBackend(t)
	mock := newMockGQL(t, map[string]string{
		"admin":   "changeme",
		"app-svc": "s3cret",
	})

	resp := issueViaCreds(t, b, s, mock)

	if resp.Secret == nil || resp.Secret.SecretType != graphqlTokenType {
		t.Fatalf("creds read did not return a %s secret: %v", graphqlTokenType, resp.Secret)
	}
	if resp.Secret.TTL != 120*time.Second || resp.Secret.MaxTTL != 600*time.Second {
		t.Fatalf("lease bounds = %v/%v", resp.Secret.TTL, resp.Secret.MaxTTL)
	}
	if tok, _ := resp.Data["token"].(string); tok == "" {
		t.Fatal("creds read returned empty token")
	}
}

func TestTokenRenewUsesRoleTTLs(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	mock := newMockGQL(t, map[string]string{
		"admin":   "changeme",
		"app-svc": "s3cret",
	})

	issued := issueViaCreds(t, b, s, mock)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/my-role",
		Storage:   s,
		Secret:    issued.Secret,
	})
	if err != nil || resp == nil {
		t.Fatalf("renew failed: err=%v resp=%v", err, resp)
	}
	if resp.Secret.TTL != 120*time.Second || resp.Secret.MaxTTL != 600*time.Second {
		t.Fatalf("renewed lease bounds = %v/%v", resp.Secret.TTL, resp.Secret.MaxTTL)
	}
}

func TestTokenRenewFailsWhenRoleDeleted(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	mock := newMockGQL(t, map[string]string{
		"admin":   "changeme",
		"app-svc": "s3cret",
	})

	issued := issueViaCreds(t, b, s, mock)

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/my-role",
		Storage:   s,
	}); err != nil {
		t.Fatalf("role delete: %v", err)
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RenewOperation,
		Path:      "creds/my-role",
		Storage:   s,
		Secret:    issued.Secret,
	}); err == nil {
		t.Fatal("expected renew to fail after role deletion")
	}
}

func TestTokenRevokeSignsOutUpstream(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	mock := newMockGQL(t, map[string]string{
		"admin":   "changeme",
		"app-svc": "s3cret",
	})

	issued := issueViaCreds(t, b, s, mock)
	if mock.LiveTokens() != 1 {
		t.Fatalf("live tokens before revoke = %d, want 1", mock.LiveTokens())
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/my-role",
		Storage:   s,
		Secret:    issued.Secret,
	})
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("revoke returned error response: %v", resp.Error())
	}
	if mock.LiveTokens() != 0 {
		t.Fatalf("live tokens after revoke = %d, want 0", mock.LiveTokens())
	}
}

func TestTokenRevokeAlreadyDeadTokenSucceeds(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	mock := newMockGQL(t, map[string]string{
		"admin":   "changeme",
		"app-svc": "s3cret",
	})

	issued := issueViaCreds(t, b, s, mock)

	// First revoke kills it upstream.
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/my-role",
		Storage:   s,
		Secret:    issued.Secret,
	}); err != nil {
		t.Fatalf("first revoke: %v", err)
	}

	// Second revoke hits the mock's 401 path. This MUST succeed or
	// OpenBao's revocation queue wedges on already-dead tokens.
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/my-role",
		Storage:   s,
		Secret:    issued.Secret,
	}); err != nil {
		t.Fatalf("revoke of already-dead token must succeed, got: %v", err)
	}
}

func TestCredsReadUnknownRole(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	mock := newMockGQL(t, map[string]string{"admin": "changeme"})
	writeTestConfig(t, b, s, mock, "admin", "changeme")

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/nope",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response for unknown role, got %v", resp)
	}
}

// TestAccCredsAgainstLiveServer runs the issuance/revoke cycle against a
// real graphql-server-go instance. Gated to keep `go test ./...` hermetic:
//
//	BAO_ACC=1 GRAPHQL_URL=http://localhost:9090/query \
//	GRAPHQL_USERNAME=admin GRAPHQL_PASSWORD=changeme go test -run TestAcc ./...
func TestAccCredsAgainstLiveServer(t *testing.T) {
	if os.Getenv("BAO_ACC") != "1" {
		t.Skip("set BAO_ACC=1 to run acceptance tests")
	}
	endpoint := os.Getenv("GRAPHQL_URL")
	username := os.Getenv("GRAPHQL_USERNAME")
	password := os.Getenv("GRAPHQL_PASSWORD")
	if endpoint == "" || username == "" || password == "" {
		t.Fatal("GRAPHQL_URL, GRAPHQL_USERNAME, GRAPHQL_PASSWORD are required for acceptance tests")
	}

	b, s := getTestBackend(t)
	ctx := context.Background()

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Storage:   s,
		Data: map[string]any{
			"username": username,
			"password": password,
			"url":      endpoint,
		},
	}); err != nil {
		t.Fatalf("config write: %v", err)
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/acc",
		Storage:   s,
		Data: map[string]any{
			"username": username,
			"password": password,
			"ttl":      60,
			"max_ttl":  300,
		},
	}); err != nil {
		t.Fatalf("role write: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/acc",
		Storage:   s,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("creds read failed: err=%v resp=%v", err, resp)
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/acc",
		Storage:   s,
		Secret:    resp.Secret,
	}); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
}
