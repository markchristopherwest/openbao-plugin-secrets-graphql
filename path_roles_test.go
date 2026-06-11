package secretsengine

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestRoleWriteIssuesLeasedSecret(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	mock := newMockGQL(t, map[string]string{
		"admin":   "changeme",
		"app-svc": "s3cret",
	})
	writeTestConfig(t, b, s, mock, "admin", "changeme")

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/my-role",
		Storage:   s,
		Data: map[string]any{
			"username": "app-svc",
			"password": "s3cret",
			"ttl":      300,
			"max_ttl":  3600,
		},
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	// The write itself must carry a leased secret, same shape as creds/.
	if resp.Secret == nil {
		t.Fatal("role write did not return a Secret")
	}
	if resp.Secret.SecretType != graphqlTokenType {
		t.Fatalf("secret type = %q, want %q", resp.Secret.SecretType, graphqlTokenType)
	}
	if resp.Secret.TTL != 300*time.Second || resp.Secret.MaxTTL != 3600*time.Second {
		t.Fatalf("lease bounds = %v/%v", resp.Secret.TTL, resp.Secret.MaxTTL)
	}
	if tok, _ := resp.Data["token"].(string); tok == "" {
		t.Fatal("role write returned empty token")
	}
	if uid, _ := resp.Data["user_id"].(string); uid != "usr_app-svc" {
		t.Fatalf("user_id = %v, want usr_app-svc (string, prefixed)", resp.Data["user_id"])
	}
	// Internal data must let renew/revoke do their jobs later.
	if resp.Secret.InternalData["role"] != "my-role" {
		t.Fatalf("internal role = %v", resp.Secret.InternalData["role"])
	}
	if resp.Secret.InternalData["token"] == "" {
		t.Fatal("internal token missing")
	}
}

func TestRoleReadListDelete(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	mock := newMockGQL(t, map[string]string{"app-svc": "s3cret"})
	writeTestConfig(t, b, s, mock, "app-svc", "s3cret")

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/my-role",
		Storage:   s,
		Data:      map[string]any{"username": "app-svc", "password": "s3cret"},
	}); err != nil {
		t.Fatalf("role write: %v", err)
	}

	// Read: no password in the response, ever.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/my-role",
		Storage:   s,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("role read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["username"] != "app-svc" {
		t.Fatalf("role username = %v", resp.Data["username"])
	}
	if _, leaked := resp.Data["password"]; leaked {
		t.Fatal("role read leaked password")
	}

	// List.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   s,
	})
	if err != nil || resp == nil {
		t.Fatalf("role list failed: err=%v", err)
	}
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "my-role" {
		t.Fatalf("role list = %v", resp.Data["keys"])
	}

	// Delete, then read returns nil.
	if _, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/my-role",
		Storage:   s,
	}); err != nil {
		t.Fatalf("role delete: %v", err)
	}
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/my-role",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("role read after delete: %v", err)
	}
	if resp != nil {
		t.Fatalf("role survived delete: %v", resp)
	}
}

func TestRoleWriteRejectsTTLAboveMax(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	mock := newMockGQL(t, map[string]string{"app-svc": "s3cret"})
	writeTestConfig(t, b, s, mock, "app-svc", "s3cret")

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/bad",
		Storage:   s,
		Data: map[string]any{
			"username": "app-svc",
			"password": "s3cret",
			"ttl":      600,
			"max_ttl":  60,
		},
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response for ttl > max_ttl, got %v", resp)
	}
}

func TestRoleWriteFailsOnBadUpstreamCreds(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	mock := newMockGQL(t, map[string]string{"app-svc": "s3cret"})
	writeTestConfig(t, b, s, mock, "app-svc", "s3cret")

	// Wrong password: the role write must surface the sign-in failure so
	// broken roles are caught at write time, not first creds read.
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/broken",
		Storage:   s,
		Data:      map[string]any{"username": "app-svc", "password": "wrong"},
	})
	if err == nil {
		t.Fatal("expected role write with bad upstream creds to fail")
	}
}
