package secretsengine

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestRotateRoot(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	mock := newMockGQL(t, map[string]string{"admin": "changeme"})
	writeTestConfig(t, b, s, mock, "admin", "changeme")

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("rotate-root failed: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("rotate-root error response: %v", resp.Error())
	}

	cfg, err := getConfig(ctx, s)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg.Password == "changeme" {
		t.Fatal("password did not rotate in storage")
	}

	// The new password must actually work: build a fresh client from the
	// rotated config and sign in. This also proves the upstream accepted
	// the same value that was persisted.
	client, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient after rotation: %v", err)
	}
	if _, err := client.SignIn(ctx, cfg.Username, cfg.Password); err != nil {
		t.Fatalf("sign-in with rotated password failed: %v", err)
	}

	// The rotation session token must be signed out (best-effort, but the
	// mock is reliable): only the verification sign-in above is live.
	if got := mock.LiveTokens(); got != 1 {
		t.Fatalf("live tokens after rotation+verify = %d, want 1", got)
	}
}

func TestRotateRootUnconfigured(t *testing.T) {
	b, s := getTestBackend(t)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   s,
	}); err == nil {
		t.Fatal("expected rotate-root to fail without config")
	}
}
