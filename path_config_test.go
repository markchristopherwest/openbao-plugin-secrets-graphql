package secretsengine

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestConfigCRUD(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	// Create.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Storage:   s,
		Data: map[string]any{
			"username": "admin",
			"password": "changeme",
			"url":      "http://localhost:9090/query",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config create failed: err=%v resp=%v", err, resp)
	}

	// Read must return username/url and must not leak the password.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configStoragePath,
		Storage:   s,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("config read failed: err=%v resp=%v", err, resp)
	}
	if got := resp.Data["username"]; got != "admin" {
		t.Fatalf("username = %v, want admin", got)
	}
	if got := resp.Data["url"]; got != "http://localhost:9090/query" {
		t.Fatalf("url = %v", got)
	}
	if _, leaked := resp.Data["password"]; leaked {
		t.Fatal("config read leaked password")
	}

	// Partial update: password only; other fields must persist.
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configStoragePath,
		Storage:   s,
		Data: map[string]any{
			"password": "rotated",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config update failed: err=%v resp=%v", err, resp)
	}
	cfg, err := getConfig(ctx, s)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg.Password != "rotated" || cfg.Username != "admin" {
		t.Fatalf("config after partial update = %+v", cfg)
	}

	// Delete.
	if _, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configStoragePath,
		Storage:   s,
	}); err != nil {
		t.Fatalf("config delete failed: %v", err)
	}
	cfg, err = getConfig(ctx, s)
	if err != nil {
		t.Fatalf("getConfig after delete: %v", err)
	}
	if cfg != nil {
		t.Fatalf("config survived delete: %+v", cfg)
	}
}

func TestConfigCreateRequiresAllFields(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	for _, data := range []map[string]any{
		{"password": "p", "url": "http://x/query"},
		{"username": "u", "url": "http://x/query"},
		{"username": "u", "password": "p"},
	} {
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      configStoragePath,
			Storage:   s,
			Data:      data,
		})
		if err == nil {
			t.Fatalf("expected error creating config with %v", data)
		}
	}
}
