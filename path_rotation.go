package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/base62"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathRotateRoot(b *graphqlBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRootWrite,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    pathRotateRootHelpSyn,
		HelpDescription: pathRotateRootHelpDesc,
	}
}

// pathRotateRootWrite rotates the management password:
//  1. sign in with current config creds (proves they still work)
//  2. updatePassword to a generated value via that session token
//  3. persist new config, then drop the cached client
//  4. best-effort sign-out of the rotation session
//
// Order matters: persist only after the upstream accepted the new
// password, so storage never holds a password the server doesn't know.
// The window where the server has the new password but storage write
// fails is surfaced as a hard error for the operator to reconcile.
func (b *graphqlBackend) pathRotateRootWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("backend is not configured; nothing to rotate")
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	auth, err := client.SignIn(ctx, config.Username, config.Password)
	if err != nil {
		return nil, fmt.Errorf("authenticating with current root credentials: %w", err)
	}

	newPassword, err := base62.Random(24)
	if err != nil {
		return nil, fmt.Errorf("generating replacement password: %w", err)
	}

	if err := client.UpdatePassword(ctx, auth.Token, newPassword); err != nil {
		return nil, fmt.Errorf("rotating root password upstream: %w", err)
	}

	config.Password = newPassword
	if err := putConfig(ctx, req.Storage, config); err != nil {
		return nil, fmt.Errorf("CRITICAL: upstream password rotated but storing new config failed; reconcile manually: %w", err)
	}

	// Cached client still holds the old password; rebuild on next use.
	b.reset()

	// Best-effort: the rotation session token is short-lived anyway.
	_ = client.SignOut(ctx, auth.Token)

	return nil, nil
}

const pathRotateRootHelpSyn = `Rotate the configured management password.`

const pathRotateRootHelpDesc = `
Generates a new random password, applies it upstream via the
updatePassword mutation, and persists it in the backend config. The new
password is never returned; reads of config continue to omit it.
`
