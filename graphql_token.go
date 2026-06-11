package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const graphqlTokenType = "graphql_token"

// graphqlToken defines the leased secret this engine issues. Registering
// it in backend.go (Secrets:) is what makes OpenBao attach a lease_id to
// responses produced via b.Secret(graphqlTokenType).Response(...) and
// route expiration through tokenRenew/tokenRevoke.
func (b *graphqlBackend) graphqlToken() *framework.Secret {
	return &framework.Secret{
		Type: graphqlTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "JWT issued by the upstream GraphQL server",
			},
			"user_id": {
				Type:        framework.TypeString,
				Description: "Upstream user ID (prefixed string, e.g. usr_...)",
			},
			"username": {
				Type:        framework.TypeString,
				Description: "Upstream username the token authenticates as",
			},
		},
		Renew:  b.tokenRenew,
		Revoke: b.tokenRevoke,
	}
}

// tokenRenew extends the lease using the issuing role's TTL/MaxTTL. The
// role name travels in InternalData so renewals survive plugin restarts.
func (b *graphqlBackend) tokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, errors.New("secret is missing role internal data")
	}
	roleName, ok := roleRaw.(string)
	if !ok {
		return nil, errors.New("secret role internal data is malformed")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("loading role %q for renewal: %w", roleName, err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %q no longer exists; cannot renew", roleName)
	}

	resp := &logical.Response{Secret: req.Secret}
	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}

// tokenRevoke signs the token out upstream. Hardened on purpose:
//   - missing internal token  -> nothing to revoke, succeed
//   - upstream 401/403 or an invalid-token GraphQL error -> the token is
//     already dead upstream, so report success
//
// Anything else (network down, 5xx) returns an error so OpenBao retries.
// Returning errors for already-dead tokens is what wedges the revocation
// queue and blocks mount disable/seal operations.
func (b *graphqlBackend) tokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tokenRaw, ok := req.Secret.InternalData["token"]
	if !ok {
		return nil, nil
	}
	token, ok := tokenRaw.(string)
	if !ok || token == "" {
		return nil, nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("building client for revocation: %w", err)
	}

	if err := client.SignOut(ctx, token); err != nil {
		if errors.Is(err, errPermissionDenied) {
			// Token already invalid upstream; revocation goal achieved.
			return nil, nil
		}
		return nil, fmt.Errorf("revoking graphql token: %w", err)
	}
	return nil, nil
}

// issueRoleCreds is the single credential issuance path. Both role writes
// (path_roles.go) and creds/<role> reads (path_credentials.go) call this,
// so lease shape, TTL handling, and internal data stay identical no matter
// how a token was requested.
func (b *graphqlBackend) issueRoleCreds(ctx context.Context, req *logical.Request, role *graphqlRoleEntry) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	auth, err := client.SignIn(ctx, role.Username, role.Password)
	if err != nil {
		return nil, fmt.Errorf("issuing credentials for role %q: %w", role.Name, err)
	}

	resp := b.Secret(graphqlTokenType).Response(
		// Response data: what the caller sees alongside lease_id.
		map[string]any{
			"token":    auth.Token,
			"user_id":  auth.UserID,
			"username": auth.Username,
		},
		// Internal data: what renew/revoke need later.
		map[string]any{
			"token": auth.Token,
			"role":  role.Name,
		},
	)

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}
