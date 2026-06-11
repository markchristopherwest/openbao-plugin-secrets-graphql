package secretsengine

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathCredentials(b *graphqlBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role to issue credentials for",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
			// Update is accepted too so callers can POST; both funnel
			// into the same issuance path.
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

// pathCredentialsRead resolves the role and delegates to issueRoleCreds,
// the single issuance path shared with role writes.
func (b *graphqlBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("resolving role for credentials: %w", err)
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	return b.issueRoleCreds(ctx, req, role)
}

const pathCredentialsHelpSyn = `Issue a leased GraphQL token for a role.`

const pathCredentialsHelpDesc = `
Reading creds/<role> signs in to the upstream GraphQL server with the
role's stored identity and returns a JWT wrapped in an OpenBao lease.
The lease honors the role's ttl/max_ttl; renewal re-reads the role and
revocation signs the token out upstream.
`
