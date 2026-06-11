package secretsengine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const roleStoragePrefix = "role/"

// graphqlRoleEntry binds an OpenBao role to an upstream GraphQL identity
// plus the lease bounds applied to tokens issued for it.
type graphqlRoleEntry struct {
	Name     string        `json:"name"`
	Username string        `json:"username"`
	Password string        `json:"password"`
	TTL      time.Duration `json:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl"`
}

// toResponseData omits the password: role reads must never leak the
// upstream credential.
func (r *graphqlRoleEntry) toResponseData() map[string]any {
	return map[string]any{
		"name":     r.Name,
		"username": r.Username,
		"ttl":      int64(r.TTL.Seconds()),
		"max_ttl":  int64(r.MaxTTL.Seconds()),
	}
}

func pathRole(b *graphqlBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"username": {
					Type:        framework.TypeString,
					Description: "Upstream GraphQL username this role signs in as",
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Upstream GraphQL password for the username",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease TTL for tokens issued from this role",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lease TTL for tokens issued from this role",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *graphqlBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *graphqlBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	return logical.ListResponse(entries), nil
}

func (b *graphqlBackend) pathRolesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: role.toResponseData(),
	}, nil
}

// pathRolesWrite upserts the role, then immediately issues a leased token
// through issueRoleCreds. Returning a real Secret here (not just role
// metadata) is intentional: a role write proves the stored credentials
// work and hands the caller a usable token with a lease_id, identical in
// shape to what creds/<name> returns.
func (b *graphqlBackend) pathRolesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation
	if role == nil {
		if !createOperation {
			return nil, errors.New("role not found during update operation")
		}
		role = &graphqlRoleEntry{Name: name}
	}

	if username, ok := data.GetOk("username"); ok {
		role.Username = username.(string)
	} else if createOperation {
		return nil, errors.New("missing username in role")
	}

	if password, ok := data.GetOk("password"); ok {
		role.Password = password.(string)
	} else if createOperation {
		return nil, errors.New("missing password in role")
	}

	if ttlRaw, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}
	if maxTTLRaw, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}
	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, role); err != nil {
		return nil, err
	}

	// Single issuance path shared with creds/<name>.
	return b.issueRoleCreds(ctx, req, role)
}

func (b *graphqlBackend) pathRolesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if err := req.Storage.Delete(ctx, roleStoragePrefix+name); err != nil {
		return nil, fmt.Errorf("deleting role %q: %w", name, err)
	}
	return nil, nil
}

func (b *graphqlBackend) getRole(ctx context.Context, s logical.Storage, name string) (*graphqlRoleEntry, error) {
	if name == "" {
		return nil, errors.New("missing role name")
	}

	entry, err := s.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("reading role %q: %w", name, err)
	}
	if entry == nil {
		return nil, nil
	}

	role := new(graphqlRoleEntry)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, fmt.Errorf("decoding role %q: %w", name, err)
	}
	// Backfill for entries written before Name was persisted.
	if role.Name == "" {
		role.Name = name
	}
	return role, nil
}

func setRole(ctx context.Context, s logical.Storage, role *graphqlRoleEntry) error {
	entry, err := logical.StorageEntryJSON(roleStoragePrefix+role.Name, role)
	if err != nil {
		return fmt.Errorf("encoding role %q: %w", role.Name, err)
	}
	if entry == nil {
		return errors.New("encoded role entry was nil")
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("persisting role %q: %w", role.Name, err)
	}
	return nil
}

const pathRoleHelpSynopsis = `Manage roles that issue GraphQL tokens.`

const pathRoleHelpDescription = `
A role binds an upstream GraphQL identity (username/password) to lease
bounds. Writing a role validates the credentials by signing in and returns
a leased token, the same shape as reading creds/<role>.
`

const pathRoleListHelpSynopsis = `List configured roles.`
const pathRoleListHelpDescription = `List the names of all configured roles.`
