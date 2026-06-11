package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const configStoragePath = "config"

// graphqlConfig holds the management credentials and endpoint for the
// upstream GraphQL server. URL must be the full GraphQL endpoint
// (e.g. http://graphql-server:9090/query) -- no path is inferred.
type graphqlConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

func pathConfig(b *graphqlBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Management username for the GraphQL server",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Username",
					Sensitive: false,
				},
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Management password for the GraphQL server",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Password",
					Sensitive: true,
				},
			},
			"url": {
				Type:        framework.TypeString,
				Description: "Full GraphQL endpoint URL, e.g. http://host:9090/query",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "URL",
					Sensitive: false,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck lets the framework distinguish create vs
// update so CAS-style semantics work for clients that care.
func (b *graphqlBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

// pathConfigRead never returns the password.
func (b *graphqlBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]any{
			"username": config.Username,
			"url":      config.URL,
		},
	}, nil
}

func (b *graphqlBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation
	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(graphqlConfig)
	}

	if username, ok := data.GetOk("username"); ok {
		config.Username = username.(string)
	} else if createOperation {
		return nil, errors.New("missing username in configuration")
	}

	if password, ok := data.GetOk("password"); ok {
		config.Password = password.(string)
	} else if createOperation {
		return nil, errors.New("missing password in configuration")
	}

	if u, ok := data.GetOk("url"); ok {
		config.URL = u.(string)
	} else if createOperation {
		return nil, errors.New("missing url in configuration")
	}

	if err := putConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	// Drop the cached client so the next operation picks up new settings.
	b.reset()

	return nil, nil
}

func (b *graphqlBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, fmt.Errorf("deleting configuration: %w", err)
	}
	b.reset()
	return nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*graphqlConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, fmt.Errorf("reading configuration: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	config := new(graphqlConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, fmt.Errorf("decoding configuration: %w", err)
	}
	return config, nil
}

func putConfig(ctx context.Context, s logical.Storage, config *graphqlConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return fmt.Errorf("encoding configuration: %w", err)
	}
	if entry == nil {
		return errors.New("encoded configuration entry was nil")
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("persisting configuration: %w", err)
	}
	return nil
}

const pathConfigHelpSynopsis = `Configure the GraphQL backend.`

const pathConfigHelpDescription = `
The GraphQL secrets backend requires management credentials and the full
URL of the upstream GraphQL endpoint. The password is write-only and is
never returned by read operations. Use config/rotate-root to rotate it.
`
