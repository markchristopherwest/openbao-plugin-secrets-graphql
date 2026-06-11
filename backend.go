package secretsengine

import (
	"context"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Factory returns a configured instance of the GraphQL secrets backend.
// OpenBao's plugin host calls this via plugin.ServeMultiplex in cmd/.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// graphqlBackend wraps the framework backend and caches the upstream
// GraphQL client. The client is rebuilt lazily whenever config changes
// (see invalidate/reset).
type graphqlBackend struct {
	*framework.Backend

	lock   sync.RWMutex
	client *graphqlClient
}

func backend() *graphqlBackend {
	var b = graphqlBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
				pathRotateRoot(&b),
			},
		),
		// Secrets registration is what wires lease_id issuance and the
		// renew/revoke callbacks into OpenBao's expiration manager.
		// Without this, responses carrying a Secret are rejected at
		// mount time ("secret type unsupported").
		Secrets: []*framework.Secret{
			b.graphqlToken(),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return &b
}

// reset drops the cached client so the next operation rebuilds it from
// the (possibly changed) stored config.
func (b *graphqlBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate is called by OpenBao core when replicated/HA storage for a
// key changes underneath this node.
func (b *graphqlBackend) invalidate(_ context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient returns the cached client, building one from stored config
// under the write lock if needed. Double-checked locking mirrors the
// upstream scaffold; the client itself is safe for concurrent use and
// never mutates shared auth state (see doAuth in client.go).
func (b *graphqlBackend) getClient(ctx context.Context, s logical.Storage) (*graphqlClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	// Re-check under the write lock: another goroutine may have built it.
	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = new(graphqlConfig)
	}

	client, err := newClient(config)
	if err != nil {
		return nil, err
	}
	b.client = client

	return b.client, nil
}

const backendHelp = `
The GraphQL secrets backend dynamically issues, renews, and revokes JSON
Web Tokens (JWTs) against an upstream GraphQL identity server.

After mounting this backend in OpenBao, configure connection credentials
with the "config" endpoint, define identities under "role/", and read
leased tokens from "creds/<role>".
`
