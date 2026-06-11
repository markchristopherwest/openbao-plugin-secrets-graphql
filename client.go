package secretsengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// errPermissionDenied marks upstream auth failures: HTTP 401/403 or a
// GraphQL error whose message indicates a dead/invalid token. Revocation
// treats this sentinel as success so an already-expired upstream token can
// never wedge OpenBao's revocation queue.
var errPermissionDenied = errors.New("graphql: permission denied")

const defaultRequestTimeout = 10 * time.Second

// Operation documents. These must match the schema served by
// graphql-server-go (gqlgen, default endpoint path /query). Field names
// are camelCase per that schema; userId is a prefixed string ("usr_...").
const (
	opSignIn = `mutation SignIn($username: String!, $password: String!) {
  signIn(username: $username, password: $password) {
    userId
    username
    token
  }
}`

	opSignOut = `mutation SignOut {
  signOut
}`

	opUpdatePassword = `mutation UpdatePassword($password: String!) {
  updatePassword(password: $password)
}`
)

// AuthResponse is the payload returned by the signIn mutation.
// UserID is a string on purpose: the server issues prefixed IDs like
// "usr_01h..." and an int here breaks unmarshaling.
type AuthResponse struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

// graphqlClient is a minimal, dependency-free GraphQL-over-HTTP client.
// It is intentionally stateless with respect to auth: every call that
// needs a token takes it as an argument (doAuth principle), so revoking
// a lease token can never clobber credentials shared by other operations.
type graphqlClient struct {
	httpClient *http.Client
	endpoint   string // full GraphQL endpoint URL, e.g. http://host:9090/query
	username   string // management identity from config; used by rotate-root
	password   string
}

// newClient validates stored config and returns a client. The endpoint
// must be the full GraphQL URL including path; we do not guess "/query"
// so that proxies/ingress rewrites stay explicit.
func newClient(config *graphqlConfig) (*graphqlClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}
	if config.Username == "" {
		return nil, errors.New("client username was not defined")
	}
	if config.Password == "" {
		return nil, errors.New("client password was not defined")
	}
	if config.URL == "" {
		return nil, errors.New("client URL was not defined")
	}
	if _, err := url.ParseRequestURI(config.URL); err != nil {
		return nil, fmt.Errorf("client URL is invalid: %w", err)
	}

	return &graphqlClient{
		httpClient: &http.Client{Timeout: defaultRequestTimeout},
		endpoint:   config.URL,
		username:   config.Username,
		password:   config.Password,
	}, nil
}

// gqlRequest / gqlEnvelope are the standard GraphQL-over-HTTP shapes.
type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type gqlError struct {
	Message string `json:"message"`
}

type gqlEnvelope struct {
	Data   json.RawMessage `json:"data"`
	Errors []gqlError      `json:"errors"`
}

// do executes one GraphQL operation. authToken, when non-empty, is sent
// as the Authorization header (raw JWT, matching the server's middleware).
// out, when non-nil, receives the unmarshaled "data" object.
func (c *graphqlClient) do(ctx context.Context, query string, variables map[string]any, authToken string, out any) error {
	body, err := json.Marshal(gqlRequest{Query: query, Variables: variables})
	if err != nil {
		return fmt.Errorf("marshaling graphql request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building graphql request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing graphql request: %w", err)
	}
	defer resp.Body.Close()

	// Cap the read so a misbehaving upstream can't balloon plugin memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("reading graphql response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: status %d", errPermissionDenied, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("graphql endpoint returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var env gqlEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("decoding graphql envelope: %w", err)
	}
	if len(env.Errors) > 0 {
		msg := env.Errors[0].Message
		if isAuthErrMessage(msg) {
			return fmt.Errorf("%w: %s", errPermissionDenied, msg)
		}
		return fmt.Errorf("graphql error: %s", msg)
	}

	if out != nil {
		if len(env.Data) == 0 || string(env.Data) == "null" {
			return errors.New("graphql response contained no data")
		}
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("decoding graphql data: %w", err)
		}
	}
	return nil
}

// isAuthErrMessage classifies GraphQL-level errors that mean the token
// (or credentials) are already invalid upstream. Kept deliberately broad:
// misclassifying a dead token as dead is harmless; the reverse wedges
// the revocation queue.
func isAuthErrMessage(msg string) bool {
	m := strings.ToLower(msg)
	for _, needle := range []string{
		"unauthorized",
		"unauthenticated",
		"permission denied",
		"forbidden",
		"invalid token",
		"token expired",
		"invalid credentials",
	} {
		if strings.Contains(m, needle) {
			return true
		}
	}
	return false
}

// SignIn authenticates an arbitrary identity and returns its JWT. It does
// not store the token on the client.
func (c *graphqlClient) SignIn(ctx context.Context, username, password string) (*AuthResponse, error) {
	var payload struct {
		SignIn AuthResponse `json:"signIn"`
	}
	err := c.do(ctx, opSignIn, map[string]any{
		"username": username,
		"password": password,
	}, "", &payload)
	if err != nil {
		return nil, fmt.Errorf("signing in user %q: %w", username, err)
	}
	if payload.SignIn.Token == "" {
		return nil, errors.New("sign-in succeeded but returned an empty token")
	}
	return &payload.SignIn, nil
}

// SignOut invalidates the supplied token upstream. The token is explicit
// (never read from client state) so concurrent revocations are isolated.
func (c *graphqlClient) SignOut(ctx context.Context, token string) error {
	var payload struct {
		SignOut bool `json:"signOut"`
	}
	if err := c.do(ctx, opSignOut, nil, token, &payload); err != nil {
		return fmt.Errorf("signing out: %w", err)
	}
	return nil
}

// UpdatePassword changes the password of the identity that owns the
// supplied token. Used by config/rotate-root.
func (c *graphqlClient) UpdatePassword(ctx context.Context, token, newPassword string) error {
	var payload struct {
		UpdatePassword bool `json:"updatePassword"`
	}
	if err := c.do(ctx, opUpdatePassword, map[string]any{
		"password": newPassword,
	}, token, &payload); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	if !payload.UpdatePassword {
		return errors.New("server reported password update did not apply")
	}
	return nil
}
