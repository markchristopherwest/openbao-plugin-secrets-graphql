# openbao-plugin-secrets-graphql

An [OpenBao](https://openbao.org) secrets engine that dynamically issues, renews, and revokes JSON Web Tokens (JWTs) against an upstream GraphQL identity server ([graphql-server-go](https://github.com/markchristopherwest/graphql-server-go)).

Originally a HashiCorp Vault plugin forked from the HashiCups tutorial scaffold; rewritten end-to-end against `github.com/openbao/openbao/sdk/v2`.

## How it works

- `config` stores management credentials and the **full** GraphQL endpoint URL (e.g. `http://host:9090/query`; no path is inferred).
- `role/<name>` binds an upstream identity (username/password) plus `ttl`/`max_ttl`. Writing a role validates the credentials by signing in and returns a **leased token** -- identical in shape to a `creds/` read, `lease_id` included.
- `creds/<name>` signs in as the role's identity and returns a leased JWT.
- Renewal re-reads the role's TTL bounds; revocation signs the token out upstream. Revocation treats upstream `401`/`403` or invalid-token GraphQL errors as **success** so already-dead tokens never wedge the revocation queue.
- `config/rotate-root` rotates the management password via the `updatePassword` mutation; the new password is persisted only after the upstream accepts it and is never returned.

All issuance flows through a single path (`issueRoleCreds`), so role writes and creds reads can't drift.

## Build

```sh
go mod tidy
CGO_ENABLED=0 go build -o bao/plugins/openbao-plugin-secrets-graphql ./cmd/openbao-plugin-secrets-graphql
```

## Run (dev)

```sh
./run.sh
```

Or manually:

```sh
bao server -dev -dev-root-token-id=root -dev-plugin-dir=./bao/plugins

export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root

bao plugin register \
  -sha256="$(sha256sum bao/plugins/openbao-plugin-secrets-graphql | cut -d' ' -f1)" \
  secret openbao-plugin-secrets-graphql

bao secrets enable -path=gql openbao-plugin-secrets-graphql

bao write gql/config username=admin password=changeme url=http://127.0.0.1:9090/query
bao write gql/role/my-role username=admin password=changeme ttl=300 max_ttl=3600
bao read  gql/creds/my-role
bao lease renew  <lease_id>
bao lease revoke <lease_id>
bao write -f gql/config/rotate-root
```

## Test

Unit tests are hermetic (httptest mock GraphQL server):

```sh
go build ./... && go vet ./... && go test ./...
```

Acceptance tests against a live graphql-server-go:

```sh
BAO_ACC=1 \
GRAPHQL_URL=http://127.0.0.1:9090/query \
GRAPHQL_USERNAME=admin \
GRAPHQL_PASSWORD=changeme \
go test -run TestAcc ./...
```

## Docker

```sh
docker buildx build --platform linux/amd64,linux/arm64 -t openbao-plugin-secrets-graphql .
```

The final stage layers the static plugin binary onto `openbao/openbao`; point `plugin_directory` at `/openbao/plugins`.

## Schema contract

The client sends standard GraphQL-over-HTTP POSTs and expects these operations from the server (camelCase fields; `userId` is a prefixed string like `usr_...`):

```graphql
mutation SignIn($username: String!, $password: String!) {
  signIn(username: $username, password: $password) { userId username token }
}
mutation SignOut { signOut }                       # Authorization: <JWT>
mutation UpdatePassword($password: String!) {      # Authorization: <JWT>
  updatePassword(password: $password)
}
```

## License

MPL-2.0
