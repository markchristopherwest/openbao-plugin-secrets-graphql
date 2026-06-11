module github.com/markchristopherwest/openbao-plugin-secrets-graphql

go 1.23

// OpenBao forked the Vault SDK at the MPL boundary; the import paths are
// github.com/openbao/openbao/{api,sdk}/v2 but the framework/logical surface
// is API-compatible with hashicorp/vault/sdk. No network in this sandbox:
// run `go mod tidy` locally to resolve exact versions and populate go.sum.
require (
	github.com/hashicorp/go-hclog v1.6.3
	github.com/openbao/openbao/api/v2 v2.2.0
	github.com/openbao/openbao/sdk/v2 v2.2.0
)
