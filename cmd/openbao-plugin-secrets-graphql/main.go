package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	graphql "github.com/markchristopherwest/openbao-plugin-secrets-graphql"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

// main wires the backend into OpenBao's plugin host. OpenBao's api/v2
// keeps the Vault-era names (PluginAPIClientMeta, VaultPluginTLSProvider)
// for compatibility, so the bootstrap is structurally identical to a
// Vault plugin -- only the import paths change.
func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	// ServeMultiplex lets one plugin process back multiple mounts.
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: graphql.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	logger := hclog.New(&hclog.LoggerOptions{})
	logger.Error("plugin shutting down", "error", err)
	os.Exit(1)
}
