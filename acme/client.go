package acme

import (
	"context"
	"fmt"
	"os"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

func getCertFromACMEProvider(ctx context.Context, logger log.Logger, req *logical.Request, a *account, names []string) (*certificate.Resource, error) {
	client, err := a.getClient()
	if err != nil {
		return nil, err
	}

	err = setupChallengeProviders(ctx, logger, client, a, req)
	if err != nil {
		return nil, err
	}

	request := certificate.ObtainRequest{
		Domains: names,
		Bundle:  true,
		KeyType: certcrypto.KeyType(a.KeyType),
	}

	return client.Certificate.Obtain(ctx, request)
}

func setupChallengeProviders(ctx context.Context, logger log.Logger, client *lego.Client, a *account, req *logical.Request) error {
	// DNS-01
	if a.Provider != "" {
		// Set the provider configuration as environment variables, so that they get picked up when the challenge provider
		// is created
		for key, value := range a.ProviderConfiguration {
			err := os.Setenv(key, value)
			if err != nil {
				return fmt.Errorf(`error setting key "%s" for DNS provider configuation`, key)
			}
		}

		provider, err := dns.NewDNSChallengeProviderByName(a.Provider)
		if err != nil {
			return err
		}

		if len(a.DNSResolvers) > 0 {
			opts := &dns01.Options{RecursiveNameservers: a.DNSResolvers}
			dns01.SetDefaultClient(dns01.NewClient(opts))
		}

		err = client.Challenge.SetDNS01Provider(
			provider,
			dns01.CondOptions(a.IgnoreDNSPropagation, dns01.DisableAuthoritativeNssPropagationRequirement()),
		)
		if err != nil {
			return err
		}
	}

	// HTTP-01
	if a.EnableHTTP01 {
		provider := newVaultHTTP01Provider(ctx, logger, req)
		err := client.Challenge.SetHTTP01Provider(provider)
		if err != nil {
			return err
		}
	}

	// TLS-ALPN-01
	if a.EnableTLSALPN01 {
		provider := newVaultTLSALPN01Provider(ctx, logger, req)
		err := client.Challenge.SetTLSALPN01Provider(provider)
		if err != nil {
			return err
		}
	}

	return nil
}
