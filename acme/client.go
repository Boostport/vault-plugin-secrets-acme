package acme

import (
	"context"

	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge/dns01"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/providers/dns"
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
	}

	return client.Certificate.Obtain(request)
}

func setupChallengeProviders(ctx context.Context, logger log.Logger, client *lego.Client, a *account, req *logical.Request) error {
	// DNS-01
	if a.Provider != "" {
		provider, err := dns.NewDNSChallengeProviderByName(a.Provider, a.ProviderConfiguration)
		if err != nil {
			return err
		}

		err = client.Challenge.SetDNS01Provider(
			provider,
			dns01.CondOption(len(a.DNSResolvers) > 0, dns01.AddRecursiveNameservers(a.DNSResolvers)),
			dns01.CondOption(a.IgnoreDNSPropagation, dns01.DisableCompletePropagationRequirement()),
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
