package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/balzanelli/cert-manager-webhook-njalla/internal/njalla"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
)

// GroupName is the K8s API group
var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&njallaDNSProviderSolver{},
	)
}

// njallaDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type njallaDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// njallaDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type njallaDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *njallaDNSProviderSolver) Name() string {
	return "njalla"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *njallaDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	token, err := c.getSecret(cfg.APIKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get Njalla API token: %v", err)
	}

	client := njalla.NewClient(string(token))

	name, domain := c.getDomainAndEntry(ch)

	record, err := client.GetRecord(name, "TXT", domain)
	if err != nil {
		return fmt.Errorf("unable to check TXT record: %v", err)
	}

	if record != nil {
		if err = client.EditRecord(record.ID, domain, ch.Key); err != nil {
			return fmt.Errorf("unable to change TXT record: %v", err)
		}
	} else {
		if _, err = client.AddRecord(njalla.Record{
			Name:    name,
			Domain:  domain,
			Content: ch.Key,
			TTL:     300,
			Type:    "TXT",
		}); err != nil {
			return fmt.Errorf("unable to create TXT record: %v", err)
		}
	}

	return nil
}

func (c *njallaDNSProviderSolver) getDomainAndEntry(ch *v1alpha1.ChallengeRequest) (string, string) {
	// Both ch.ResolvedZone and ch.ResolvedFQDN end with a dot: '.'
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".")
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	return entry, domain
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *njallaDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	token, err := c.getSecret(cfg.APIKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get Njalla API token: %v", err)
	}

	client := njalla.NewClient(string(token))

	name, domain := c.getDomainAndEntry(ch)

	record, err := client.GetRecord(name, "TXT", domain)
	if err != nil {
		return fmt.Errorf("unable to check TXT record: %v", err)
	}

	if record != nil {
		if err = client.RemoveRecord(record.ID, domain); err != nil {
			return fmt.Errorf("unable to remove TXT record: %v", err)
		}
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *njallaDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (njallaDNSProviderConfig, error) {
	cfg := njallaDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *njallaDNSProviderSolver) getSecret(selector cmmeta.SecretKeySelector, namespace string) ([]byte, error) {
	secretName := selector.LocalObjectReference.Name

	secret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret `%s`; %v", secretName, err)
	}

	b, ok := secret.Data[selector.Key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret \"%s/%s\"", selector.Key,
			selector.LocalObjectReference.Name, namespace)
	}

	return b, nil
}
