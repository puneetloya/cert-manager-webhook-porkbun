package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/bcspragu/cert-manager-webhook-porkbun/porkbun"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

func main() {
	// Configure log level from environment (default: info)
	logLevel := slog.LevelInfo
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		switch strings.ToLower(level) {
		case "debug":
			logLevel = slog.LevelDebug
		case "info":
			logLevel = slog.LevelInfo
		case "warn", "warning":
			logLevel = slog.LevelWarn
		case "error":
			logLevel = slog.LevelError
		}
	}

	// Initialize structured logger with JSON output for production
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	slog.Info("starting cert-manager-webhook-porkbun", "logLevel", logLevel.String())

	if err := run(); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	groupName := os.Getenv("GROUP_NAME")
	if groupName == "" {
		return errors.New("GROUP_NAME must be specified")
	}

	slog.Info("webhook configuration loaded", "groupName", groupName)

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(groupName, &porkbunDNSProviderSolver{})

	return nil
}

// porkbunDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type porkbunDNSProviderSolver struct {
	porkbun *porkbun.Client
	client  *kubernetes.Clientset
}

// porkbunDNSProviderConfig is a structure that is used to decode into when
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
type porkbunDNSProviderConfig struct {
	APIKey       corev1.SecretKeySelector `json:"apiKey"`
	SecretAPIKey corev1.SecretKeySelector `json:"secretApiKey"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (p *porkbunDNSProviderSolver) Name() string {
	return "porkbun"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (p *porkbunDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()

	slog.Info("Present called - attempting to create DNS TXT record",
		"resolvedZone", ch.ResolvedZone,
		"resolvedFQDN", ch.ResolvedFQDN,
		"resourceNamespace", ch.ResourceNamespace,
		"allowAmbientCredentials", ch.AllowAmbientCredentials)

	pbClient, err := p.newPorkbunClient(ch)
	if err != nil {
		slog.Error("failed to initialize Porkbun client",
			"error", err,
			"resourceNamespace", ch.ResourceNamespace)
		return fmt.Errorf("failed to init Porkbun client: %w", err)
	}

	domain := util.UnFqdn(ch.ResolvedZone)
	subDomain := getSubDomain(domain, ch.ResolvedFQDN)
	target := ch.Key

	slog.Info("parsed challenge request",
		"domain", domain,
		"subdomain", subDomain,
		"targetKeyLength", len(target))

	recordsResp, err := pbClient.RetrieveDNSRecordsByDomainSubdomainType(ctx, domain, subDomain, "TXT")
	if err != nil {
		slog.Error("failed to retrieve DNS records from Porkbun",
			"domain", domain,
			"subdomain", subDomain,
			"error", err)
		return fmt.Errorf("failed to get DNS records: %w", err)
	}

	slog.Info("retrieved existing DNS records",
		"domain", domain,
		"subdomain", subDomain,
		"status", recordsResp.Status,
		"message", recordsResp.Message,
		"recordCount", len(recordsResp.Records))

	if recordsResp.Status != "SUCCESS" {
		slog.Error("Porkbun API returned non-success status when retrieving records",
			"status", recordsResp.Status,
			"message", recordsResp.Message,
			"domain", domain,
			"subdomain", subDomain)
		return fmt.Errorf("invalid status %q loading DNS records: %s", recordsResp.Status, recordsResp.Message)
	}

	for _, rec := range recordsResp.Records {
		if rec.Content != target {
			continue
		}
		// The record already exists, just return.
		slog.Info("DNS TXT record already exists, skipping creation",
			"subdomain", subDomain,
			"domain", domain,
			"recordId", rec.ID)
		return nil
	}

	slog.Info("no existing TXT record found, creating new record",
		"domain", domain,
		"subdomain", subDomain)

	createResp, err := pbClient.CreateDNSRecord(ctx, domain, &porkbun.NewDNSRecord{
		Name:    subDomain,
		Type:    "TXT",
		Content: target,
		TTL:     "60",
	})
	if err != nil {
		slog.Error("failed to create DNS record",
			"domain", domain,
			"subdomain", subDomain,
			"error", err)
		return fmt.Errorf("failed to create DNS record: %w", err)
	}

	slog.Info("Porkbun API create record response",
		"status", createResp.Status,
		"recordId", createResp.ID)

	if createResp.Status != "SUCCESS" {
		slog.Error("Porkbun API returned non-success status when creating record",
			"status", createResp.Status,
			"domain", domain,
			"subdomain", subDomain)
		return fmt.Errorf("invalid status %q creating DNS record", createResp.Status)
	}

	slog.Info("DNS TXT record created successfully",
		"subdomain", subDomain,
		"domain", domain,
		"recordId", createResp.ID)

	return nil
}

func getSubDomain(domain, fqdn string) string {
	if idx := strings.Index(fqdn, "."+domain); idx != -1 {
		return fqdn[:idx]
	}

	return util.UnFqdn(fqdn)
}

func (p *porkbunDNSProviderSolver) newPorkbunClient(ch *v1alpha1.ChallengeRequest) (*porkbun.Client, error) {
	ctx := context.Background()

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse webhook config: %w", err)
	}

	if !ch.AllowAmbientCredentials {
		if err := p.validate(&cfg); err != nil {
			return nil, fmt.Errorf("invalid config: %w", err)
		}
	}

	apiKey, err := p.secret(ctx, cfg.APIKey, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	secretAPIKey, err := p.secret(ctx, cfg.SecretAPIKey, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	// Validate that credentials are present before making API calls
	if apiKey == "" {
		slog.Error("porkbun API key is empty - cannot authenticate with Porkbun API",
			"configuredSecretName", cfg.APIKey.Name,
			"configuredSecretKey", cfg.APIKey.Key,
			"namespace", ch.ResourceNamespace)
		return nil, errors.New("porkbun API key is empty: check that the secret exists and contains the correct key")
	}

	if secretAPIKey == "" {
		slog.Error("porkbun secret API key is empty - cannot authenticate with Porkbun API",
			"configuredSecretName", cfg.SecretAPIKey.Name,
			"configuredSecretKey", cfg.SecretAPIKey.Key,
			"namespace", ch.ResourceNamespace)
		return nil, errors.New("porkbun secret API key is empty: check that the secret exists and contains the correct key")
	}

	slog.Info("porkbun client credentials loaded successfully",
		"apiKeyLength", len(apiKey),
		"secretApiKeyLength", len(secretAPIKey),
		"namespace", ch.ResourceNamespace)

	return porkbun.New(secretAPIKey, apiKey), nil
}

func (p *porkbunDNSProviderSolver) secret(ctx context.Context, ref corev1.SecretKeySelector, namespace string) (string, error) {
	if ref.Name == "" {
		slog.Warn("secret reference name is empty, no credential will be loaded",
			"namespace", namespace,
			"key", ref.Key)
		return "", nil
	}

	slog.Debug("loading secret",
		"secretName", ref.Name,
		"secretKey", ref.Key,
		"namespace", namespace)

	secret, err := p.client.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		slog.Error("failed to load secret from kubernetes",
			"secretName", ref.Name,
			"namespace", namespace,
			"error", err)
		return "", fmt.Errorf("failed to load secret: %w", err)
	}

	bytes, ok := secret.Data[ref.Key]
	if !ok {
		slog.Error("key not found in secret",
			"key", ref.Key,
			"secretName", ref.Name,
			"namespace", namespace,
			"availableKeys", getSecretKeys(secret.Data))
		return "", fmt.Errorf("key not found %q in secret '%s/%s'", ref.Key, namespace, ref.Name)
	}

	slog.Debug("secret loaded successfully",
		"secretName", ref.Name,
		"secretKey", ref.Key,
		"namespace", namespace,
		"valueLength", len(bytes))

	return string(bytes), nil
}

func (p *porkbunDNSProviderSolver) validate(cfg *porkbunDNSProviderConfig) error {
	if cfg.APIKey.Name == "" {
		return errors.New("no API key given in porkbun webhook config")
	}

	if cfg.SecretAPIKey.Name == "" {
		return errors.New("no secret API key given in porkbun webhook config")
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (p *porkbunDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()

	pbClient, err := p.newPorkbunClient(ch)
	if err != nil {
		return fmt.Errorf("failed to init Porkbun client: %w", err)
	}

	domain := util.UnFqdn(ch.ResolvedZone)
	subDomain := getSubDomain(domain, ch.ResolvedFQDN)
	target := ch.Key

	recordsResp, err := pbClient.RetrieveDNSRecordsByDomainSubdomainType(ctx, domain, subDomain, "TXT")
	if err != nil {
		return fmt.Errorf("failed to load existing records: %w", err)
	}
	if recordsResp.Status != "SUCCESS" {
		return fmt.Errorf("invalid status %q loading DNS records", recordsResp.Status)
	}

	for _, rec := range recordsResp.Records {
		if rec.Content != target {
			continue
		}
		deleteResp, err := pbClient.DeleteDNSRecordByDomainID(ctx, domain, rec.ID)
		if err != nil {
			return fmt.Errorf("failed to delete DNS record: %w", err)
		}
		if deleteResp.Status != "SUCCESS" {
			return fmt.Errorf("invalid status %q deleting DNS record %q", recordsResp.Status, rec.ID)
		}

		slog.Info("DNS TXT record deleted successfully",
			"subdomain", subDomain,
			"domain", domain,
			"recordId", rec.ID)
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
func (c *porkbunDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	slog.Info("initializing porkbun DNS provider solver")

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		slog.Error("failed to create kubernetes client", "error", err)
		return err
	}

	c.client = cl

	slog.Info("porkbun DNS provider solver initialized successfully")
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (porkbunDNSProviderConfig, error) {
	cfg := porkbunDNSProviderConfig{}

	// Handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// getSecretKeys returns the keys available in a secret's data map
func getSecretKeys(data map[string][]byte) []string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	return keys
}
