package awskeys

import (
	"context"
	"fmt"
	"sync"
	"time"

	fpe "github.com/gopherbytes/gopher-fpe"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"golang.org/x/sync/singleflight"
)

type Provider struct {
	kms        *kms.Client
	secrets    SecretsClient
	secretName string
	cache      SecretCache

	secretMu      sync.RWMutex
	cachedSecret  *secretDocument
	secretExpires time.Time

	secretGroup singleflight.Group
}

type SecretCache interface {
	GetSecret(ctx context.Context) (string, bool)
	SetSecret(secret string)
	InvalidateSecret()
}

type SecretsClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

var _ fpe.KeyProvider = (*Provider)(nil)

func NewProvider(kmsClient *kms.Client, secretsClient SecretsClient, secretName string, cache SecretCache) (*Provider, error) {
	if kmsClient == nil {
		return nil, fmt.Errorf("kms client is required")
	}

	if secretsClient == nil {
		return nil, fmt.Errorf("secrets manager client is required")
	}

	if secretName == "" {
		return nil, fmt.Errorf("secret name is required")
	}

	return &Provider{
		kms:        kmsClient,
		secrets:    secretsClient,
		secretName: secretName,
		cache:      cache,
	}, nil
}

func (p *Provider) CurrentVersion(ctx context.Context) (uint16, error) {
	secret, err := p.fetchSecret(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetch current secret: %w", err)
	}

	return uint16(secret.CurrentVersion), nil
}

func (p *Provider) Key(ctx context.Context, version uint16) (fpe.Key, error) {

	secret, err := p.fetchSecret(ctx)
	if err != nil {
		return fpe.Key{}, fmt.Errorf(
			"fetch secret for key version %d: %w",
			version,
			err,
		)
	}

	entry, ok := secret.KeyMap[fmt.Sprintf("%d", version)]
	if !ok {
		p.invalidateSecretCache()

		return fpe.Key{}, fmt.Errorf(
			"key version %d not found in secret",
			version,
		)
	}

	keyBytes, err := p.decryptKey(ctx, entry)
	if err != nil {
		return fpe.Key{}, fmt.Errorf(
			"decrypt key version %d: %w",
			version,
			err,
		)
	}

	return fpe.Key{
		Version: version,
		Bytes:   keyBytes,
	}, nil
}
