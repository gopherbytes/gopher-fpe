package awskeys

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const secretTTL = 10 * time.Minute

type keyEntry struct {
	EncryptedKey string `json:"encrypted_key"`
	KMSKeyID     string `json:"kms_key_id"`
}

type secretDocument struct {
	CurrentVersion int                 `json:"current_version"`
	KeyMap         map[string]keyEntry `json:"key_map"`
}

func (p *Provider) fetchSecret(ctx context.Context) (*secretDocument, error) {
	p.secretMu.RLock()

	if p.cachedSecret != nil && time.Now().Before(p.secretExpires) {
		secret := p.cachedSecret
		p.secretMu.RUnlock()
		return secret, nil
	}

	p.secretMu.RUnlock()

	result, err, _ := p.secretGroup.Do("current-secret", func() (any, error) {
		p.secretMu.RLock()

		if p.cachedSecret != nil && time.Now().Before(p.secretExpires) {
			secret := p.cachedSecret
			p.secretMu.RUnlock()
			return secret, nil
		}

		p.secretMu.RUnlock()

		if p.cache != nil {
			if rawSecret, ok := p.cache.GetSecret(ctx); ok {

				var secret secretDocument

				if err := json.Unmarshal([]byte(rawSecret), &secret); err == nil {
					if err := validateSecretDocument(&secret); err == nil {
						p.storeSecretInMemory(&secret)

						return &secret, nil
					}
				}
			}
		}

		out, err := p.secrets.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(p.secretName),
		})
		if err != nil {
			return nil, fmt.Errorf("get secret value: %w", err)
		}

		if out.SecretString == nil {
			return nil, fmt.Errorf("secret %q has no SecretString", p.secretName)
		}

		var secret secretDocument

		if err := json.Unmarshal([]byte(*out.SecretString), &secret); err != nil {
			return nil, fmt.Errorf("decode secret document: %w", err)
		}

		if err := validateSecretDocument(&secret); err != nil {
			return nil, fmt.Errorf("invalid secret document: %w", err)
		}

		p.storeSecretInMemory(&secret)

		if p.cache != nil {
			p.cache.SetSecret(*out.SecretString)
		}

		return &secret, nil
	},
	)
	if err != nil {
		return nil, err
	}

	secret, ok := result.(*secretDocument)
	if !ok {
		return nil, fmt.Errorf(
			"unexpected secret cache result type",
		)
	}

	return secret, nil
}

func (p *Provider) storeSecretInMemory(secret *secretDocument) {
	p.secretMu.Lock()
	defer p.secretMu.Unlock()

	p.cachedSecret = secret
	p.secretExpires = time.Now().Add(secretTTL)
}

func (p *Provider) invalidateSecretCache() {
	p.secretMu.Lock()
	p.cachedSecret = nil
	p.secretExpires = time.Time{}
	p.secretMu.Unlock()

	if p.cache != nil {
		p.cache.InvalidateSecret()
	}
}

func validateSecretDocument(secret *secretDocument) error {
	if secret == nil {
		return fmt.Errorf("secret document is nil")
	}

	if secret.KeyMap == nil {
		return fmt.Errorf("secret has no key_map")
	}

	if secret.CurrentVersion < 0 || secret.CurrentVersion > 65535 {
		return fmt.Errorf("invalid current key version %d", secret.CurrentVersion)
	}

	return nil
}
