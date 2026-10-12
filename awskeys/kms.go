package awskeys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const kmsTimeout = 3 * time.Second

var encryptionContext = map[string]string{
	"service": "fpe",
}

func (p *Provider) decryptKey(ctx context.Context, entry keyEntry) ([]byte, error) {
	encryptedKey, err := base64.StdEncoding.DecodeString(entry.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted key: %w", err)
	}

	input := &kms.DecryptInput{
		CiphertextBlob:    encryptedKey,
		EncryptionContext: encryptionContext,
	}

	if entry.KMSKeyID != "" {
		input.KeyId = aws.String(entry.KMSKeyID)
	}

	decryptCtx, cancel := context.WithTimeout(ctx, kmsTimeout)
	defer cancel()

	out, err := p.kms.Decrypt(decryptCtx, input)
	if err != nil {

		if _, ok := errors.AsType[*types.InvalidCiphertextException](err); ok {
			p.invalidateSecretCache()
		}

		return nil, fmt.Errorf("kms decrypt: %w", err)
	}
	if len(out.Plaintext) == 0 {
		return nil, fmt.Errorf("kms returned empty plaintext key")
	}

	return out.Plaintext, nil
}
