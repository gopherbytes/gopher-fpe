package awskeys

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const testSecret = `{
	"current_version": 1,
	"key_map": {
		"1": {
			"encrypted_key": "dGVzdA==",
			"kms_key_id": "test-key"
		}
	}
}`

type fakeSecretsClient struct {
	getCalls atomic.Int32
	delay    time.Duration
	secret   string
}

func (f *fakeSecretsClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.getCalls.Add(1)

	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	return &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(f.secret),
	}, nil
}

func TestConcurrentSecretFetchUsesSingleflight(t *testing.T) {
	ctx := context.Background()

	client := &fakeSecretsClient{
		delay:  50 * time.Millisecond,
		secret: testSecret,
	}

	provider := &Provider{
		secrets:    client,
		secretName: "test-secret",
	}

	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make(chan error, goroutines)
	start := make(chan struct{})

	var badVersion atomic.Bool

	for range goroutines {
		go func() {
			defer wg.Done()

			<-start

			secret, err := provider.fetchSecret(ctx)
			if err != nil {
				errs <- err
				return
			}

			if secret.CurrentVersion != 1 {
				badVersion.Store(true)
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("fetchSecret failed: %v", err)
	}

	if badVersion.Load() {
		t.Fatal("received unexpected current version")
	}

	if got := client.getCalls.Load(); got != 1 {
		t.Fatalf(
			"expected exactly one Secrets Manager call, got %d",
			got,
		)
	}
}
