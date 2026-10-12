package fpe

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeKeyProvider struct {
	version uint16
	key     []byte

	versionCalls atomic.Int32
	keyCalls     atomic.Int32

	keyDelay time.Duration
}

func (p *fakeKeyProvider) CurrentVersion(ctx context.Context) (uint16, error) {
	p.versionCalls.Add(1)
	return p.version, nil
}

func (p *fakeKeyProvider) Key(ctx context.Context, version uint16) (Key, error) {
	p.keyCalls.Add(1)

	if p.keyDelay > 0 {
		time.Sleep(p.keyDelay)
	}

	return Key{
		Version: version,
		Bytes:   p.key,
	}, nil
}

func newTestProvider() *fakeKeyProvider {
	return &fakeKeyProvider{
		version: 1,
		key:     []byte("0123456789abcdef"),
	}
}

func TestEncryptDeterministic(t *testing.T) {
	ctx := context.Background()
	provider := newTestProvider()
	service := NewService(provider, nil)

	opts := EncryptOptions{
		Radix: 10,
		Tweak: "customer-id",
	}

	first, err := service.Encrypt(
		ctx,
		[]string{"123456789"},
		opts,
	)
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	second, err := service.Encrypt(
		ctx,
		[]string{"123456789"},
		opts,
	)
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	if first[0] != second[0] {
		t.Fatalf(
			"expected deterministic encryption, got %q and %q",
			first[0],
			second[0],
		)
	}
}

func TestEncryptDifferentTweakProducesDifferentCiphertext(t *testing.T) {
	ctx := context.Background()
	provider := newTestProvider()
	service := NewService(provider, nil)

	first, err := service.Encrypt(
		ctx,
		[]string{"123456789"},
		EncryptOptions{
			Radix: 10,
			Tweak: "customer-id",
		},
	)
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	second, err := service.Encrypt(
		ctx,
		[]string{"123456789"},
		EncryptOptions{
			Radix: 10,
			Tweak: "account-id",
		},
	)
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	if first[0] == second[0] {
		t.Fatalf(
			"expected different tweaks to produce different ciphertext, got %q",
			first[0],
		)
	}
}

func TestEncryptUsesDefaultRadix(t *testing.T) {
	ctx := context.Background()
	provider := newTestProvider()
	service := NewService(provider, nil)

	value := []string{"AbC123xy"}

	withDefault, err := service.Encrypt(
		ctx,
		value,
		EncryptOptions{},
	)
	if err != nil {
		t.Fatalf("encrypt with default radix failed: %v", err)
	}

	withExplicitRadix, err := service.Encrypt(
		ctx,
		value,
		EncryptOptions{
			Radix: DefaultRadix,
		},
	)
	if err != nil {
		t.Fatalf("encrypt with explicit radix failed: %v", err)
	}

	if withDefault[0] != withExplicitRadix[0] {
		t.Fatalf(
			"default radix output %q differs from explicit radix output %q",
			withDefault[0],
			withExplicitRadix[0],
		)
	}
}

func TestMemoryCipherCacheAvoidsRepeatedKeyLookup(t *testing.T) {
	ctx := context.Background()
	provider := newTestProvider()
	service := NewService(provider, nil)

	opts := EncryptOptions{
		Radix: 10,
		Tweak: "customer-id",
	}

	for range 10 {
		_, err := service.Encrypt(
			ctx,
			[]string{"123456789"},
			opts,
		)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
	}

	if got := provider.keyCalls.Load(); got != 1 {
		t.Fatalf(
			"expected key provider to be called once, got %d",
			got,
		)
	}
}

func TestConcurrentEncryptBuildsCipherOnce(t *testing.T) {
	ctx := context.Background()
	provider := newTestProvider()

	// Make Key() slow enough that concurrent callers overlap.
	provider.keyDelay = 50 * time.Millisecond

	service := NewService(provider, nil)

	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make(chan error, goroutines)
	results := make(chan []string, goroutines)

	start := make(chan struct{})

	for range goroutines {
		go func() {
			defer wg.Done()

			<-start

			result, err := service.Encrypt(
				ctx,
				[]string{"123456789"},
				EncryptOptions{
					Radix: 10,
					Tweak: "customer-id",
				},
			)
			if err != nil {
				errs <- err
				return
			}

			results <- result
		}()
	}

	close(start)
	wg.Wait()

	close(errs)
	close(results)

	for err := range errs {
		t.Fatalf("concurrent encrypt failed: %v", err)
	}

	if got := provider.keyCalls.Load(); got != 1 {
		t.Fatalf(
			"expected one Key() call during concurrent cipher build, got %d",
			got,
		)
	}

	var expected string

	for result := range results {
		if len(result) != 1 {
			t.Fatalf(
				"expected one encrypted value, got %d",
				len(result),
			)
		}

		if expected == "" {
			expected = result[0]
			continue
		}

		if result[0] != expected {
			t.Fatalf(
				"expected all concurrent results to match: %q != %q",
				result[0],
				expected,
			)
		}
	}
}
