package fpe

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type integrationKeyProvider struct {
	version uint16
	key     []byte

	versionCalls atomic.Int32
	keyCalls     atomic.Int32
}

func (p *integrationKeyProvider) CurrentVersion(
	ctx context.Context,
) (uint16, error) {
	p.versionCalls.Add(1)
	return p.version, nil
}

func (p *integrationKeyProvider) Key(
	ctx context.Context,
	version uint16,
) (Key, error) {
	p.keyCalls.Add(1)

	return Key{
		Version: version,
		Bytes:   p.key,
	}, nil
}

type integrationCipherCache struct {
	mu sync.RWMutex

	ciphers map[string]*Cipher

	getCalls atomic.Int32
	setCalls atomic.Int32
}

func newIntegrationCipherCache() *integrationCipherCache {
	return &integrationCipherCache{
		ciphers: make(map[string]*Cipher),
	}
}

func (c *integrationCipherCache) GetCipher(
	ctx context.Context,
	cacheKey string,
	radix int,
	maxTweakLength int,
) (*Cipher, bool) {
	c.getCalls.Add(1)

	c.mu.RLock()
	cipher, ok := c.ciphers[cacheKey]
	c.mu.RUnlock()

	return cipher, ok
}

func (c *integrationCipherCache) SetCipher(
	cacheKey string,
	key []byte,
	tweak []byte,
) {
	c.setCalls.Add(1)

	// The service currently does not provide radix here,
	// so for this integration fake we do not reconstruct
	// and store the cipher.
	//
	// The real Redis cache serialization/reconstruction
	// behavior is already covered by cache/redis_test.go.
}

func TestServiceFullFlowColdThenMemoryHit(t *testing.T) {
	ctx := context.Background()

	provider := &integrationKeyProvider{
		version: 1,
		key:     []byte("0123456789abcdef"),
	}

	cache := newIntegrationCipherCache()

	service := NewService(
		provider,
		cache,
	)

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
		t.Fatalf("first Encrypt failed: %v", err)
	}

	if len(first) != 1 || first[0] == "" {
		t.Fatal("expected first encryption to return ciphertext")
	}

	if got := provider.keyCalls.Load(); got != 1 {
		t.Fatalf(
			"expected one key lookup after cold encryption, got %d",
			got,
		)
	}

	if got := cache.getCalls.Load(); got != 1 {
		t.Fatalf(
			"expected one distributed cache lookup after cold encryption, got %d",
			got,
		)
	}

	if got := cache.setCalls.Load(); got != 1 {
		t.Fatalf(
			"expected cipher to be written to distributed cache once, got %d",
			got,
		)
	}

	second, err := service.Encrypt(
		ctx,
		[]string{"123456789"},
		opts,
	)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}

	if len(second) != 1 || second[0] == "" {
		t.Fatal("expected second encryption to return ciphertext")
	}

	if second[0] != first[0] {
		t.Fatalf(
			"expected deterministic ciphertext, got %q and %q",
			first[0],
			second[0],
		)
	}

	if got := provider.keyCalls.Load(); got != 1 {
		t.Fatalf(
			"expected second encryption to reuse in-memory cipher and avoid key lookup; got %d key calls",
			got,
		)
	}

	if got := cache.getCalls.Load(); got != 1 {
		t.Fatalf(
			"expected second encryption to avoid distributed cache; got %d cache lookups",
			got,
		)
	}

	if got := cache.setCalls.Load(); got != 1 {
		t.Fatalf(
			"expected distributed cache to be written once, got %d writes",
			got,
		)
	}
}

func TestServiceUsesDistributedCipherCacheBeforeKeyProvider(t *testing.T) {
	ctx := context.Background()

	const (
		version = uint16(1)
		radix   = 10
		tweak   = "customer-id"
	)

	provider := &integrationKeyProvider{
		version: version,
		key:     []byte("0123456789abcdef"),
	}

	cache := newIntegrationCipherCache()

	binaryTweak := buildTweak(
		version,
		tweak,
	)

	cachedCipher, err := NewCipher(
		radix,
		tweakLength,
		provider.key,
		binaryTweak,
	)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	cacheKey := "1-customer-id-10"

	cache.mu.Lock()
	cache.ciphers[cacheKey] = cachedCipher
	cache.mu.Unlock()

	service := NewService(
		provider,
		cache,
	)

	result, err := service.Encrypt(
		ctx,
		[]string{"123456789"},
		EncryptOptions{
			Radix: radix,
			Tweak: tweak,
		},
	)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(result) != 1 || result[0] == "" {
		t.Fatal("expected ciphertext")
	}

	if got := cache.getCalls.Load(); got != 1 {
		t.Fatalf(
			"expected one distributed cache lookup, got %d",
			got,
		)
	}

	if got := provider.keyCalls.Load(); got != 0 {
		t.Fatalf(
			"expected distributed cache hit to avoid key/KMS lookup, got %d key calls",
			got,
		)
	}

	if got := cache.setCalls.Load(); got != 0 {
		t.Fatalf(
			"expected cache hit not to rewrite distributed cache, got %d writes",
			got,
		)
	}
}

func TestServiceDifferentTweaksCreateDifferentCacheEntries(t *testing.T) {
	ctx := context.Background()

	provider := &integrationKeyProvider{
		version: 1,
		key:     []byte("0123456789abcdef"),
	}

	cache := newIntegrationCipherCache()

	service := NewService(
		provider,
		cache,
	)

	first, err := service.Encrypt(
		ctx,
		[]string{"123456789"},
		EncryptOptions{
			Radix: 10,
			Tweak: "customer",
		},
	)
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	second, err := service.Encrypt(
		ctx,
		[]string{"123456789"},
		EncryptOptions{
			Radix: 10,
			Tweak: "account",
		},
	)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}

	if len(first) != 1 || len(second) != 1 {
		t.Fatal("expected one ciphertext from each encryption")
	}

	if first[0] == second[0] {
		t.Fatalf(
			"expected different tweaks to produce different ciphertext, got %q",
			first[0],
		)
	}

	if got := provider.keyCalls.Load(); got != 2 {
		t.Fatalf(
			"expected separate cipher builds for two tweaks, got %d key calls",
			got,
		)
	}

	if got := cache.getCalls.Load(); got != 2 {
		t.Fatalf(
			"expected two distributed cache lookups, got %d",
			got,
		)
	}

	if got := cache.setCalls.Load(); got != 2 {
		t.Fatalf(
			"expected two distributed cache writes, got %d",
			got,
		)
	}
}

func TestServiceDifferentRadixCreatesDifferentCacheEntries(t *testing.T) {
	ctx := context.Background()

	provider := &integrationKeyProvider{
		version: 1,
		key:     []byte("0123456789abcdef"),
	}

	cache := newIntegrationCipherCache()

	service := NewService(
		provider,
		cache,
	)

	first, err := service.Encrypt(
		ctx,
		[]string{"123456"},
		EncryptOptions{
			Radix: 10,
		},
	)
	if err != nil {
		t.Fatalf("radix-10 Encrypt failed: %v", err)
	}

	second, err := service.Encrypt(
		ctx,
		[]string{"abc123"},
		EncryptOptions{
			Radix: 36,
		},
	)
	if err != nil {
		t.Fatalf("radix-36 Encrypt failed: %v", err)
	}

	if len(first) != 1 || first[0] == "" {
		t.Fatal("expected radix-10 ciphertext")
	}

	if len(second) != 1 || second[0] == "" {
		t.Fatal("expected radix-36 ciphertext")
	}

	if got := provider.keyCalls.Load(); got != 2 {
		t.Fatalf(
			"expected separate cipher builds for different radix values, got %d key calls",
			got,
		)
	}
}

func TestServiceColdBurstPerformsOneKeyLookup(t *testing.T) {
	ctx := context.Background()

	provider := &integrationKeyProvider{
		version: 1,
		key:     []byte("0123456789abcdef"),
	}

	cache := newIntegrationCipherCache()

	service := NewService(
		provider,
		cache,
	)

	const goroutines = 100

	start := make(chan struct{})
	errs := make(chan error, goroutines)
	results := make(chan []string, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)

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
		t.Fatalf("Encrypt failed during cold burst: %v", err)
	}

	var expected string

	for result := range results {
		if len(result) != 1 {
			t.Fatalf(
				"expected one ciphertext, got %d",
				len(result),
			)
		}

		if expected == "" {
			expected = result[0]
			continue
		}

		if result[0] != expected {
			t.Fatalf(
				"expected all ciphertext values to match, got %q and %q",
				expected,
				result[0],
			)
		}
	}

	if got := provider.keyCalls.Load(); got != 1 {
		t.Fatalf(
			"expected one key lookup during cold burst, got %d",
			got,
		)
	}

	if got := cache.setCalls.Load(); got != 1 {
		t.Fatalf(
			"expected one distributed-cache write during cold burst, got %d",
			got,
		)
	}
}

func TestPrewarmPopulatesMemoryCipherCache(t *testing.T) {
	ctx := context.Background()

	provider := &integrationKeyProvider{
		version: 1,
		key:     []byte("0123456789abcdef"),
	}

	cache := newIntegrationCipherCache()

	service := NewService(
		provider,
		cache,
	)

	if err := service.Prewarm(ctx); err != nil {
		t.Fatalf("Prewarm failed: %v", err)
	}

	keyCallsAfterPrewarm := provider.keyCalls.Load()
	cacheGetsAfterPrewarm := cache.getCalls.Load()
	cacheSetsAfterPrewarm := cache.setCalls.Load()

	if keyCallsAfterPrewarm != 1 {
		t.Fatalf(
			"expected prewarm to retrieve key once, got %d",
			keyCallsAfterPrewarm,
		)
	}

	_, err := service.Encrypt(
		ctx,
		[]string{"AbC123"},
		EncryptOptions{},
	)
	if err != nil {
		t.Fatalf("Encrypt after prewarm failed: %v", err)
	}

	if got := provider.keyCalls.Load(); got != keyCallsAfterPrewarm {
		t.Fatalf(
			"expected encryption after prewarm to reuse memory cipher; key calls increased from %d to %d",
			keyCallsAfterPrewarm,
			got,
		)
	}

	if got := cache.getCalls.Load(); got != cacheGetsAfterPrewarm {
		t.Fatalf(
			"expected encryption after prewarm to avoid distributed-cache lookup; calls increased from %d to %d",
			cacheGetsAfterPrewarm,
			got,
		)
	}

	if got := cache.setCalls.Load(); got != cacheSetsAfterPrewarm {
		t.Fatalf(
			"expected encryption after prewarm not to rewrite distributed cache; writes increased from %d to %d",
			cacheSetsAfterPrewarm,
			got,
		)
	}
}

func TestServiceMemoryCipherExpiresAndRebuilds(t *testing.T) {
	ctx := context.Background()

	provider := &integrationKeyProvider{
		version: 1,
		key:     []byte("0123456789abcdef"),
	}

	cache := newIntegrationCipherCache()

	service := NewService(
		provider,
		cache,
	)

	opts := EncryptOptions{
		Radix: 10,
		Tweak: "customer-id",
	}

	_, err := service.Encrypt(
		ctx,
		[]string{"123456789"},
		opts,
	)
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	cacheKey := "1-customer-id-10"

	value, ok := service.cipherCache.Load(cacheKey)
	if !ok {
		t.Fatal("expected cipher to exist in memory cache")
	}

	cached, ok := value.(*cachedCipher)
	if !ok {
		t.Fatalf(
			"expected *cachedCipher, got %T",
			value,
		)
	}

	cached.expires = time.Now().Add(-time.Second)

	_, err = service.Encrypt(
		ctx,
		[]string{"123456789"},
		opts,
	)
	if err != nil {
		t.Fatalf("Encrypt after memory expiration failed: %v", err)
	}

	if got := cache.getCalls.Load(); got != 2 {
		t.Fatalf(
			"expected distributed cache to be checked again after L1 expiration, got %d checks",
			got,
		)
	}

	if got := provider.keyCalls.Load(); got != 2 {
		t.Fatalf(
			"expected key to be retrieved again because fake distributed cache misses, got %d key calls",
			got,
		)
	}
}
