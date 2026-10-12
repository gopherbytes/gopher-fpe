//go:build !noredis

package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	fpe "github.com/gopherbytes/gopher-fpe"
	"github.com/redis/go-redis/v9"
)

type fakeRedisClient struct {
	mu     sync.RWMutex
	values map[string]string
}

func newFakeRedisClient() *fakeRedisClient {
	return &fakeRedisClient{
		values: make(map[string]string),
	}
}

func (f *fakeRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)

	f.mu.RLock()
	value, ok := f.values[key]
	f.mu.RUnlock()

	if !ok {
		cmd.SetErr(redis.Nil)
		return cmd
	}

	cmd.SetVal(value)
	return cmd
}

func (f *fakeRedisClient) Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)

	var stringValue string

	switch v := value.(type) {
	case string:
		stringValue = v
	case []byte:
		stringValue = string(v)
	default:
		cmd.SetErr(fmt.Errorf("unsupported value type %T", value))
		return cmd
	}

	f.mu.Lock()
	f.values[key] = stringValue
	f.mu.Unlock()

	cmd.SetVal("OK")
	return cmd
}

func (f *fakeRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)

	var deleted int64

	f.mu.Lock()

	for _, key := range keys {
		if _, ok := f.values[key]; ok {
			delete(f.values, key)
			deleted++
		}
	}

	f.mu.Unlock()

	cmd.SetVal(deleted)
	return cmd
}

func (f *fakeRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("PONG")
	return cmd
}

func newTestRedis() (*Redis, *fakeRedisClient) {
	client := newFakeRedisClient()

	cache := &Redis{
		client:    client,
		available: true,
	}

	return cache, client
}

func TestSecretCacheRoundTrip(t *testing.T) {
	cache, _ := newTestRedis()

	secret := `{
		"current_version": 1,
		"key_map": {
			"1": {
				"encrypted_key": "abc",
				"kms_key_id": "key-1"
			}
		}
	}`

	cache.SetSecret(secret)

	// SetSecret currently writes asynchronously.
	// Give the goroutine a short opportunity to complete.
	deadline := time.Now().Add(time.Second)

	for {
		got, ok := cache.GetSecret(context.Background())
		if ok {
			if got != secret {
				t.Fatalf(
					"expected secret %q, got %q",
					secret,
					got,
				)
			}
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("secret was not written to cache")
		}

		time.Sleep(time.Millisecond)
	}
}

func TestInvalidateSecret(t *testing.T) {
	cache, client := newTestRedis()

	client.mu.Lock()
	client.values[secretRedisKey] = `{"current_version":1}`
	client.mu.Unlock()

	cache.InvalidateSecret()

	client.mu.RLock()
	_, ok := client.values[secretRedisKey]
	client.mu.RUnlock()

	if ok {
		t.Fatal("expected secret cache entry to be deleted")
	}
}

func TestCipherCacheRoundTrip(t *testing.T) {
	cache, _ := newTestRedis()

	const cacheKey = "1-customer-id-10"

	key := []byte("0123456789abcdef")
	tweak := make([]byte, 10)

	cache.SetCipher(
		cacheKey,
		key,
		tweak,
	)

	deadline := time.Now().Add(time.Second)

	var cipher *fpe.Cipher

	for {
		var ok bool

		cipher, ok = cache.GetCipher(
			context.Background(),
			cacheKey,
			10,
			10,
		)

		if ok {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("cipher was not written to Redis cache")
		}

		time.Sleep(time.Millisecond)
	}

	result, err := cipher.Encrypt("123456789")
	if err != nil {
		t.Fatalf("encrypt using reconstructed cipher: %v", err)
	}

	if result == "" {
		t.Fatal("expected non-empty ciphertext")
	}
}

func TestGetSecretMiss(t *testing.T) {
	cache, _ := newTestRedis()

	_, ok := cache.GetSecret(context.Background())
	if ok {
		t.Fatal("expected secret cache miss")
	}
}

func TestGetCipherMiss(t *testing.T) {
	cache, _ := newTestRedis()

	_, ok := cache.GetCipher(
		context.Background(),
		"missing",
		10,
		10,
	)

	if ok {
		t.Fatal("expected cipher cache miss")
	}
}
