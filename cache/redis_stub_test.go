//go:build noredis

package cache

import (
	"context"
	"testing"
)

func TestNoRedisIsUnavailable(t *testing.T) {
	cache := NewRedis("ignored")

	if cache.Available() {
		t.Fatal("expected noredis cache to be unavailable")
	}
}

func TestNoRedisEndpointIsEmpty(t *testing.T) {
	cache := NewRedis("ignored")

	if got := cache.Endpoint(); got != "" {
		t.Fatalf("expected empty endpoint, got %q", got)
	}
}

func TestNoRedisInitDoesNothing(t *testing.T) {
	ctx := context.Background()

	cache := NewRedis("ignored")

	cache.Init(ctx)

	if cache.Available() {
		t.Fatal("expected cache to remain unavailable after Init")
	}
}

func TestNoRedisSecretAlwaysMisses(t *testing.T) {
	ctx := context.Background()

	cache := NewRedis("ignored")

	cache.SetSecret(`{"current_version":1}`)

	secret, ok := cache.GetSecret(ctx)
	if ok {
		t.Fatal("expected secret cache miss")
	}

	if secret != "" {
		t.Fatalf("expected empty secret, got %q", secret)
	}
}

func TestNoRedisCipherAlwaysMisses(t *testing.T) {
	ctx := context.Background()

	cache := NewRedis("ignored")

	cache.SetCipher(
		"1-test-10",
		[]byte("0123456789abcdef"),
		make([]byte, 10),
	)

	cipher, ok := cache.GetCipher(
		ctx,
		"1-test-10",
		10,
		10,
	)

	if ok {
		t.Fatal("expected cipher cache miss")
	}

	if cipher != nil {
		t.Fatal("expected nil cipher")
	}
}

func TestNoRedisInvalidateSecretDoesNothing(t *testing.T) {
	cache := NewRedis("ignored")

	cache.InvalidateSecret()
}
