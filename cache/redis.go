//go:build !noredis

package cache

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	fpe "github.com/gopherbytes/gopher-fpe"
	"github.com/redis/go-redis/v9"
)

const (
	redisTimeout   = 500 * time.Millisecond
	cipherCacheTTL = 4 * time.Hour

	secretRedisKey = "fpe:secret:current"
	secretRedisTTL = 5 * time.Minute
)

type redisClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Ping(ctx context.Context) *redis.StatusCmd
}

type Redis struct {
	client    redisClient
	endpoint  string
	once      sync.Once
	available bool
}

func NewRedis(endpoint string) *Redis {
	return &Redis{endpoint: endpoint}
}

func (r *Redis) Init(ctx context.Context) {
	r.once.Do(func() {
		if r.endpoint == "" {
			return
		}

		r.client = redis.NewClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:6379", r.endpoint),
			DialTimeout:  redisTimeout,
			ReadTimeout:  redisTimeout,
			WriteTimeout: redisTimeout,
			MaxRetries:   1,
			PoolSize:     10,
			MinIdleConns: 2,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		})

		r.available = true

		// pingCtx, cancel := context.WithTimeout(ctx, redisTimeout)
		// defer cancel()

		// if err := r.client.Ping(pingCtx).Err(); err == nil {
		// 	r.available = true
		// }
	})
}

func (r *Redis) Available() bool {
	return r.available
}

func (r *Redis) Endpoint() string {
	return r.endpoint
}

type cipherEntry struct {
	Key   string `json:"key"`
	Tweak string `json:"tweak"`
}

func (r *Redis) GetCipher(ctx context.Context, cacheKey string, radix int, maxTweakLength int) (*fpe.Cipher, bool) {
	if !r.available {
		return nil, false
	}

	redisCtx, cancel := context.WithTimeout(ctx, redisTimeout)
	defer cancel()

	value, err := r.client.Get(redisCtx, cacheKey).Result()
	if err != nil {
		return nil, false
	}

	var cached cipherEntry
	if err := json.Unmarshal([]byte(value), &cached); err != nil {
		return nil, false
	}

	key, err := base64.StdEncoding.DecodeString(cached.Key)
	if err != nil {
		return nil, false
	}

	tweak, err := base64.StdEncoding.DecodeString(cached.Tweak)
	if err != nil {
		return nil, false
	}

	cipher, err := fpe.NewCipher(
		radix,
		maxTweakLength,
		key,
		tweak,
	)
	if err != nil {
		return nil, false
	}

	return cipher, true
}

func (r *Redis) SetCipher(cacheKey string, key []byte, tweak []byte) {
	if !r.available {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			redisTimeout,
		)
		defer cancel()

		entry := cipherEntry{
			Key:   base64.StdEncoding.EncodeToString(key),
			Tweak: base64.StdEncoding.EncodeToString(tweak),
		}

		value, err := json.Marshal(entry)
		if err != nil {
			return
		}

		_ = r.client.Set(
			ctx,
			cacheKey,
			value,
			cipherCacheTTL,
		).Err()
	}()
}

func (r *Redis) GetSecret(ctx context.Context) (string, bool) {
	if !r.available {
		return "", false
	}

	redisCtx, cancel := context.WithTimeout(ctx, redisTimeout)
	defer cancel()

	value, err := r.client.Get(
		redisCtx,
		secretRedisKey,
	).Result()
	if err != nil {
		return "", false
	}

	return value, true
}

func (r *Redis) SetSecret(secretJSON string) {
	if !r.available {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			redisTimeout,
		)
		defer cancel()

		_ = r.client.Set(
			ctx,
			secretRedisKey,
			secretJSON,
			secretRedisTTL,
		).Err()
	}()
}

func (r *Redis) InvalidateSecret() {
	if !r.available {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), redisTimeout)
	defer cancel()

	_ = r.client.Del(ctx, secretRedisKey).Err()
}
