package fpe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	tweakVersionLen = 2
	tweakHashLen    = 8
	tweakLength     = tweakVersionLen + tweakHashLen
	cipherTTL       = 120 * time.Minute
)

type Service struct {
	keys  KeyProvider
	cache CipherCache

	cipherCache sync.Map
	buildGroup  singleflight.Group
}

type EncryptOptions struct {
	Radix int
	Tweak string
}

type cachedCipher struct {
	cipher  *Cipher
	expires time.Time
}

type CipherCache interface {
	GetCipher(ctx context.Context, cacheKey string, radix int, maxTweakLength int) (*Cipher, bool)
	SetCipher(cacheKey string, key []byte, tweak []byte)
}

func NewService(keys KeyProvider, cache CipherCache) *Service {
	return &Service{keys: keys, cache: cache}
}

func buildTweak(version uint16, custom string) []byte {
	tweak := make([]byte, tweakLength)

	binary.BigEndian.PutUint16(tweak[:tweakVersionLen], version)

	hash := sha256.Sum256([]byte(custom))
	copy(tweak[tweakVersionLen:], hash[:tweakHashLen])

	return tweak
}

func (s *Service) getCipher(ctx context.Context, version uint16, radix int, customTweak string) (*Cipher, error) {
	cacheKey := fmt.Sprintf("%d-%s-%d", version, customTweak, radix)

	if value, ok := s.cipherCache.Load(cacheKey); ok {
		cached := value.(*cachedCipher)

		if time.Now().Before(cached.expires) {
			return cached.cipher, nil
		}

		s.cipherCache.Delete(cacheKey)
	}

	result, err, _ := s.buildGroup.Do(
		cacheKey,
		func() (any, error) {
			if value, ok := s.cipherCache.Load(cacheKey); ok {
				cached := value.(*cachedCipher)

				if time.Now().Before(cached.expires) {
					return cached.cipher, nil
				}

				s.cipherCache.Delete(cacheKey)
			}

			tweak := buildTweak(version, customTweak)

			if s.cache != nil {
				if cipher, ok := s.cache.GetCipher(
					ctx,
					cacheKey,
					radix,
					tweakLength,
				); ok {
					s.cipherCache.Store(
						cacheKey,
						&cachedCipher{
							cipher:  cipher,
							expires: time.Now().Add(cipherTTL),
						},
					)

					return cipher, nil
				}
			}

			key, err := s.keys.Key(ctx, version)
			if err != nil {
				return nil, WrapError(
					ErrKeyUnavailable,
					"unable to obtain encryption key",
					err,
				)
			}

			cipher, err := NewCipher(
				radix,
				tweakLength,
				key.Bytes,
				tweak,
			)
			if err != nil {
				return nil, WrapError(
					ErrCipherBuild,
					"unable to initialize cipher",
					err,
				)
			}

			s.cipherCache.Store(
				cacheKey,
				&cachedCipher{
					cipher:  cipher,
					expires: time.Now().Add(cipherTTL),
				},
			)

			if s.cache != nil {
				s.cache.SetCipher(
					cacheKey,
					key.Bytes,
					tweak,
				)
			}

			return cipher, nil
		},
	)
	if err != nil {
		return nil, err
	}

	cipher, ok := result.(*Cipher)
	if !ok {
		return nil, WrapError(
			ErrCipherBuild,
			"unexpected cipher cache result type",
			nil,
		)
	}

	return cipher, nil
}

func (s *Service) Prewarm(ctx context.Context) error {
	version, err := s.keys.CurrentVersion(ctx)
	if err != nil {
		return WrapError(ErrKeyUnavailable, "unable to obtain current key version during prewarm", err)
	}

	_, err = s.getCipher(ctx, version, DefaultRadix, "")
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) Encrypt(ctx context.Context, values []string, opts EncryptOptions) ([]string, error) {
	radix := opts.Radix
	if radix == 0 {
		radix = DefaultRadix
	}

	for _, value := range values {
		if err := validateInput(value, radix); err != nil {
			return nil, err
		}
	}

	version, err := s.keys.CurrentVersion(ctx)
	if err != nil {
		return nil, WrapError(
			ErrKeyUnavailable,
			"unable to obtain current key version",
			err,
		)
	}

	cipher, err := s.getCipher(
		ctx,
		version,
		radix,
		opts.Tweak,
	)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(values))

	for i, value := range values {
		encrypted, err := cipher.Encrypt(value)
		if err != nil {
			return nil, WrapError(
				ErrEncrypt,
				"encryption failed",
				err,
			)
		}

		result[i] = encrypted
	}

	return result, nil
}
