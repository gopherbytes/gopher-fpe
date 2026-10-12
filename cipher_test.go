package fpe

import (
	"strings"
	"testing"
)

func TestCipherEncryptDeterministic(t *testing.T) {
	key := []byte("0123456789abcdef")
	tweak := make([]byte, 10)

	cipher, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	first, err := cipher.Encrypt("123456789")
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	second, err := cipher.Encrypt("123456789")
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}

	if first != second {
		t.Fatalf(
			"expected deterministic ciphertext, got %q and %q",
			first,
			second,
		)
	}
}

func TestCipherEncryptPreservesLengthRadix10(t *testing.T) {
	key := []byte("0123456789abcdef")
	tweak := make([]byte, 10)

	cipher, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	plain := "123456789"

	encrypted, err := cipher.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(encrypted) != len(plain) {
		t.Fatalf(
			"expected ciphertext length %d, got %d",
			len(plain),
			len(encrypted),
		)
	}
}

func TestCipherEncryptPreservesRadix10Characters(t *testing.T) {
	key := []byte("0123456789abcdef")
	tweak := make([]byte, 10)

	cipher, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	encrypted, err := cipher.Encrypt("123456789")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	for _, r := range encrypted {
		if r < '0' || r > '9' {
			t.Fatalf(
				"expected radix-10 ciphertext, found invalid character %q in %q",
				r,
				encrypted,
			)
		}
	}
}

func TestCipherEncryptPreservesRadix36Characters(t *testing.T) {
	key := []byte("0123456789abcdef")
	tweak := make([]byte, 10)

	cipher, err := NewCipher(
		36,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	encrypted, err := cipher.Encrypt("abc123")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(encrypted) != len("abc123") {
		t.Fatalf(
			"expected ciphertext length %d, got %d",
			len("abc123"),
			len(encrypted),
		)
	}

	for _, r := range encrypted {
		valid := (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'z')

		if !valid {
			t.Fatalf(
				"expected radix-36 ciphertext, found invalid character %q in %q",
				r,
				encrypted,
			)
		}
	}
}

func TestCipherEncryptPreservesRadix62Characters(t *testing.T) {
	key := []byte("0123456789abcdef")
	tweak := make([]byte, 10)

	cipher, err := NewCipher(
		62,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	plain := "AbC123"

	encrypted, err := cipher.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(encrypted) != len(plain) {
		t.Fatalf(
			"expected ciphertext length %d, got %d",
			len(plain),
			len(encrypted),
		)
	}

	for _, r := range encrypted {
		valid := (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z')

		if !valid {
			t.Fatalf(
				"expected radix-62 ciphertext, found invalid character %q in %q",
				r,
				encrypted,
			)
		}
	}
}

func TestCipherDifferentTweaksProduceDifferentCiphertext(t *testing.T) {
	key := []byte("0123456789abcdef")

	firstTweak := []byte{
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 1,
	}

	secondTweak := []byte{
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 2,
	}

	firstCipher, err := NewCipher(
		10,
		10,
		key,
		firstTweak,
	)
	if err != nil {
		t.Fatalf("first NewCipher failed: %v", err)
	}

	secondCipher, err := NewCipher(
		10,
		10,
		key,
		secondTweak,
	)
	if err != nil {
		t.Fatalf("second NewCipher failed: %v", err)
	}

	plain := "123456789"

	first, err := firstCipher.Encrypt(plain)
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	second, err := secondCipher.Encrypt(plain)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}

	if first == second {
		t.Fatalf(
			"expected different tweaks to produce different ciphertext, got %q",
			first,
		)
	}
}

func TestCipherDifferentKeysProduceDifferentCiphertext(t *testing.T) {
	firstKey := []byte("0123456789abcdef")
	secondKey := []byte("fedcba9876543210")

	tweak := make([]byte, 10)

	firstCipher, err := NewCipher(
		10,
		10,
		firstKey,
		tweak,
	)
	if err != nil {
		t.Fatalf("first NewCipher failed: %v", err)
	}

	secondCipher, err := NewCipher(
		10,
		10,
		secondKey,
		tweak,
	)
	if err != nil {
		t.Fatalf("second NewCipher failed: %v", err)
	}

	plain := "123456789"

	first, err := firstCipher.Encrypt(plain)
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	second, err := secondCipher.Encrypt(plain)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}

	if first == second {
		t.Fatalf(
			"expected different keys to produce different ciphertext, got %q",
			first,
		)
	}
}

func TestNewCipherRejectsInvalidAESKeyLength(t *testing.T) {
	key := []byte("too-short")
	tweak := make([]byte, 10)

	_, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err == nil {
		t.Fatal("expected invalid AES key length to fail")
	}
}

func TestNewCipherAcceptsAES128Key(t *testing.T) {
	key := make([]byte, 16)
	tweak := make([]byte, 10)

	_, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("expected AES-128 key to be accepted, got: %v", err)
	}
}

func TestNewCipherAcceptsAES192Key(t *testing.T) {
	key := make([]byte, 24)
	tweak := make([]byte, 10)

	_, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("expected AES-192 key to be accepted, got: %v", err)
	}
}

func TestNewCipherAcceptsAES256Key(t *testing.T) {
	key := make([]byte, 32)
	tweak := make([]byte, 10)

	_, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("expected AES-256 key to be accepted, got: %v", err)
	}
}

func TestNewCipherRejectsTweakLongerThanMaximum(t *testing.T) {
	key := []byte("0123456789abcdef")

	maxTweakLength := 10
	tweak := make([]byte, maxTweakLength+1)

	_, err := NewCipher(
		10,
		maxTweakLength,
		key,
		tweak,
	)
	if err == nil {
		t.Fatal("expected tweak longer than maxTLen to fail")
	}
}

func TestNewCipherAcceptsMaximumTweakLength(t *testing.T) {
	key := []byte("0123456789abcdef")

	maxTweakLength := 10
	tweak := make([]byte, maxTweakLength)

	_, err := NewCipher(
		10,
		maxTweakLength,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf(
			"expected tweak at maximum length to be accepted, got: %v",
			err,
		)
	}
}

func TestCipherRejectsInputBelowMinimumLength(t *testing.T) {
	key := []byte("0123456789abcdef")
	tweak := make([]byte, 10)

	cipher, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	_, err = cipher.Encrypt("12345")
	if err == nil {
		t.Fatal("expected input below cipher minimum length to fail")
	}
}

func TestCipherAcceptsMinimumLengthRadix10(t *testing.T) {
	key := []byte("0123456789abcdef")
	tweak := make([]byte, 10)

	cipher, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	encrypted, err := cipher.Encrypt("123456")
	if err != nil {
		t.Fatalf(
			"expected minimum-length radix-10 input to encrypt, got: %v",
			err,
		)
	}

	if len(encrypted) != 6 {
		t.Fatalf(
			"expected ciphertext length 6, got %d",
			len(encrypted),
		)
	}
}

func TestCipherEncryptLongInput(t *testing.T) {
	key := []byte("0123456789abcdef")
	tweak := make([]byte, 10)

	cipher, err := NewCipher(
		10,
		10,
		key,
		tweak,
	)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	plain := strings.Repeat("1", 128)

	encrypted, err := cipher.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt failed for long input: %v", err)
	}

	if len(encrypted) != len(plain) {
		t.Fatalf(
			"expected ciphertext length %d, got %d",
			len(plain),
			len(encrypted),
		)
	}

	for _, r := range encrypted {
		if r < '0' || r > '9' {
			t.Fatalf(
				"expected radix-10 ciphertext, found %q",
				r,
			)
		}
	}
}
