package fpe

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateInputAcceptsValidRadix10(t *testing.T) {
	err := validateInput("123456", 10)
	if err != nil {
		t.Fatalf("expected valid radix-10 input, got error: %v", err)
	}
}

func TestValidateInputAcceptsValidRadix36(t *testing.T) {
	err := validateInput("abc123", 36)
	if err != nil {
		t.Fatalf("expected valid radix-36 input, got error: %v", err)
	}
}

func TestValidateInputAcceptsValidRadix62(t *testing.T) {
	err := validateInput("AbC123", 62)
	if err != nil {
		t.Fatalf("expected valid radix-62 input, got error: %v", err)
	}
}

func TestValidateInputRejectsUnsupportedRadix(t *testing.T) {
	err := validateInput("123456", 16)
	if err == nil {
		t.Fatal("expected unsupported radix error")
	}

	var fpeErr *Error
	if !errors.As(err, &fpeErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}

	if fpeErr.Code != ErrUnsupportedRadix {
		t.Fatalf("expected error code %q, got %q", ErrUnsupportedRadix, fpeErr.Code)
	}
}

func TestValidateInputRejectsTooShortRadix10(t *testing.T) {
	err := validateInput("12345", 10)
	if err == nil {
		t.Fatal("expected input-too-short error")
	}

	var fpeErr *Error
	if !errors.As(err, &fpeErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}

	if fpeErr.Code != ErrInputTooShort {
		t.Fatalf("expected error code %q, got %q", ErrInputTooShort, fpeErr.Code)
	}
}

func TestValidateInputAcceptsMinimumLengthRadix10(t *testing.T) {
	err := validateInput("123456", 10)
	if err != nil {
		t.Fatalf("expected six radix-10 characters to satisfy minimum domain, got: %v", err)
	}
}

func TestValidateInputRejectsTooShortRadix36(t *testing.T) {
	err := validateInput("abc", 36)
	if err == nil {
		t.Fatal("expected input-too-short error")
	}

	var fpeErr *Error
	if !errors.As(err, &fpeErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}

	if fpeErr.Code != ErrInputTooShort {
		t.Fatalf("expected error code %q, got %q", ErrInputTooShort, fpeErr.Code)
	}
}

func TestValidateInputAcceptsMinimumLengthRadix36(t *testing.T) {
	err := validateInput("abcd", 36)
	if err != nil {
		t.Fatalf("expected four radix-36 characters to satisfy minimum domain, got: %v", err)
	}
}

func TestValidateInputRejectsTooShortRadix62(t *testing.T) {
	err := validateInput("abc", 62)
	if err == nil {
		t.Fatal("expected input-too-short error")
	}

	var fpeErr *Error
	if !errors.As(err, &fpeErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}

	if fpeErr.Code != ErrInputTooShort {
		t.Fatalf("expected error code %q, got %q", ErrInputTooShort, fpeErr.Code)
	}
}

func TestValidateInputAcceptsMinimumLengthRadix62(t *testing.T) {
	err := validateInput("AbC1", 62)
	if err != nil {
		t.Fatalf("expected four radix-62 characters to satisfy minimum domain, got: %v", err)
	}
}

func TestValidateInputRejectsInvalidRadix10Character(t *testing.T) {
	err := validateInput("12345a", 10)
	if err == nil {
		t.Fatal("expected invalid-character error")
	}

	var fpeErr *Error
	if !errors.As(err, &fpeErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}

	if fpeErr.Code != ErrInvalidChar {
		t.Fatalf("expected error code %q, got %q", ErrInvalidChar, fpeErr.Code)
	}
}

func TestValidateInputRejectsUppercaseRadix36(t *testing.T) {
	err := validateInput("ABC123", 36)
	if err == nil {
		t.Fatal("expected uppercase characters to be rejected for radix 36")
	}

	var fpeErr *Error
	if !errors.As(err, &fpeErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}

	if fpeErr.Code != ErrInvalidChar {
		t.Fatalf("expected error code %q, got %q", ErrInvalidChar, fpeErr.Code)
	}
}

func TestValidateInputAcceptsUppercaseRadix62(t *testing.T) {
	err := validateInput("ABC123", 62)
	if err != nil {
		t.Fatalf("expected uppercase characters to be valid for radix 62, got: %v", err)
	}
}

func TestValidateInputRejectsSymbolRadix62(t *testing.T) {
	err := validateInput("ABC12-", 62)
	if err == nil {
		t.Fatal("expected symbol to be rejected for radix 62")
	}

	var fpeErr *Error
	if !errors.As(err, &fpeErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}

	if fpeErr.Code != ErrInvalidChar {
		t.Fatalf("expected error code %q, got %q", ErrInvalidChar, fpeErr.Code)
	}
}

func TestValidateInputRejectsInputOverMaximumLength(t *testing.T) {
	input := strings.Repeat("1", maxInputLen+1)

	err := validateInput(input, 10)
	if err == nil {
		t.Fatal("expected input-too-long error")
	}

	var fpeErr *Error
	if !errors.As(err, &fpeErr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}

	if fpeErr.Code != ErrInputTooLong {
		t.Fatalf(
			"expected error code %q, got %q",
			ErrInputTooLong,
			fpeErr.Code,
		)
	}
}

func TestValidateInputAcceptsMaximumLength(t *testing.T) {
	input := strings.Repeat("1", maxInputLen)

	err := validateInput(input, 10)
	if err != nil {
		t.Fatalf(
			"expected input at maximum length to be accepted, got: %v",
			err,
		)
	}
}

func TestDomainValid(t *testing.T) {
	tests := []struct {
		name   string
		radix  int
		length int
		want   bool
	}{
		{
			name:   "radix10 too small",
			radix:  10,
			length: 5,
			want:   false,
		},
		{
			name:   "radix10 minimum",
			radix:  10,
			length: 6,
			want:   true,
		},
		{
			name:   "radix36 too small",
			radix:  36,
			length: 3,
			want:   false,
		},
		{
			name:   "radix36 minimum",
			radix:  36,
			length: 4,
			want:   true,
		},
		{
			name:   "radix62 too small",
			radix:  62,
			length: 3,
			want:   false,
		},
		{
			name:   "radix62 minimum",
			radix:  62,
			length: 4,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domainValid(tt.radix, tt.length)

			if got != tt.want {
				t.Fatalf("domainValid(%d, %d) = %v, want %v", tt.radix, tt.length, got, tt.want)
			}
		})
	}
}
