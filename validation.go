package fpe

import (
	"fmt"
	"math"
	"math/big"
)

const (
	MinDomain    = 1_000_000
	DefaultRadix = 62
	maxInputLen  = 1024
)

func powInt(radix, length int) *big.Int {
	r := big.NewInt(int64(radix))
	return r.Exp(r, big.NewInt(int64(length)), nil)
}

func domainValid(radix, length int) bool {
	return powInt(radix, length).Cmp(big.NewInt(MinDomain)) >= 0
}

func validateInput(plain string, radix int) error {
	if radix != 10 && radix != 36 && radix != 62 {
		return NewError(
			ErrUnsupportedRadix,
			fmt.Sprintf("unsupported radix %d", radix),
		)
	}

	if !domainValid(radix, len(plain)) {
		minLen := int(math.Ceil(math.Log(float64(MinDomain)) / math.Log(float64(radix))))
		return NewError(ErrInputTooShort, fmt.Sprintf("input too short for base %d: must be >= %d", radix, minLen))
	}

	if len(plain) > maxInputLen {
		return NewError(ErrInputTooLong, fmt.Sprintf("input too long (>%d)", maxInputLen))
	}

	var allowed func(rune) bool

	switch radix {
	case 10:
		allowed = func(r rune) bool {
			return r >= '0' && r <= '9'
		}

	case 36:
		allowed = func(r rune) bool {
			return (r >= '0' && r <= '9') ||
				(r >= 'a' && r <= 'z')
		}

	case 62:
		allowed = func(r rune) bool {
			return (r >= '0' && r <= '9') ||
				(r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z')
		}
	}

	for _, r := range plain {
		if !allowed(r) {
			return NewError(
				ErrInvalidChar,
				fmt.Sprintf(
					"char %q not allowed in base %d",
					r,
					radix,
				),
			)
		}
	}

	return nil
}
