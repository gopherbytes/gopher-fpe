package fpe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
)

const (
	numRounds     = 10
	blockSize     = aes.BlockSize
	halfBlockSize = blockSize / 2
)

var (
	ivZero                = make([]byte, blockSize)
	errTweakLengthInvalid = errors.New("tweak length invalid")
)

type Cipher struct {
	radix     int
	maxTLen   int
	tweak     []byte
	block     cipher.Block
	minMsgLen uint32
	maxMsgLen uint32
}

func ceilDiv(x, y int) int { return (x + y - 1) / y }

func pow(radix int, n uint32) *big.Int {
	r := big.NewInt(int64(radix))
	return r.Exp(r, big.NewInt(int64(n)), nil)
}

func calcMinLen(radix int) uint32 {
	res := big.NewInt(1)
	r := big.NewInt(int64(radix))
	n := uint32(0)

	for res.Cmp(big.NewInt(MinDomain)) < 0 {
		n++
		res.Mul(res, r)
	}

	return n
}

func NewCipher(radix, maxTLen int, key, tweak []byte) (*Cipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("AES key must be 128/192/256 bits")
	}
	if radix < 2 || radix > big.MaxBase {
		return nil, errors.New("radix out of range")
	}
	if len(tweak) > maxTLen {
		return nil, errTweakLengthInvalid
	}

	minLen := calcMinLen(radix)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		radix:     radix,
		maxTLen:   maxTLen,
		tweak:     tweak,
		block:     block,
		minMsgLen: minLen,
		maxMsgLen: ^uint32(0),
	}, nil
}

func ciphWithCBC(cbc cipher.BlockMode, buf []byte) error {
	if len(buf)%blockSize != 0 {
		return errors.New("ciph len ! multiple 16")
	}
	cbc.CryptBlocks(buf, buf)
	cbc.(interface{ SetIV([]byte) }).SetIV(ivZero)
	return nil
}

func (c *Cipher) Encrypt(value string) (string, error) {
	return c.feistel(value, c.tweak, true)
}

func (c *Cipher) feistel(value string, tweak []byte, enc bool) (string, error) {

	n := uint32(len(value))
	if n < c.minMsgLen || n > c.maxMsgLen {
		return "", errors.New("msg len out of bounds")
	}
	if len(tweak) > c.maxTLen {
		return "", errTweakLengthInvalid
	}

	// Create a local CBC encrypter (no shared state)
	cbc := cipher.NewCBCEncrypter(c.block, ivZero)

	u := n / 2
	v := n - u
	radixBig := big.NewInt(int64(c.radix))

	// b, d, maxJ SIN floats
	bits := pow(c.radix, v).BitLen()
	b := ceilDiv(bits, 8)
	d := 4*ceilDiv(b, 4) + 4
	maxJ := ceilDiv(d, 16)

	// P constante
	P := make([]byte, blockSize)
	P[0], P[1], P[2] = 0x01, 0x02, 0x01
	binary.BigEndian.PutUint16(P[4:6], uint16(c.radix))
	P[6], P[7] = 0x0a, byte(u)
	binary.BigEndian.PutUint32(P[8:12], n)
	binary.BigEndian.PutUint32(P[12:16], uint32(len(tweak)))

	numPad := (-len(tweak) - b - 1) % 16
	if numPad < 0 {
		numPad += 16
	}
	lenQ := len(tweak) + b + 1 + numPad
	lenPQ := blockSize + lenQ
	total := lenQ + lenPQ + (maxJ-1)*blockSize
	buf := make([]byte, total)
	Q := buf[:lenQ]
	copy(Q[:len(tweak)], tweak)
	PQ := buf[lenQ : lenQ+lenPQ]
	Y := buf[lenQ+lenPQ-blockSize:]
	R := Y[:blockSize]
	xored := Y[blockSize:]

	var numA, numB, numC, numY big.Int
	var numModU, numModV big.Int
	numModU.Exp(radixBig, big.NewInt(int64(u)), nil)
	numModV.Exp(radixBig, big.NewInt(int64(v)), nil)

	left := value[:u]
	right := value[u:]

	if _, ok := numA.SetString(left, c.radix); !ok {
		return "", errors.New("invalid left numeral for radix")
	}

	if _, ok := numB.SetString(right, c.radix); !ok {
		return "", errors.New("invalid right numeral for radix")
	}

	rounds := func(i int) int {
		if enc {
			return i
		}
		return numRounds - 1 - i
	}

	for r := range numRounds {
		i := rounds(r)

		Q[len(tweak)+numPad] = byte(i)
		var src big.Int
		if enc {
			src = numB
		} else {
			src = numA
		}
		Bbytes := src.Bytes()
		for j := len(tweak) + numPad + 1; j < lenQ; j++ {
			Q[j] = 0x00
		}
		copy(Q[lenQ-len(Bbytes):], Bbytes)

		copy(PQ[:blockSize], P)
		copy(PQ[blockSize:], Q)
		// PRF inline (uses local cbc)
		if err := ciphWithCBC(cbc, PQ); err != nil {
			return "", err
		}
		copy(R, PQ[len(PQ)-blockSize:])

		for j := 1; j < maxJ; j++ {
			off := (j - 1) * blockSize
			for k := 0; k < halfBlockSize; k++ {
				xored[off+k] = 0
			}
			binary.BigEndian.PutUint64(xored[off+halfBlockSize:off+blockSize], uint64(j))
			for k := 0; k < blockSize; k++ {
				xored[off+k] ^= R[k]
			}

			if err := ciphWithCBC(cbc, xored[off:off+blockSize]); err != nil {
				return "", err
			}
		}
		numY.SetBytes(Y[:d])

		if enc {
			numC.Add(&numA, &numY)
		} else {
			numC.Sub(&numB, &numY)
		}

		if i%2 == 0 {
			numC.Mod(&numC, &numModU)
		} else {
			numC.Mod(&numC, &numModV)
		}

		if enc {
			numA.Set(&numB)
			numB.Set(&numC)
		} else {
			numB.Set(&numA)
			numA.Set(&numC)
		}
	}

	A, B := numA.Text(c.radix), numB.Text(c.radix)
	if len(A) < int(u) {
		A = strings.Repeat("0", int(u)-len(A)) + A
	}
	if len(B) < int(v) {
		B = strings.Repeat("0", int(v)-len(B)) + B
	}

	return A + B, nil
}
