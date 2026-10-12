package fpe

import "context"

type Key struct {
	Version uint16
	Bytes   []byte
}

type KeyProvider interface {
	CurrentVersion(ctx context.Context) (uint16, error)
	Key(ctx context.Context, version uint16) (Key, error)
}
