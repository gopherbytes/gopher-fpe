//go:build noredis

package cache

import (
	"context"

	"github.com/fpe-tooling/fpe"
)

type Redis struct{}

func NewRedis(_ string) *Redis {
	return &Redis{}
}

func (r *Redis) Init(_ context.Context) {}

func (r *Redis) Available() bool {
	return false
}

func (r *Redis) Endpoint() string {
	return ""
}

func (r *Redis) GetCipher(_ context.Context, _ string, _ int, _ int) (*fpe.Cipher, bool) {
	return nil, false
}

func (r *Redis) SetCipher(_ string, _ []byte, _ []byte) {
}

func (r *Redis) GetSecret(_ context.Context) (string, bool) {
	return "", false
}

func (r *Redis) SetSecret(_ string) {}

func (r *Redis) InvalidateSecret() {}
