package crypto

import (
	"runtime"

	"github.com/alexedwards/argon2id"
)

type ICryptoService interface {
	HashPassword(password string) (string, error)
	ComparePasswordAndHash(password, hash string) (bool, error)
}

type CryptoService struct {

}

func NewCryptoService() *CryptoService {
	return &CryptoService{}
}

func (c *CryptoService) HashPassword(password string) (string, error) {
	params := &argon2id.Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: uint8(runtime.NumCPU()),
		SaltLength:  16,
		KeyLength:   32,
	}
	return argon2id.CreateHash(password, params)
}

func (c *CryptoService) ComparePasswordAndHash(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}	