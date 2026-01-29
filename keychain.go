package keychain

import (
	"github.com/morpheuszero/keychain/internal/crypto"
	"github.com/morpheuszero/keychain/internal/jwt"
)

type Keychain struct {
	cryptoService crypto.ICryptoService
	jwtService jwt.IJWTService
}

func NewKeychain() *Keychain {
	return &Keychain{
		cryptoService: crypto.NewCryptoService(),
		jwtService: jwt.NewJWTService(),
	}
}

func (k *Keychain) HashPassword(password string) (string, error) {
	return k.cryptoService.HashPassword(password)
}

func (k *Keychain) ComparePasswordAndHash(password, hash string) (bool, error) {
	return k.cryptoService.ComparePasswordAndHash(password, hash)
}

func (k *Keychain) GenerateJWTToken(options jwt.JWTTokenOptions) (string, error) {
	return k.jwtService.GenerateToken(options)
}

func (k *Keychain) ValidateJWTToken(token string, options jwt.JWTTokenOptions) (map[string]interface{}, error) {
	return k.jwtService.ValidateToken(token, options)
}