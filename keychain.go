package keychain

import "github.com/morpheuszero/keychain/internal/crypto"

type Keychain struct {
	cryptoService crypto.ICryptoService
}

func NewKeychain() *Keychain {
	return &Keychain{
		cryptoService: crypto.NewCryptoService(),
	}
}

func (k *Keychain) HashPassword(password string) (string, error) {
	return k.cryptoService.HashPassword(password)
}

func (k *Keychain) ComparePasswordAndHash(password, hash string) (bool, error) {
	return k.cryptoService.ComparePasswordAndHash(password, hash)
}