package keychain

import (
	"net/http"

	"github.com/morpheuszero/keychain/common/cookies"
	"github.com/morpheuszero/keychain/common/crypto"
	"github.com/morpheuszero/keychain/common/jwt"
	"github.com/morpheuszero/keychain/common/rbac"
)

type Keychain struct {
	cryptoService     crypto.ICryptoService
	jwtService        jwt.IJWTService
	cookieJar         cookies.ICookieJar
	authPolicyHandler rbac.AuthPolicyHandler
}

func NewKeychain() *Keychain {
	return &Keychain{
		cryptoService:     crypto.NewCryptoService(),
		jwtService:        jwt.NewJWTService(),
		cookieJar:         cookies.NewCookieJar(),
		authPolicyHandler: *rbac.NewAuthPolicyHandler(),
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

func (k *Keychain) SetCookie(w http.ResponseWriter, options *cookies.CookieOptions) {
	k.cookieJar.SetCookie(w, options)
}

func (k *Keychain) GetCookieValue(r *http.Request, name string) (string, error) {
	return k.cookieJar.GetCookieValue(r, name)
}
func (k *Keychain) DeleteCookie(w http.ResponseWriter, name string) {
	k.cookieJar.DeleteCookie(w, name)
}
func (k *Keychain) GetAuthPolicyHandler() *rbac.AuthPolicyHandler {
	return &k.authPolicyHandler
}
