package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTTokenOptions struct {
	SecretKey         string
	Issuer            string
	Audience 	      string
	Subject		      string
	ExpirationSeconds int
	Claims           map[string]interface{}
}

type IJWTService interface {
	GenerateToken(options JWTTokenOptions) (string, error)
	ValidateToken(token string, options JWTTokenOptions) (map[string]interface{}, error)
}

type JWTService struct {

}

func NewJWTService() *JWTService {
	return &JWTService{}
}	

func (j *JWTService) GenerateToken(options JWTTokenOptions) (string, error) {
	
	var claims jwt.MapClaims = make(jwt.MapClaims)
	claims["iss"] = options.Issuer
	claims["aud"] = options.Audience
	claims["sub"] = options.Subject
	claims["exp"] = time.Now().Add(time.Duration(options.ExpirationSeconds) * time.Second).Unix()
	claims["iat"] = time.Now().Unix()

	for k, v := range options.Claims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(options.SecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JWTService) ValidateToken(token string, options JWTTokenOptions) (map[string]interface{}, error) {
	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		return []byte(options.SecretKey), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, err
	}

	mappedClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	claims := map[string]interface{}(mappedClaims)

	if claims["iss"] != options.Issuer {
		return nil, fmt.Errorf("invalid issuer")
	}
	if claims["aud"] != options.Audience {
		return nil, fmt.Errorf("invalid audience")
	}
	if claims["sub"] != options.Subject {
		return nil, fmt.Errorf("invalid subject")
	}

	return claims, nil
}