package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewJWTService(t *testing.T) {
	service := NewJWTService()
	if service == nil {
		t.Fatal("NewJWTService() returned nil")
	}
}

func TestGenerateToken_Success(t *testing.T) {
	service := NewJWTService()
	options := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            nil,
	}

	token, err := service.GenerateToken(options)
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned empty token")
	}
}

func TestGenerateToken_WithCustomClaims(t *testing.T) {
	service := NewJWTService()
	customClaims := map[string]interface{}{
		"userId":   "12345",
		"username": "testuser",
		"role":     "admin",
	}
	options := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            customClaims,
	}

	token, err := service.GenerateToken(options)
	if err != nil {
		t.Fatalf("GenerateToken() with custom claims failed: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned empty token")
	}
}

func TestGenerateToken_MinimalOptions(t *testing.T) {
	service := NewJWTService()
	options := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "",
		Audience:          "",
		Subject:           "",
		ExpirationSeconds: 60,
		Claims:            nil,
	}

	token, err := service.GenerateToken(options)
	if err != nil {
		t.Fatalf("GenerateToken() with minimal options failed: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned empty token")
	}
}

func TestValidateToken_Success(t *testing.T) {
	service := NewJWTService()
	options := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            nil,
	}

	token, err := service.GenerateToken(options)
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}

	claims, err := service.ValidateToken(token, options)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}
	if claims == nil {
		t.Fatal("ValidateToken() returned nil claims")
	}
	if claims["iss"] != options.Issuer {
		t.Fatalf("ValidateToken() issuer mismatch: got %v, want %v", claims["iss"], options.Issuer)
	}
	if claims["aud"] != options.Audience {
		t.Fatalf("ValidateToken() audience mismatch: got %v, want %v", claims["aud"], options.Audience)
	}
	if claims["sub"] != options.Subject {
		t.Fatalf("ValidateToken() subject mismatch: got %v, want %v", claims["sub"], options.Subject)
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	service := NewJWTService()
	options := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: -1, // Already expired
		Claims:            nil,
	}

	token, err := service.GenerateToken(options)
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}

	time.Sleep(time.Second) // Ensure token is expired

	_, err = service.ValidateToken(token, options)
	if err == nil {
		t.Fatal("ValidateToken() should fail with expired token")
	}
}

func TestValidateToken_InvalidSecret(t *testing.T) {
	service := NewJWTService()
	generateOptions := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            nil,
	}

	token, err := service.GenerateToken(generateOptions)
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}

	validateOptions := generateOptions
	validateOptions.SecretKey = "wrong-secret-key"

	_, err = service.ValidateToken(token, validateOptions)
	if err == nil {
		t.Fatal("ValidateToken() should fail with wrong secret key")
	}
}

func TestValidateToken_InvalidIssuer(t *testing.T) {
	service := NewJWTService()
	generateOptions := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            nil,
	}

	token, err := service.GenerateToken(generateOptions)
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}

	validateOptions := generateOptions
	validateOptions.Issuer = "wrong-issuer"

	_, err = service.ValidateToken(token, validateOptions)
	if err == nil {
		t.Fatal("ValidateToken() should fail with wrong issuer")
	}
}

func TestValidateToken_InvalidAudience(t *testing.T) {
	service := NewJWTService()
	generateOptions := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            nil,
	}

	token, err := service.GenerateToken(generateOptions)
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}

	validateOptions := generateOptions
	validateOptions.Audience = "wrong-audience"

	_, err = service.ValidateToken(token, validateOptions)
	if err == nil {
		t.Fatal("ValidateToken() should fail with wrong audience")
	}
}

func TestValidateToken_InvalidSubject(t *testing.T) {
	service := NewJWTService()
	generateOptions := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            nil,
	}

	token, err := service.GenerateToken(generateOptions)
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}

	validateOptions := generateOptions
	validateOptions.Subject = "wrong-subject"

	_, err = service.ValidateToken(token, validateOptions)
	if err == nil {
		t.Fatal("ValidateToken() should fail with wrong subject")
	}
}

func TestValidateToken_MalformedToken(t *testing.T) {
	service := NewJWTService()
	options := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            nil,
	}

	malformedToken := "this.is.not.a.valid.token"

	_, err := service.ValidateToken(malformedToken, options)
	if err == nil {
		t.Fatal("ValidateToken() should fail with malformed token")
	}
}

func TestValidateToken_CustomClaims(t *testing.T) {
	service := NewJWTService()
	customClaims := map[string]interface{}{
		"userId":   "12345",
		"username": "testuser",
		"role":     "admin",
	}
	options := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            customClaims,
	}

	token, err := service.GenerateToken(options)
	if err != nil {
		t.Fatalf("GenerateToken() failed: %v", err)
	}

	claims, err := service.ValidateToken(token, options)
	if err != nil {
		t.Fatalf("ValidateToken() failed: %v", err)
	}

	if claims["userId"] != "12345" {
		t.Fatalf("Custom claim userId mismatch: got %v, want %v", claims["userId"], "12345")
	}
	if claims["username"] != "testuser" {
		t.Fatalf("Custom claim username mismatch: got %v, want %v", claims["username"], "testuser")
	}
	if claims["role"] != "admin" {
		t.Fatalf("Custom claim role mismatch: got %v, want %v", claims["role"], "admin")
	}
}

func TestValidateToken_InvalidClaimsType(t *testing.T) {
	// Create a token with invalid claims structure
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:  "test-issuer",
		Subject: "test-subject",
	})

	tokenString, err := token.SignedString([]byte("test-secret-key"))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	service := NewJWTService()
	options := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
	}

	_, err = service.ValidateToken(tokenString, options)
	if err == nil {
		t.Fatal("ValidateToken() should fail when audience doesn't match")
	}
}

func TestGenerateToken_EmptyClaimsMap(t *testing.T) {
	service := NewJWTService()
	options := JWTTokenOptions{
		SecretKey:         "test-secret-key",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims:            map[string]interface{}{}, // Empty map to ensure loop is entered
	}

	token, err := service.GenerateToken(options)
	if err != nil {
		t.Fatalf("GenerateToken() with empty claims map failed: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned empty token")
	}
}
