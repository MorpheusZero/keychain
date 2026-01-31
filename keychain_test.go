package keychain

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/morpheuszero/keychain/common/cookies"
	"github.com/morpheuszero/keychain/common/jwt"
	"github.com/morpheuszero/keychain/common/rbac"
)

func TestNewKeychain(t *testing.T) {
	kc := NewKeychain()

	if kc == nil {
		t.Fatal("NewKeychain() returned nil")
	}
	if kc.cryptoService == nil {
		t.Error("cryptoService not initialized")
	}
	if kc.jwtService == nil {
		t.Error("jwtService not initialized")
	}
	if kc.cookieJar == nil {
		t.Error("cookieJar not initialized")
	}
}

func TestKeychain_HashPassword(t *testing.T) {
	kc := NewKeychain()
	password := "testPassword123"

	hash, err := kc.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}
	if hash == "" {
		t.Error("HashPassword() returned empty hash")
	}
	if hash == password {
		t.Error("HashPassword() returned unhashed password")
	}
}

func TestKeychain_ComparePasswordAndHash(t *testing.T) {
	kc := NewKeychain()
	password := "testPassword123"

	hash, err := kc.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	match, err := kc.ComparePasswordAndHash(password, hash)
	if err != nil {
		t.Fatalf("ComparePasswordAndHash() failed: %v", err)
	}
	if !match {
		t.Error("ComparePasswordAndHash() returned false for matching password")
	}

	mismatch, err := kc.ComparePasswordAndHash("wrongPassword", hash)
	if err != nil {
		t.Fatalf("ComparePasswordAndHash() failed: %v", err)
	}
	if mismatch {
		t.Error("ComparePasswordAndHash() returned true for non-matching password")
	}
}

func TestKeychain_GenerateJWTToken(t *testing.T) {
	kc := NewKeychain()
	options := jwt.JWTTokenOptions{
		SecretKey:         "test-secret",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims: map[string]interface{}{
			"userId": "12345",
			"role":   "admin",
		},
	}

	token, err := kc.GenerateJWTToken(options)
	if err != nil {
		t.Fatalf("GenerateJWTToken() failed: %v", err)
	}
	if token == "" {
		t.Error("GenerateJWTToken() returned empty token")
	}
}

func TestKeychain_ValidateJWTToken(t *testing.T) {
	kc := NewKeychain()
	options := jwt.JWTTokenOptions{
		SecretKey:         "test-secret",
		Issuer:            "test-issuer",
		Audience:          "test-audience",
		Subject:           "test-subject",
		ExpirationSeconds: 3600,
		Claims: map[string]interface{}{
			"userId": "12345",
		},
	}

	token, err := kc.GenerateJWTToken(options)
	if err != nil {
		t.Fatalf("GenerateJWTToken() failed: %v", err)
	}

	claims, err := kc.ValidateJWTToken(token, options)
	if err != nil {
		t.Fatalf("ValidateJWTToken() failed: %v", err)
	}
	if claims == nil {
		t.Error("ValidateJWTToken() returned nil claims")
	}
	if claims["userId"] != "12345" {
		t.Errorf("ValidateJWTToken() userId mismatch: got %v, want %v", claims["userId"], "12345")
	}
	if claims["iss"] != options.Issuer {
		t.Errorf("ValidateJWTToken() issuer mismatch: got %v, want %v", claims["iss"], options.Issuer)
	}
}

func TestKeychain_SetCookie(t *testing.T) {
	kc := NewKeychain()
	w := httptest.NewRecorder()

	options := &cookies.CookieOptions{
		Name:     "test-cookie",
		Value:    "test-value",
		Path:     "/",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
	}

	kc.SetCookie(w, options)

	cookiesList := w.Result().Cookies()
	if len(cookiesList) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookiesList))
	}

	cookie := cookiesList[0]
	if cookie.Name != options.Name {
		t.Errorf("Cookie name mismatch: got %v, want %v", cookie.Name, options.Name)
	}
	if cookie.Value != options.Value {
		t.Errorf("Cookie value mismatch: got %v, want %v", cookie.Value, options.Value)
	}
}

func TestKeychain_GetCookieValue(t *testing.T) {
	kc := NewKeychain()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.AddCookie(&http.Cookie{
		Name:  "test-cookie",
		Value: "test-value",
	})

	value, err := kc.GetCookieValue(req, "test-cookie")
	if err != nil {
		t.Fatalf("GetCookieValue() failed: %v", err)
	}
	if value != "test-value" {
		t.Errorf("Cookie value mismatch: got %v, want %v", value, "test-value")
	}
}

func TestKeychain_GetCookieValue_NotFound(t *testing.T) {
	kc := NewKeychain()
	req := httptest.NewRequest("GET", "http://example.com", nil)

	_, err := kc.GetCookieValue(req, "non-existent-cookie")
	if err == nil {
		t.Error("GetCookieValue() should fail when cookie doesn't exist")
	}
}

func TestKeychain_DeleteCookie(t *testing.T) {
	kc := NewKeychain()
	w := httptest.NewRecorder()

	kc.DeleteCookie(w, "cookie-to-delete")

	cookiesList := w.Result().Cookies()
	if len(cookiesList) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookiesList))
	}

	cookie := cookiesList[0]
	if cookie.Name != "cookie-to-delete" {
		t.Errorf("Cookie name mismatch: got %v, want %v", cookie.Name, "cookie-to-delete")
	}
	if cookie.MaxAge != -1 {
		t.Errorf("Deleted cookie should have MaxAge -1, got %v", cookie.MaxAge)
	}
}

func TestKeychain_GetAuthPolicyHandler(t *testing.T) {
	kc := NewKeychain()

	handler := kc.GetAuthPolicyHandler()

	if handler == nil {
		t.Fatal("GetAuthPolicyHandler() returned nil")
	}

	// Test that the handler works
	policy := rbac.NewAuthPolicy("test-policy", []string{"read", "write"})
	handler.AddPolicy(policy)

	retrievedPolicy, exists := handler.GetPolicy("test-policy")
	if !exists {
		t.Error("Policy should exist after adding through handler")
	}
	if retrievedPolicy.Name != policy.Name {
		t.Errorf("Policy name mismatch: got %v, want %v", retrievedPolicy.Name, policy.Name)
	}
}

func TestKeychain_EndToEndWorkflow(t *testing.T) {
	kc := NewKeychain()

	// 1. Hash a password
	password := "mySecurePassword123"
	hash, err := kc.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	// 2. Verify password
	match, err := kc.ComparePasswordAndHash(password, hash)
	if err != nil {
		t.Fatalf("ComparePasswordAndHash() failed: %v", err)
	}
	if !match {
		t.Error("Password verification failed")
	}

	// 3. Generate JWT token
	jwtOptions := jwt.JWTTokenOptions{
		SecretKey:         "my-secret-key",
		Issuer:            "my-app",
		Audience:          "my-users",
		Subject:           "user-123",
		ExpirationSeconds: 3600,
		Claims: map[string]interface{}{
			"username": "testuser",
			"role":     "admin",
		},
	}
	token, err := kc.GenerateJWTToken(jwtOptions)
	if err != nil {
		t.Fatalf("GenerateJWTToken() failed: %v", err)
	}

	// 4. Validate JWT token
	claims, err := kc.ValidateJWTToken(token, jwtOptions)
	if err != nil {
		t.Fatalf("ValidateJWTToken() failed: %v", err)
	}
	if claims["username"] != "testuser" {
		t.Error("JWT claims validation failed")
	}

	// 5. Set a cookie
	w := httptest.NewRecorder()
	cookieOptions := &cookies.CookieOptions{
		Name:     "session",
		Value:    token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
	}
	kc.SetCookie(w, cookieOptions)

	// 6. Retrieve cookie
	req := httptest.NewRequest("GET", "http://example.com", nil)
	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}
	cookieValue, err := kc.GetCookieValue(req, "session")
	if err != nil {
		t.Fatalf("GetCookieValue() failed: %v", err)
	}
	if cookieValue != token {
		t.Error("Cookie value does not match token")
	}

	// 7. Setup RBAC policies
	handler := kc.GetAuthPolicyHandler()
	adminPolicy := rbac.NewAuthPolicy("admin", []string{"read", "write", "delete"})
	handler.AddPolicy(adminPolicy)

	userPermissions := []string{"read", "write", "delete", "execute"}
	policy, exists := handler.GetPolicy("admin")
	if !exists {
		t.Error("Admin policy should exist")
	}
	if !policy.IsAllowed(userPermissions) {
		t.Error("User should be allowed by admin policy")
	}

	// 8. Delete cookie
	w2 := httptest.NewRecorder()
	kc.DeleteCookie(w2, "session")
	deletedCookie := w2.Result().Cookies()[0]
	if deletedCookie.MaxAge != -1 {
		t.Error("Cookie should be deleted (MaxAge=-1)")
	}
}
