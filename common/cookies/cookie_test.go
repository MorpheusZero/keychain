package cookies

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewCookieJar(t *testing.T) {
	jar := NewCookieJar()
	if jar == nil {
		t.Fatal("NewCookieJar() returned nil")
	}
}

func TestSetCookie_AllOptions(t *testing.T) {
	jar := NewCookieJar()
	w := httptest.NewRecorder()

	options := &CookieOptions{
		Name:     "test-cookie",
		Value:    "test-value",
		Path:     "/test",
		Domain:   "example.com",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	jar.SetCookie(w, options)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != options.Name {
		t.Errorf("Cookie name mismatch: got %v, want %v", cookie.Name, options.Name)
	}
	if cookie.Value != options.Value {
		t.Errorf("Cookie value mismatch: got %v, want %v", cookie.Value, options.Value)
	}
	if cookie.Path != options.Path {
		t.Errorf("Cookie path mismatch: got %v, want %v", cookie.Path, options.Path)
	}
	if cookie.Domain != options.Domain {
		t.Errorf("Cookie domain mismatch: got %v, want %v", cookie.Domain, options.Domain)
	}
	if cookie.MaxAge != options.MaxAge {
		t.Errorf("Cookie MaxAge mismatch: got %v, want %v", cookie.MaxAge, options.MaxAge)
	}
	if cookie.Secure != options.Secure {
		t.Errorf("Cookie Secure mismatch: got %v, want %v", cookie.Secure, options.Secure)
	}
	if cookie.HttpOnly != options.HttpOnly {
		t.Errorf("Cookie HttpOnly mismatch: got %v, want %v", cookie.HttpOnly, options.HttpOnly)
	}
	if cookie.SameSite != options.SameSite {
		t.Errorf("Cookie SameSite mismatch: got %v, want %v", cookie.SameSite, options.SameSite)
	}
}

func TestSetCookie_MinimalOptions(t *testing.T) {
	jar := NewCookieJar()
	w := httptest.NewRecorder()

	options := &CookieOptions{
		Name:  "simple-cookie",
		Value: "simple-value",
	}

	jar.SetCookie(w, options)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != options.Name {
		t.Errorf("Cookie name mismatch: got %v, want %v", cookie.Name, options.Name)
	}
	if cookie.Value != options.Value {
		t.Errorf("Cookie value mismatch: got %v, want %v", cookie.Value, options.Value)
	}
}

func TestSetCookie_SameSiteStrict(t *testing.T) {
	jar := NewCookieJar()
	w := httptest.NewRecorder()

	options := &CookieOptions{
		Name:     "samesite-cookie",
		Value:    "test-value",
		SameSite: http.SameSiteStrictMode,
	}

	jar.SetCookie(w, options)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	if cookies[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("Expected SameSite Strict, got %v", cookies[0].SameSite)
	}
}

func TestSetCookie_SameSiteLax(t *testing.T) {
	jar := NewCookieJar()
	w := httptest.NewRecorder()

	options := &CookieOptions{
		Name:     "samesite-cookie",
		Value:    "test-value",
		SameSite: http.SameSiteLaxMode,
	}

	jar.SetCookie(w, options)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	if cookies[0].SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSite Lax, got %v", cookies[0].SameSite)
	}
}

func TestSetCookie_SameSiteNone(t *testing.T) {
	jar := NewCookieJar()
	w := httptest.NewRecorder()

	options := &CookieOptions{
		Name:     "samesite-cookie",
		Value:    "test-value",
		SameSite: http.SameSiteNoneMode,
	}

	jar.SetCookie(w, options)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	if cookies[0].SameSite != http.SameSiteNoneMode {
		t.Errorf("Expected SameSite None, got %v", cookies[0].SameSite)
	}
}

func TestGetCookieValue_Success(t *testing.T) {
	jar := NewCookieJar()

	// Create a request with a cookie
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.AddCookie(&http.Cookie{
		Name:  "test-cookie",
		Value: "test-value",
	})

	value, err := jar.GetCookieValue(req, "test-cookie")
	if err != nil {
		t.Fatalf("GetCookieValue() failed: %v", err)
	}
	if value != "test-value" {
		t.Errorf("Cookie value mismatch: got %v, want %v", value, "test-value")
	}
}

func TestGetCookieValue_NotFound(t *testing.T) {
	jar := NewCookieJar()

	// Create a request without the cookie we're looking for
	req := httptest.NewRequest("GET", "http://example.com", nil)

	_, err := jar.GetCookieValue(req, "non-existent-cookie")
	if err == nil {
		t.Fatal("GetCookieValue() should fail when cookie doesn't exist")
	}
}

func TestDeleteCookie(t *testing.T) {
	jar := NewCookieJar()
	w := httptest.NewRecorder()

	jar.DeleteCookie(w, "cookie-to-delete")

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "cookie-to-delete" {
		t.Errorf("Cookie name mismatch: got %v, want %v", cookie.Name, "cookie-to-delete")
	}
	if cookie.Value != "" {
		t.Errorf("Deleted cookie should have empty value, got %v", cookie.Value)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("Deleted cookie should have MaxAge -1, got %v", cookie.MaxAge)
	}
	if cookie.Path != "/" {
		t.Errorf("Deleted cookie should have Path /, got %v", cookie.Path)
	}
}
