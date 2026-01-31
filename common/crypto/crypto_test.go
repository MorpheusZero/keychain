package crypto

import (
	"testing"
)

func TestNewCryptoService(t *testing.T) {
	service := NewCryptoService()
	if service == nil {
		t.Fatal("NewCryptoService() returned nil")
	}
}

func TestHashPassword_Success(t *testing.T) {
	service := NewCryptoService()
	password := "mySecurePassword123"

	hash, err := service.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword() returned empty hash")
	}
	if hash == password {
		t.Fatal("HashPassword() returned unhashed password")
	}
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	service := NewCryptoService()
	password := ""

	hash, err := service.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() with empty password failed: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword() returned empty hash for empty password")
	}
}

func TestComparePasswordAndHash_Match(t *testing.T) {
	service := NewCryptoService()
	password := "mySecurePassword123"

	hash, err := service.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	match, err := service.ComparePasswordAndHash(password, hash)
	if err != nil {
		t.Fatalf("ComparePasswordAndHash() failed: %v", err)
	}
	if !match {
		t.Fatal("ComparePasswordAndHash() returned false for matching password")
	}
}

func TestComparePasswordAndHash_Mismatch(t *testing.T) {
	service := NewCryptoService()
	password := "mySecurePassword123"
	wrongPassword := "wrongPassword"

	hash, err := service.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	match, err := service.ComparePasswordAndHash(wrongPassword, hash)
	if err != nil {
		t.Fatalf("ComparePasswordAndHash() failed: %v", err)
	}
	if match {
		t.Fatal("ComparePasswordAndHash() returned true for non-matching password")
	}
}

func TestComparePasswordAndHash_InvalidHash(t *testing.T) {
	service := NewCryptoService()
	password := "mySecurePassword123"
	invalidHash := "not-a-valid-hash"

	_, err := service.ComparePasswordAndHash(password, invalidHash)
	if err == nil {
		t.Fatal("ComparePasswordAndHash() should fail with invalid hash")
	}
}
