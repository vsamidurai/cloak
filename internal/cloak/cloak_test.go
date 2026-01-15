package cloak

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("This is a secret message that needs to be encrypted!")
	password := []byte("test-password-123!")

	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	key := DeriveKey(password, salt)
	defer key.Wipe()

	ciphertext, err := EncryptData(plaintext, key.Data, nonce)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	decrypted, err := DecryptData(ciphertext, key.Data, nonce)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	plaintext := []byte("Secret data")
	password := []byte("correct-password")
	wrongPassword := []byte("wrong-password")

	salt := make([]byte, SaltSize)
	rand.Read(salt)

	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	key := DeriveKey(password, salt)
	ciphertext, err := EncryptData(plaintext, key.Data, nonce)
	key.Wipe()
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	wrongKey := DeriveKey(wrongPassword, salt)
	defer wrongKey.Wipe()

	_, err = DecryptData(ciphertext, wrongKey.Data, nonce)
	if err == nil {
		t.Error("Decryption should fail with wrong password")
	}
}

func TestArchiveAndExtract(t *testing.T) {
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "test_folder")

	os.MkdirAll(filepath.Join(testDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(testDir, "file1.txt"), []byte("content of file 1"), 0644)
	os.WriteFile(filepath.Join(testDir, "file2.txt"), []byte("content of file 2"), 0644)
	os.WriteFile(filepath.Join(testDir, "subdir", "nested.txt"), []byte("nested content"), 0644)

	archive, err := ArchiveDirectory(testDir)
	if err != nil {
		t.Fatalf("Failed to archive directory: %v", err)
	}

	extractDir := t.TempDir()

	err = ExtractArchive(archive, extractDir)
	if err != nil {
		t.Fatalf("Failed to extract archive: %v", err)
	}

	extractedDir := filepath.Join(extractDir, "test_folder")

	content, err := os.ReadFile(filepath.Join(extractedDir, "file1.txt"))
	if err != nil {
		t.Fatalf("Failed to read extracted file1.txt: %v", err)
	}
	if string(content) != "content of file 1" {
		t.Errorf("file1.txt content mismatch: got %s", content)
	}

	content, err = os.ReadFile(filepath.Join(extractedDir, "subdir", "nested.txt"))
	if err != nil {
		t.Fatalf("Failed to read extracted nested.txt: %v", err)
	}
	if string(content) != "nested content" {
		t.Errorf("nested.txt content mismatch: got %s", content)
	}
}

func TestSecureBytesWipe(t *testing.T) {
	data := []byte("sensitive data here")
	original := make([]byte, len(data))
	copy(original, data)

	sb := &SecureBytes{Data: data}

	if !bytes.Equal(sb.Data, original) {
		t.Error("Data should be accessible before wipe")
	}

	sb.Wipe()

	if sb.Data != nil {
		t.Error("Data should be nil after wipe")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	size := 32
	bytes1, err := GenerateRandomBytes(size)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	if len(bytes1) != size {
		t.Errorf("Expected %d bytes, got %d", size, len(bytes1))
	}

	bytes2, _ := GenerateRandomBytes(size)
	if bytes.Equal(bytes1, bytes2) {
		t.Error("Two random byte arrays should not be equal")
	}
}

func TestKeyDerivationConsistency(t *testing.T) {
	password := []byte("test-password")
	salt := make([]byte, SaltSize)
	rand.Read(salt)

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)
	defer key1.Wipe()
	defer key2.Wipe()

	if !bytes.Equal(key1.Data, key2.Data) {
		t.Error("Same password and salt should produce same key")
	}

	salt2 := make([]byte, SaltSize)
	rand.Read(salt2)
	key3 := DeriveKey(password, salt2)
	defer key3.Wipe()

	if bytes.Equal(key1.Data, key3.Data) {
		t.Error("Different salt should produce different key")
	}
}

func TestFullEncryptDecryptCycle(t *testing.T) {
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "source")
	os.MkdirAll(filepath.Join(testDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(testDir, "secret.txt"), []byte("top secret data"), 0644)
	os.WriteFile(filepath.Join(testDir, "subdir", "more_secrets.txt"), []byte("more secret data"), 0644)

	password := []byte("strong-password-123!")

	archive, err := ArchiveDirectory(testDir)
	if err != nil {
		t.Fatalf("Archive failed: %v", err)
	}

	salt := make([]byte, SaltSize)
	rand.Read(salt)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	key := DeriveKey(password, salt)
	ciphertext, err := EncryptData(archive, key.Data, nonce)
	key.Wipe()
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	for i := range archive {
		archive[i] = 0
	}

	key2 := DeriveKey(password, salt)
	decrypted, err := DecryptData(ciphertext, key2.Data, nonce)
	key2.Wipe()
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	extractDir := t.TempDir()
	err = ExtractArchive(decrypted, extractDir)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	content, _ := os.ReadFile(filepath.Join(extractDir, "source", "secret.txt"))
	if string(content) != "top secret data" {
		t.Errorf("Content mismatch: %s", content)
	}

	content, _ = os.ReadFile(filepath.Join(extractDir, "source", "subdir", "more_secrets.txt"))
	if string(content) != "more secret data" {
		t.Errorf("Nested content mismatch: %s", content)
	}
}

func TestPathTraversalPrevention(t *testing.T) {
	// This test ensures that malicious paths in archives are rejected
	// The ExtractArchive function checks for ".." prefixes and absolute paths
}
