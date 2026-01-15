// Package cloak provides secure directory encryption using AES-256-GCM with Argon2id key derivation.
package cloak

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	// MagicBytes identifies the file format and version.
	MagicBytes = "CLOAK01"

	// SaltSize is the size of the salt for Argon2id (256-bit).
	SaltSize = 32

	// NonceSize is the size of the nonce for AES-GCM (96-bit).
	NonceSize = 12

	// KeySize is the size of the encryption key (256-bit for AES-256).
	KeySize = 32

	// Argon2id parameters (OWASP recommendations).
	argonTime    = 3         // Number of iterations
	argonMemory  = 64 * 1024 // 64 MB memory
	argonThreads = 4         // Parallelism
)

// SecureBytes wraps a byte slice and provides secure wiping.
type SecureBytes struct {
	Data []byte
}

// Wipe securely clears the byte slice from memory.
func (s *SecureBytes) Wipe() {
	if s.Data != nil {
		for i := range s.Data {
			s.Data[i] = 0
		}
		runtime.KeepAlive(s.Data)
		s.Data = nil
	}
}

// ReadPasswordSecure reads a password from terminal without echoing.
func ReadPasswordSecure(prompt string) (*SecureBytes, error) {
	fmt.Print(prompt)

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("password input requires a terminal (stdin must be a TTY)")
	}

	password, err := term.ReadPassword(fd)
	fmt.Println()

	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	return &SecureBytes{Data: password}, nil
}

// DeriveKey uses Argon2id to derive an encryption key from password and salt.
func DeriveKey(password, salt []byte) *SecureBytes {
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, KeySize)
	return &SecureBytes{Data: key}
}

// GenerateRandomBytes generates cryptographically secure random bytes.
func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// ArchiveDirectory creates a tar.gz archive of the directory in memory.
func ArchiveDirectory(dirPath string) ([]byte, error) {
	var buf bytes.Buffer

	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	baseName := filepath.Base(dirPath)

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header: %w", err)
		}

		relPath, err := filepath.Rel(filepath.Dir(dirPath), path)
		if err != nil {
			return err
		}
		header.Name = relPath

		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			header.Linkname = link
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return fmt.Errorf("failed to write file to archive: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	if err := tarWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}

	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	fmt.Printf("Archived directory '%s' (%d bytes compressed)\n", baseName, buf.Len())
	return buf.Bytes(), nil
}

// ExtractArchive extracts a tar.gz archive to the specified directory.
func ExtractArchive(data []byte, destDir string) error {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		cleanName := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			return fmt.Errorf("invalid path in archive: %s", header.Name)
		}

		targetPath := filepath.Join(destDir, cleanName)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return err
			}

			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("failed to write file: %w", err)
			}
			file.Close()

		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return err
			}

			os.Remove(targetPath)
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		}
	}

	return nil
}

// EncryptData encrypts data using AES-256-GCM.
func EncryptData(plaintext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptData decrypts data using AES-256-GCM.
func DecryptData(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: invalid password or corrupted file")
	}

	return plaintext, nil
}

// Encrypt encrypts a folder and writes the encrypted output to a .cloak file.
func Encrypt(folderPath string) error {
	info, err := os.Stat(folderPath)
	if err != nil {
		return fmt.Errorf("cannot access folder: %w", err)
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}

	absPath, err := filepath.Abs(folderPath)
	if err != nil {
		return err
	}
	outputPath := strings.TrimSuffix(absPath, string(filepath.Separator)) + ".cloak"

	if _, err := os.Stat(outputPath); err == nil {
		return fmt.Errorf("output file already exists: %s", outputPath)
	}

	password, err := ReadPasswordSecure("Enter encryption password: ")
	if err != nil {
		return err
	}
	defer password.Wipe()

	confirmPassword, err := ReadPasswordSecure("Confirm password: ")
	if err != nil {
		return err
	}
	defer confirmPassword.Wipe()

	if subtle.ConstantTimeCompare(password.Data, confirmPassword.Data) != 1 {
		return errors.New("passwords do not match")
	}

	fmt.Println("Archiving directory...")

	archive, err := ArchiveDirectory(folderPath)
	if err != nil {
		return fmt.Errorf("failed to archive directory: %w", err)
	}

	salt, err := GenerateRandomBytes(SaltSize)
	if err != nil {
		return err
	}

	nonce, err := GenerateRandomBytes(NonceSize)
	if err != nil {
		return err
	}

	fmt.Println("Deriving encryption key (this may take a moment)...")

	key := DeriveKey(password.Data, salt)
	defer key.Wipe()

	fmt.Println("Encrypting data...")

	ciphertext, err := EncryptData(archive, key.Data, nonce)
	if err != nil {
		return err
	}

	for i := range archive {
		archive[i] = 0
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if _, err := outFile.Write([]byte(MagicBytes)); err != nil {
		return err
	}
	if _, err := outFile.Write(salt); err != nil {
		return err
	}
	if _, err := outFile.Write(nonce); err != nil {
		return err
	}

	sizeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBytes, uint64(len(ciphertext)))
	if _, err := outFile.Write(sizeBytes); err != nil {
		return err
	}

	if _, err := outFile.Write(ciphertext); err != nil {
		return err
	}

	fmt.Printf("Successfully encrypted to: %s\n", outputPath)
	fmt.Printf("Original size: %d bytes, Encrypted size: %d bytes\n", len(archive), len(ciphertext))
	return nil
}

// Decrypt decrypts a .cloak file and extracts the contents.
func Decrypt(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}
	if info.IsDir() {
		return errors.New("path is a directory, expected encrypted file")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	headerSize := len(MagicBytes) + SaltSize + NonceSize + 8
	if len(data) < headerSize {
		return errors.New("invalid file: too small to be a valid encrypted file")
	}

	if string(data[:len(MagicBytes)]) != MagicBytes {
		return errors.New("invalid file: not a valid .cloak file")
	}

	offset := len(MagicBytes)
	salt := data[offset : offset+SaltSize]
	offset += SaltSize

	nonce := data[offset : offset+NonceSize]
	offset += NonceSize

	expectedSize := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	ciphertext := data[offset:]

	if uint64(len(ciphertext)) != expectedSize {
		return errors.New("invalid file: size mismatch, file may be corrupted")
	}

	password, err := ReadPasswordSecure("Enter decryption password: ")
	if err != nil {
		return err
	}
	defer password.Wipe()

	fmt.Println("Deriving decryption key (this may take a moment)...")

	key := DeriveKey(password.Data, salt)
	defer key.Wipe()

	fmt.Println("Decrypting data...")

	archive, err := DecryptData(ciphertext, key.Data, nonce)
	if err != nil {
		return err
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}
	outputDir := filepath.Dir(absPath)

	fmt.Println("Extracting files...")

	if err := ExtractArchive(archive, outputDir); err != nil {
		return fmt.Errorf("failed to extract archive: %w", err)
	}

	for i := range archive {
		archive[i] = 0
	}

	fmt.Printf("Successfully decrypted to: %s\n", outputDir)
	return nil
}
