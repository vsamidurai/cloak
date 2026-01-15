# Cloak

A secure directory encryption CLI tool written in Go. Cloak encrypts entire directories into a single encrypted file using industry-standard cryptography.

## Features

- **AES-256-GCM encryption** - Authenticated encryption for confidentiality and integrity
- **Argon2id key derivation** - Memory-hard password hashing following OWASP recommendations
- **Secure memory handling** - Sensitive data is wiped from memory after use
- **Directory compression** - Directories are compressed with gzip before encryption
- **Path traversal protection** - Prevents zip-slip and similar archive extraction attacks
- **Cross-platform** - Works on Linux, macOS, and Windows

## Installation

### From source

```bash
git clone https://github.com/vsamidurai/cloak.git
cd cloak
make install
```

### Build locally

```bash
make build
./bin/cloak --help
```

## Usage

### Encrypt a directory

```bash
cloak encrypt ./my_folder
```

This creates `my_folder.cloak` in the same location. You will be prompted to enter and confirm a password.

### Decrypt a file

```bash
cloak decrypt ./my_folder.cloak
```

This extracts the original directory structure to the current location.

## File Format

Cloak files (`.cloak`) use the following format:

| Field | Size | Description |
|-------|------|-------------|
| Magic | 7 bytes | `CLOAK01` (format identifier + version) |
| Salt | 32 bytes | Random salt for Argon2id |
| Nonce | 12 bytes | Random nonce for AES-GCM |
| Size | 8 bytes | Ciphertext size (big-endian) |
| Ciphertext | Variable | Encrypted tar.gz archive with auth tag |

## Security

### Cryptographic choices

- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key derivation**: Argon2id with OWASP-recommended parameters
  - Time: 3 iterations
  - Memory: 64 MB
  - Parallelism: 4 threads
- **Random generation**: `crypto/rand` (cryptographically secure)

### Security practices

- Passwords are compared using constant-time comparison
- Sensitive data (passwords, keys) is zeroed after use
- Archive extraction validates paths to prevent traversal attacks

## Development

### Prerequisites

- Go 1.21 or later

### Make targets

```bash
make build          # Build the binary
make test           # Run tests
make test-verbose   # Run tests with verbose output
make test-coverage  # Generate coverage report
make lint           # Run golangci-lint
make fmt            # Format code
make vet            # Run go vet
make tidy           # Tidy go modules
make clean          # Remove build artifacts
make all            # Run fmt, vet, test, and build
make help           # Show available targets
```

### Project structure

```
cloak/
├── cmd/
│   └── cloak/
│       └── main.go         # CLI entry point
├── internal/
│   └── cloak/
│       ├── cloak.go        # Core encryption logic
│       └── cloak_test.go   # Tests
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

## License

MIT License
