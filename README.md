# Cloak

A secure directory encryption CLI tool written in Go. Cloak encrypts entire directories into a single encrypted file using industry-standard cryptography.

## Features

- **AES-256-GCM encryption** - Authenticated encryption for confidentiality and integrity
- **Secure memory handling** - Sensitive data is wiped from memory after use
- **Directory compression** - Directories are compressed with gzip before encryption
- **Path traversal protection** - Prevents zip-slip and similar archive extraction attacks
- **Cross-platform** - Works on Linux, macOS, and Windows
- **Interactive mode** - Tab completion for commands and file paths (beta)

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

### Interactive mode

```bash
cloak -i
```

Starts an interactive shell with autocompletion:

```
Cloak Interactive Mode
Type 'help' for commands, Tab for autocomplete, Ctrl+D to exit

cloak> encrypt ./my_  [Tab]
         my_folder/     Directory
         my_docs/       Directory
```

Features:
- Tab completion for commands (`encrypt`, `decrypt`, `help`, `exit`)
- Smart file path suggestions (directories for encrypt, `.cloak` files for decrypt)
- Arrow keys to navigate suggestions
- Command history

## File Format

Cloak files (`.cloak`) use the following format:

| Field | Size | Description |
|-------|------|-------------|
| Magic | 7 bytes | `CLOAK01` (format identifier + version) |
| Salt | 32 bytes | Random salt for Argon2id |
| Nonce | 12 bytes | Random nonce for AES-GCM |
| Size | 8 bytes | Ciphertext size (big-endian) |
| Ciphertext | Variable | Encrypted tar.gz archive with auth tag |


## License

MIT License
