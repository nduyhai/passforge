# PassForge

PassForge is a Go library for secure password encoding and verification. It provides a collection of password encoders implementing various hashing algorithms with a consistent interface.

## Features

- Multiple password encoding algorithms:
  - **BCrypt**: Industry-standard adaptive hashing function
  - **SCrypt**: Memory-hard password hashing function
  - **Argon2**: Winner of the Password Hashing Competition, considered the most secure option
  - **PBKDF2**: Password-Based Key Derivation Function 2, widely used for password hashing
  - **NoOp**: No-operation encoder for testing (not for production use)
- **Delegating encoder**: Allows using multiple encoders with automatic algorithm detection
- Configurable parameters for each algorithm
- Simple, consistent API across all encoders

## Installation

```bash
go get github.com/nduyhai/passforge
```

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/nduyhai/passforge" 
)

func main() {
    // Create a BCrypt encoder with default cost
    encoder := passforge.NewBcryptPasswordEncoder()

    // Encode a password
    encoded, err := encoder.Encode("mySecurePassword")
    if err != nil {
        panic(err)
    }
    fmt.Println("Encoded password:", encoded)

    // Verify a password
    match, err := encoder.Verify("mySecurePassword", encoded)
    if err != nil {
        panic(err)
    }

    if match {
        fmt.Println("Password matches!")
    } else {
        fmt.Println("Password does not match!")
    }
}
```

### Using Different Encoders

#### BCrypt Encoder

```go
// Example: Create a BCrypt encoder with custom cost (higher is more secure but slower)
bcryptEncoder := passforge.NewBcryptPasswordEncoder(passforge.WithCost(12))
```

#### SCrypt Encoder

```go
// Example: Create an SCrypt encoder with custom parameters
// Parameters: N (CPU/memory cost), r (block size), p (parallelization), keyLen, saltLen
scryptEncoder := passforge.NewScryptPasswordEncoder(passforge.WithScryptN(16384), passforge.WithScryptR(8), passforge.WithScryptP(1), passforge.WithScryptKeyLen(32), passforge.WithScryptSaltLen(16))

// Or use default parameters
scryptEncoder := passforge.NewScryptPasswordEncoder()
```

#### Argon2 Encoder

```go
// Example: Create an Argon2 encoder with custom parameters
// Parameters: time, memory, threads, keyLen, saltLen
argon2Encoder := passforge.NewArgon2PasswordEncoder(passforge.WithArgon2Time(1), passforge.WithArgon2Memory(64*1024), passforge.WithArgon2Threads(4), passforge.WithArgon2KeyLen(32), passforge.WithArgon2SaltLen(16))

// Or use default parameters
argon2Encoder := passforge.NewArgon2PasswordEncoder()
```

#### PBKDF2 Encoder

```go
// Example: Create a PBKDF2 encoder with custom parameters
// Parameters: iterations, keyLen, saltLen, hashFunc
import "crypto/sha256"
pbkdf2Encoder := passforge.NewPBKDF2PasswordEncoder(passforge.WithPBKDF2Iterations(1000), passforge.WithPBKDF2KeyLen(32), passforge.WithPBKDF2SaltLen(16), passforge.WithPBKDF2HashFunc(sha256.New, "sha256"))

// Or use default parameters (SHA-256 hash function is used by default)
pbkdf2Encoder := passforge.NewPBKDF2PasswordEncoder()
```

#### NoOp Encoder (for testing only)

```go
// Example: Create a NoOp encoder (stores passwords in plain text - DO NOT USE IN PRODUCTION)
noopEncoder := passforge.NewNoOpPasswordEncoder()
```

### Delegating Password Encoder

The delegating encoder allows you to use multiple encoders and automatically detect which one to use for verification:

```go
// Example: Using the delegating password encoder

// First, create individual encoders
bcryptEncoder := passforge.NewBcryptPasswordEncoder()
argon2Encoder := passforge.NewArgon2PasswordEncoder()
pbkdf2Encoder := passforge.NewPBKDF2PasswordEncoder()

// Create a map of encoders with their IDs
encoders := map[string]passforge.PasswordEncoder{
    "bcrypt": bcryptEncoder,
    "argon2": argon2Encoder,
    "pbkdf2": pbkdf2Encoder,
}

// Create a delegating encoder with bcrypt as the default
delegatingEncoder := passforge.NewDelegatingPasswordEncoder("bcrypt", encoders)

// Encode a password (will use the default encoder - bcrypt in this case)
encoded, _ := delegatingEncoder.Encode("myPassword")
// Result will be something like: {bcrypt}$2a$10$...

// Verify a password (will automatically detect the encoder from the prefix)
match, _ := delegatingEncoder.Verify("myPassword", encoded)

// You can also verify passwords encoded with any of the configured encoders
argon2Password := "{argon2}time=1,memory=65536,threads=4,keyLen=32$KwuPJjEdIoq1nSZWGsrO6w==$5OqqfWw4e/s2UJpnvFOerxMynrBV9OGDRrGsu60RS+I="
pbkdf2Password := "{pbkdf2}iterations=10000,keyLen=32,hashFunc=sha256$+uTgq1Ll15T2MloP8UJdyQ==$G+nDsgsyWuVoQrAy8DNJXXKVTWGr9P1gmM/YNxQxyEE="
match, _ = delegatingEncoder.Verify("myPassword", argon2Password)
match, _ = delegatingEncoder.Verify("myPassword", pbkdf2Password)
```

## Development

### Prerequisites

- Go 1.24 or higher

### Available Make Commands

The project includes a Makefile with the following commands:

```bash
# Build the project
make build

# Run tests
make test

# Run tests with coverage
make test-coverage

# Clean build artifacts
make clean

# Install dependencies
make deps

# Run linter
make lint

# Format code
make fmt

# Verify dependencies
make verify

# Show help
make help
```

### Continuous Integration

This project uses GitHub Actions for continuous integration. The workflow includes:

- Running tests on multiple Go versions

The configuration files are:
- `.github/workflows/ci.yml`: GitHub Actions workflow configuration
- `.golangci.yml`: golangci-lint configuration

## License

This project is licensed under the MIT License - see the LICENSE file for details.
