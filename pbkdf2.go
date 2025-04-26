package passforge

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2PasswordEncoder is a password encoder that uses the PBKDF2 algorithm
type PBKDF2PasswordEncoder struct {
	Iterations   int              // Number of iterations
	KeyLen       int              // Length of the derived key
	SaltLen      int              // Length of the salt
	HashFunc     func() hash.Hash // Hash function to use (e.g., sha256.New)
	HashFuncName string           // Name of the hash function (e.g., "sha256")
}

// PBKDF2Option is a functional option used to configure a PBKDF2PasswordEncoder instance.
type PBKDF2Option func(*PBKDF2PasswordEncoder)

// WithPBKDF2Iterations sets the number of iterations
// Recommended minimum: 10000
// Default: 10000
// See https://en.wikipedia.org/wiki/PBKDF2#Parameters
func WithPBKDF2Iterations(iterations int) PBKDF2Option {
	return func(p *PBKDF2PasswordEncoder) {
		p.Iterations = iterations
	}
}

// WithPBKDF2KeyLen sets the length of the derived key
// Recommended minimum: 16
// Recommended maximum: 256
// Default: 32
// See https://en.wikipedia.org/wiki/PBKDF2#Parameters
//
//	The length of the derived key is expressed in bytes, not bits.
//	For example, 1024 = 1024 bytes = 1024 bits.
func WithPBKDF2KeyLen(keyLen int) PBKDF2Option {
	return func(p *PBKDF2PasswordEncoder) {
		p.KeyLen = keyLen
	}
}

// WithPBKDF2SaltLen sets the length of the salt
// Recommended minimum: 16
// Recommended maximum: 256
// Default: 16
// See https://en.wikipedia.org/wiki/PBKDF2#Parameters
//
//	The length of the salt is expressed in bytes, not bits.
//	For example, 1024 = 1024 bytes = 1024 bits.
func WithPBKDF2SaltLen(saltLen int) PBKDF2Option {
	return func(p *PBKDF2PasswordEncoder) {
		p.SaltLen = saltLen
	}
}

// WithPBKDF2HashFunc sets the hash function to use
// Recommended minimum: 10000
// Default: sha256.New
// See https://en.wikipedia.org/wiki/PBKDF2#Parameters
//
//	The hash function is used to derive the key from the password and the salt.
//	The hash function must be deterministic, i.e., the same input should always produce the same output.
//	The hash function must be cryptographically secure, i.e., it must be impossible to reverse the hash function.
func WithPBKDF2HashFunc(hashFunc func() hash.Hash, hashFuncName string) PBKDF2Option {
	return func(p *PBKDF2PasswordEncoder) {
		p.HashFunc = hashFunc
		p.HashFuncName = hashFuncName
	}
}

// NewPBKDF2PasswordEncoder creates a new PBKDF2PasswordEncoder with default parameters if not specified
func NewPBKDF2PasswordEncoder(opts ...PBKDF2Option) *PBKDF2PasswordEncoder {
	encoder := &PBKDF2PasswordEncoder{
		Iterations:   10000,
		KeyLen:       32,
		SaltLen:      16,
		HashFunc:     sha256.New,
		HashFuncName: "sha256",
	}
	for _, opt := range opts {
		opt(encoder)
	}
	return encoder
}

// Encode hashes the raw password using PBKDF2
func (p *PBKDF2PasswordEncoder) Encode(rawPassword string) (string, error) {
	// Generate random salt
	salt := make([]byte, p.SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// Hash the password with PBKDF2
	hash := pbkdf2.Key([]byte(rawPassword), salt, p.Iterations, p.KeyLen, p.HashFunc)

	// Format: iterations=ITERATIONS,keyLen=KEYLEN,hashFunc=HASHFUNC$BASE64_SALT$BASE64_HASH
	// This format allows us to retrieve the parameters when verifying
	encodedSalt := base64.StdEncoding.EncodeToString(salt)
	encodedHash := base64.StdEncoding.EncodeToString(hash)

	// Use the hash function name from the struct
	return fmt.Sprintf("iterations=%d,keyLen=%d,hashFunc=%s$%s$%s",
		p.Iterations, p.KeyLen, p.HashFuncName, encodedSalt, encodedHash), nil
}

// Verify checks if the raw password matches the encoded password
func (p *PBKDF2PasswordEncoder) Verify(rawPassword, encodedPassword string) (bool, error) {
	// Split the encoded password into parts
	parts := strings.Split(encodedPassword, "$")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid encoded password format")
	}

	// Parse parameters
	var iterations, keyLen int
	var hashFuncName string
	_, err := fmt.Sscanf(parts[0], "iterations=%d,keyLen=%d,hashFunc=%s",
		&iterations, &keyLen, &hashFuncName)
	if err != nil {
		return false, fmt.Errorf("invalid parameter format: %v", err)
	}

	// Determine hash function
	var hashFunc func() hash.Hash
	if hashFuncName == "sha256" {
		hashFunc = sha256.New
	} else {
		return false, fmt.Errorf("unsupported hash function: %s", hashFuncName)
	}

	// Decode salt and hash
	salt, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("invalid salt encoding: %v", err)
	}

	storedHash, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("invalid hash encoding: %v", err)
	}

	// Compute hash with the same parameters and salt
	computedHash := pbkdf2.Key([]byte(rawPassword), salt, iterations, keyLen, hashFunc)

	// Compare hashes using constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(storedHash, computedHash) == 1, nil
}
