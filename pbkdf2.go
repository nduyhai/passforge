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

// NewPBKDF2PasswordEncoder creates a new PBKDF2PasswordEncoder with default parameters if not specified
func NewPBKDF2PasswordEncoder(iterations, keyLen, saltLen int, hashFunc func() hash.Hash) *PBKDF2PasswordEncoder {
	// Set default values if not provided
	if iterations == 0 {
		iterations = 10000 // Recommended minimum
	}
	if keyLen == 0 {
		keyLen = 32 // 256 bits
	}
	if saltLen == 0 {
		saltLen = 16 // 128 bits
	}

	// Default to SHA-256
	hashFuncName := "sha256"
	if hashFunc == nil {
		hashFunc = sha256.New
	}

	return &PBKDF2PasswordEncoder{
		Iterations:   iterations,
		KeyLen:       keyLen,
		SaltLen:      saltLen,
		HashFunc:     hashFunc,
		HashFuncName: hashFuncName,
	}
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
