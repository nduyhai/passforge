package passforge

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

// Argon2PasswordEncoder is a password encoder that uses the Argon2id algorithm
type Argon2PasswordEncoder struct {
	Time    uint32 // Number of iterations
	Memory  uint32 // Memory usage in KiB
	Threads uint8  // Number of threads
	KeyLen  uint32 // Length of the derived key
	SaltLen uint32 // Length of the salt
}

// NewArgon2PasswordEncoder creates a new Argon2PasswordEncoder with default parameters if not specified
func NewArgon2PasswordEncoder(time, memory uint32, threads uint8, keyLen, saltLen uint32) *Argon2PasswordEncoder {
	// Set default values if not provided
	if time == 0 {
		time = 1
	}
	if memory == 0 {
		memory = 64 * 1024 // 64MB
	}
	if threads == 0 {
		threads = 4
	}
	if keyLen == 0 {
		keyLen = 32
	}
	if saltLen == 0 {
		saltLen = 16
	}

	return &Argon2PasswordEncoder{
		Time:    time,
		Memory:  memory,
		Threads: threads,
		KeyLen:  keyLen,
		SaltLen: saltLen,
	}
}

// Encode hashes the raw password using Argon2id
func (a *Argon2PasswordEncoder) Encode(rawPassword string) (string, error) {
	// Generate random salt
	salt := make([]byte, a.SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// Hash the password with Argon2id
	hash := argon2.IDKey([]byte(rawPassword), salt, a.Time, a.Memory, a.Threads, a.KeyLen)

	// Format: time=TIME,memory=MEMORY,threads=THREADS,keyLen=KEYLEN$BASE64_SALT$BASE64_HASH
	// This format allows us to retrieve the parameters when verifying
	encodedSalt := base64.StdEncoding.EncodeToString(salt)
	encodedHash := base64.StdEncoding.EncodeToString(hash)

	return fmt.Sprintf("time=%d,memory=%d,threads=%d,keyLen=%d$%s$%s",
		a.Time, a.Memory, a.Threads, a.KeyLen, encodedSalt, encodedHash), nil
}

// Verify checks if the raw password matches the encoded password
func (a *Argon2PasswordEncoder) Verify(rawPassword, encodedPassword string) (bool, error) {
	// Split the encoded password into parts
	parts := strings.Split(encodedPassword, "$")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid encoded password format")
	}

	// Parse parameters
	var time, memory, keyLen uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[0], "time=%d,memory=%d,threads=%d,keyLen=%d",
		&time, &memory, &threads, &keyLen)
	if err != nil {
		return false, fmt.Errorf("invalid parameter format: %v", err)
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
	computedHash := argon2.IDKey([]byte(rawPassword), salt, time, memory, threads, keyLen)

	// Compare hashes using constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(storedHash, computedHash) == 1, nil
}
