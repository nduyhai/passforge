package passforge

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2PasswordEncoder is a password encoder that uses the Argon2id algorithm
type Argon2PasswordEncoder struct {
	Time    uint32 // Number of iterations
	Memory  uint32 // Memory usage in KiB
	Threads uint8  // Number of threads
	KeyLen  uint32 // Length of the derived key
	SaltLen uint32 // Length of the salt
}

// Argon2Option is a function that configures an Argon2PasswordEncoder
type Argon2Option func(*Argon2PasswordEncoder)

// WithArgon2Time sets the number of iterations
// Recommended minimum: 1
// Recommended maximum: 2^32-1
// Default: 1
// See https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.md#parameters
func WithArgon2Time(time uint32) Argon2Option {
	return func(a *Argon2PasswordEncoder) {
		a.Time = time
	}
}

// WithArgon2Memory sets the memory usage in KiB
// Recommended minimum: 8
// Recommended maximum: 2^32-1
// Default: 64MB
// See https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.md#parameters
// Note: The memory usage is expressed in KiB, not MiB.
//
//	This is because the memory usage is expressed in bytes, not kilobytes.
//	For example, 1024 * 1024 = 1048576 bytes = 1 MiB.
func WithArgon2Memory(memory uint32) Argon2Option {
	return func(a *Argon2PasswordEncoder) {
		a.Memory = memory
	}
}

// WithArgon2Threads sets the number of threads
// Recommended minimum: 1
// Recommended maximum: 255
// Default: 4
// See https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.md#parameters
// Note: The number of threads is expressed as a byte, not a number.
//
//	This is because the number of threads is expressed as a power of two.
//	For example, 2^4 = 16 threads.
func WithArgon2Threads(threads uint8) Argon2Option {
	return func(a *Argon2PasswordEncoder) {
		a.Threads = threads
	}
}

// WithArgon2KeyLen sets the length of the derived key
// Recommended minimum: 16
// Recommended maximum: 2^32-1
// Default: 32
// See https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.md#parameters
// Note: The length of the derived key is expressed in bytes, not bits.
//
//	This is because the length of the derived key is expressed in bytes, not bits.
//	For example, 1024 = 1024 bytes = 1024 bits.
func WithArgon2KeyLen(keyLen uint32) Argon2Option {
	return func(a *Argon2PasswordEncoder) {
		a.KeyLen = keyLen
	}
}

// WithArgon2SaltLen sets the length of the salt
// Recommended minimum: 16
// Recommended maximum: 2^32-1
// Default: 16
// See https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.md#parameters
// Note: The length of the salt is expressed in bytes, not bits.
//
//	This is because the length of the salt is expressed in bytes, not bits.
//	For example, 1024 = 1024 bytes = 1024 bits.
func WithArgon2SaltLen(saltLen uint32) Argon2Option {
	return func(a *Argon2PasswordEncoder) {
		a.SaltLen = saltLen
	}
}

// NewArgon2PasswordEncoder creates a new Argon2PasswordEncoder with default parameters if not specified
func NewArgon2PasswordEncoder(opts ...Argon2Option) *Argon2PasswordEncoder {
	// Set default values if not provided
	encoder := &Argon2PasswordEncoder{
		Time:    1,
		Memory:  64 * 1024, // 64MB
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
	for _, opt := range opts {
		opt(encoder)
	}
	return encoder
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

// Name returns the name of the encoder.
func (a *Argon2PasswordEncoder) Name() string {
	return "argon2"
}
