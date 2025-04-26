package passforge

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// ScryptPasswordEncoder is a password encoder that uses the scrypt algorithm
type ScryptPasswordEncoder struct {
	N       int // CPU/memory cost parameter (logN)
	R       int // Block size parameter
	P       int // Parallelization parameter
	KeyLen  int // Length of the derived key
	SaltLen int // Length of the salt
}

// ScryptOption is a functional option used to configure a ScryptPasswordEncoder instance.
type ScryptOption func(*ScryptPasswordEncoder)

// WithScryptN sets the CPU/memory cost parameter (logN)
// Recommended minimum: 10
// Recommended maximum: 31
// Default: 16384
// See https://en.wikipedia.org/wiki/Scrypt#Parameters
//
//	The CPU/memory cost parameter (logN) is the logarithm of the memory cost (in MiB) and the CPU cost (in ms).
//	The memory cost (in MiB) is the memory usage of the scrypt function, measured in MiB.
func WithScryptN(n int) ScryptOption {
	return func(s *ScryptPasswordEncoder) {
		s.N = n
	}
}

// WithScryptR sets the block size parameter
// Recommended minimum: 1
// Recommended maximum: 255
// Default: 8
// See https://en.wikipedia.org/wiki/Scrypt#Parameters
//
//	The block size parameter (r) is the block size of the scrypt function, measured in bytes.
//	The block size is the number of bytes processed by the scrypt function at a time.
func WithScryptR(r int) ScryptOption {
	return func(s *ScryptPasswordEncoder) {
		s.R = r
	}
}

// WithScryptP sets the parallelization parameter
// Recommended minimum: 1
// Recommended maximum: 255
// Default: 1
// See https://en.wikipedia.org/wiki/Scrypt#Parameters
//
//	The parallelization parameter (p) is the number of threads used by the scrypt function.
//	The parallelization parameter is the number of threads used by the scrypt function.
func WithScryptP(p int) ScryptOption {
	return func(s *ScryptPasswordEncoder) {
		s.P = p
	}
}

// WithScryptKeyLen sets the length of the derived key
// Recommended minimum: 16
// Recommended maximum: 2^32-1
// Default: 32
// See https://en.wikipedia.org/wiki/Scrypt#Parameters
//
//	The length of the derived key is the length of the derived key in bytes.
//	The length of the derived key is the length of the derived key in bytes.
func WithScryptKeyLen(keyLen int) ScryptOption {
	return func(s *ScryptPasswordEncoder) {
		s.KeyLen = keyLen
	}
}

// WithScryptSaltLen sets the length of the salt
// Recommended minimum: 16
// Recommended maximum: 2^32-1
// Default: 16
// See https://en.wikipedia.org/wiki/Scrypt#Parameters
//
//	The length of the salt is the length of the salt in bytes.
//	The length of the salt is the length of the salt in bytes.
func WithScryptSaltLen(saltLen int) ScryptOption {
	return func(s *ScryptPasswordEncoder) {
		s.SaltLen = saltLen
	}
}

// NewScryptPasswordEncoder creates a new ScryptPasswordEncoder with default parameters if not specified
func NewScryptPasswordEncoder(opts ...ScryptOption) *ScryptPasswordEncoder {
	encoder := &ScryptPasswordEncoder{
		N:       16384, // 2^14, recommended minimum
		R:       8,
		P:       1,
		KeyLen:  32,
		SaltLen: 16,
	}
	for _, opt := range opts {
		opt(encoder)
	}
	return encoder
}

// Encode hashes the raw password using scrypt
func (s *ScryptPasswordEncoder) Encode(rawPassword string) (string, error) {
	// Generate random salt
	salt := make([]byte, s.SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// Hash the password with scrypt
	hash, err := scrypt.Key([]byte(rawPassword), salt, s.N, s.R, s.P, s.KeyLen)
	if err != nil {
		return "", err
	}

	// Format: N=N,r=R,p=P,keyLen=KEYLEN$BASE64_SALT$BASE64_HASH
	// This format allows us to retrieve the parameters when verifying
	encodedSalt := base64.StdEncoding.EncodeToString(salt)
	encodedHash := base64.StdEncoding.EncodeToString(hash)

	return fmt.Sprintf("N=%d,r=%d,p=%d,keyLen=%d$%s$%s",
		s.N, s.R, s.P, s.KeyLen, encodedSalt, encodedHash), nil
}

// Verify checks if the raw password matches the encoded password
func (s *ScryptPasswordEncoder) Verify(rawPassword, encodedPassword string) (bool, error) {
	// Split the encoded password into parts
	parts := strings.Split(encodedPassword, "$")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid encoded password format")
	}

	// Parse parameters
	var n, r, p, keyLen int
	_, err := fmt.Sscanf(parts[0], "N=%d,r=%d,p=%d,keyLen=%d", &n, &r, &p, &keyLen)
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
	computedHash, err := scrypt.Key([]byte(rawPassword), salt, n, r, p, keyLen)
	if err != nil {
		return false, err
	}

	// Compare hashes using constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(storedHash, computedHash) == 1, nil
}

// Name returns the name of the encoder.
func (s *ScryptPasswordEncoder) Name() string {
	return "scrypt"
}
