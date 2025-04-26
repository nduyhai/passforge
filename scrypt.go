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

// NewScryptPasswordEncoder creates a new ScryptPasswordEncoder with default parameters if not specified
func NewScryptPasswordEncoder(n, r, p, keyLen, saltLen int) *ScryptPasswordEncoder {
	// Set default values if not provided
	if n == 0 {
		n = 16384 // 2^14, recommended minimum
	}
	if r == 0 {
		r = 8
	}
	if p == 0 {
		p = 1
	}
	if keyLen == 0 {
		keyLen = 32
	}
	if saltLen == 0 {
		saltLen = 16
	}

	return &ScryptPasswordEncoder{
		N:       n,
		R:       r,
		P:       p,
		KeyLen:  keyLen,
		SaltLen: saltLen,
	}
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
