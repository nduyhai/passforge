package passforge

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// BcryptPasswordEncoder is a password encoder that uses the bcrypt algorithm
type BcryptPasswordEncoder struct {
	Cost int
}

// BcryptOption is a function that configures a BcryptPasswordEncoder.
// See https://pkg.go.dev/golang.org/x/crypto/bcrypt#GenerateFromPassword for the list of available options.
//
//	The default cost is 10.
//	The minimum cost is 4.
//	The maximum cost is 31.
//	The recommended cost is 12.
//	The recommended cost is 14.
type BcryptOption func(*BcryptPasswordEncoder)

// WithCost sets the cost of the bcrypt algorithm.
// Recommended minimum: 4
// Recommended maximum: 31
// Default: 10
// See https://pkg.go.dev/golang.org/x/crypto/bcrypt#GenerateFromPassword for the list of available options.
//
//	The default cost is 10.
//	The minimum cost is 4.
func WithCost(cost int) BcryptOption {
	return func(b *BcryptPasswordEncoder) {
		b.Cost = cost
	}
}

// NewBcryptPasswordEncoder creates a new BcryptPasswordEncoder with default parameters if not specified.
func NewBcryptPasswordEncoder(opts ...BcryptOption) *BcryptPasswordEncoder {
	encoder := &BcryptPasswordEncoder{Cost: bcrypt.DefaultCost}
	for _, opt := range opts {
		opt(encoder)
	}
	return encoder
}

// Encode hashes the raw password using bcrypt.
func (b *BcryptPasswordEncoder) Encode(rawPassword string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(rawPassword), b.Cost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// Verify checks if the raw password matches the encoded password.
func (b *BcryptPasswordEncoder) Verify(rawPassword, encodedPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(encodedPassword), []byte(rawPassword))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Name returns the name of the encoder.
func (b *BcryptPasswordEncoder) Name() string {
	return "bcrypt"
}
