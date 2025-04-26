package passforge

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type BcryptPasswordEncoder struct {
	Cost int
}

func NewBcryptPasswordEncoder(cost int) *BcryptPasswordEncoder {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &BcryptPasswordEncoder{Cost: cost}
}

func (b *BcryptPasswordEncoder) Encode(rawPassword string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(rawPassword), b.Cost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

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
