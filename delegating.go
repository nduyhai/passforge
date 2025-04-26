package passforge

import (
	"fmt"
	"strings"
)

// DelegatingPasswordEncoder delegates encoding to a default encoder and a map of encoders
type DelegatingPasswordEncoder struct {
	DefaultEncoder   PasswordEncoder
	DefaultEncoderID string
	Encoders         map[string]PasswordEncoder // e.g., "bcrypt" => bcrypt encoder
}

// NewDelegatingPasswordEncoder creates a DelegatingPasswordEncoder with a default encoder and additional encoders. Additional encoders support backward compatibility with existing passwords.
func NewDelegatingPasswordEncoder(defaultEncoderID string, encoders ...PasswordEncoder) (*DelegatingPasswordEncoder, error) {
	if defaultEncoderID == "" {
		return nil, fmt.Errorf("default encoder ID cannot be empty")
	}

	if len(encoders) == 0 {
		return nil, fmt.Errorf("at least one encoder must be provided")
	}

	encoderMap := buildEncoderMap(encoders)

	defaultEncoder, exists := encoderMap[defaultEncoderID]
	if !exists {
		return nil, fmt.Errorf("default encoder '%s' not found in provided encoders", defaultEncoderID)
	}

	return &DelegatingPasswordEncoder{
		DefaultEncoderID: defaultEncoderID,
		DefaultEncoder:   defaultEncoder,
		Encoders:         encoderMap,
	}, nil
}

// buildEncoderMap creates a map of encoder IDs to their implementations
func buildEncoderMap(encoders []PasswordEncoder) map[string]PasswordEncoder {
	encoderMap := make(map[string]PasswordEncoder, len(encoders))
	for _, encoder := range encoders {
		encoderMap[encoder.Name()] = encoder
	}
	return encoderMap
}

// Encode encodes the given raw password using the default encoder and prefixes it with the default encoder's ID.
func (d *DelegatingPasswordEncoder) Encode(rawPassword string) (string, error) {
	encoded, err := d.DefaultEncoder.Encode(rawPassword)
	if err != nil {
		return "", err
	}
	return "{" + d.getDefaultID() + "}" + encoded, nil
}

// Verify checks if the provided raw password matches the encoded password using the appropriate encoder.
// It identifies the encoder by extracting the prefix from the encoded password.
// Returns a boolean indicating a match and an error if verification fails or the encoding is unknown.
func (d *DelegatingPasswordEncoder) Verify(rawPassword, encodedPassword string) (bool, error) {
	id, realEncoded, err := extractIDAndHash(encodedPassword)
	if err != nil {
		return false, err
	}
	encoder, ok := d.Encoders[id]
	if !ok {
		return false, ErrUnknownEncoding
	}
	return encoder.Verify(rawPassword, realEncoded)
}

// getDefaultID retrieves the ID of the default password encoder used for encoding.
func (d *DelegatingPasswordEncoder) getDefaultID() string {
	return d.DefaultEncoderID
}

// extractIDAndHash extracts the ID and hash from an encoded password formatted as {id}hash.
// Returns an error if the format is invalid.
func extractIDAndHash(encodedPassword string) (string, string, error) {
	if len(encodedPassword) == 0 || encodedPassword[0] != '{' {
		return "", "", ErrInvalidFormat
	}
	idx := strings.Index(encodedPassword, "}")
	if idx == -1 {
		return "", "", ErrInvalidFormat
	}
	id := encodedPassword[1:idx]
	hash := encodedPassword[idx+1:]
	return id, hash, nil
}
