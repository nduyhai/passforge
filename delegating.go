package passforge

import "strings"

// DelegatingPasswordEncoder delegates encoding to a default encoder and a map of encoders
type DelegatingPasswordEncoder struct {
	DefaultEncoder PasswordEncoder
	Encoders       map[string]PasswordEncoder // e.g., "bcrypt" => bcrypt encoder
}

// NewDelegatingPasswordEncoder creates a new DelegatingPasswordEncoder with the specified default encoder and encoders.
// The default encoder is used when encoding a password.
// The encoders are used when verifying a password.
// The default encoder must be present in the encoders map.
// The default encoder ID is used when encoding a password.
// The default encoder ID is used when verifying a password.
// The default encoder ID must be present in the encoders map.
// The default encoder ID must be the same as the key of the default encoder in the encoders map.
func NewDelegatingPasswordEncoder(defaultEncoderID string, encoders map[string]PasswordEncoder) *DelegatingPasswordEncoder {
	return &DelegatingPasswordEncoder{
		DefaultEncoder: encoders[defaultEncoderID],
		Encoders:       encoders,
	}
}

// Encode delegates encoding to the default encoder.
// The default encoder ID is used as the prefix of the encoded password.
// The default encoder ID must be present in the encoders map.
// The default encoder ID must be the same as the key of the default encoder in the encoders map.
//
// Example:
//
//	d := NewDelegatingPasswordEncoder("bcrypt", map[string]PasswordEncoder{})
func (d *DelegatingPasswordEncoder) Encode(rawPassword string) (string, error) {
	encoded, err := d.DefaultEncoder.Encode(rawPassword)
	if err != nil {
		return "", err
	}
	return "{" + d.getDefaultID() + "}" + encoded, nil
}

// Verify delegates verification to the encoder that matches the ID in the encoded password.
// The ID is extracted from the encoded password using extractIDAndHash.
// The ID must be present in the encoders map.
//
// Example:
//
//	d := NewDelegatingPasswordEncoder("bcrypt", map[string]PasswordEncoder{})
//	err := d.Verify("password", "{bcrypt}xxxxhashxxxx")
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

// getDefaultID returns the default encoder ID.
// The default encoder ID must be present in the encoders map.
// The default encoder ID must be the same as the key of the default encoder in the encoders map.
//
// Example:
//
//	d := NewDelegatingPasswordEncoder("bcrypt", map[string]PasswordEncoder{})
//	id := d.getDefaultID() // "bcrypt"
func (d *DelegatingPasswordEncoder) getDefaultID() string {
	for id, enc := range d.Encoders {
		if enc == d.DefaultEncoder {
			return id
		}
	}
	return ""
}

// extractIDAndHash splits "{bcrypt}xxxxhashxxxx" into "bcrypt" and "xxxxhashxxxx"
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
