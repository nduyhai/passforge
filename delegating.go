package passforge

import "strings"

// DelegatingPasswordEncoder delegates encoding to a default encoder and a map of encoders
type DelegatingPasswordEncoder struct {
	DefaultEncoder PasswordEncoder
	Encoders       map[string]PasswordEncoder // e.g., "bcrypt" => bcrypt encoder
}

func NewDelegatingPasswordEncoder(defaultEncoderID string, encoders map[string]PasswordEncoder) *DelegatingPasswordEncoder {
	return &DelegatingPasswordEncoder{
		DefaultEncoder: encoders[defaultEncoderID],
		Encoders:       encoders,
	}
}

func (d *DelegatingPasswordEncoder) Encode(rawPassword string) (string, error) {
	encoded, err := d.DefaultEncoder.Encode(rawPassword)
	if err != nil {
		return "", err
	}
	return "{" + d.getDefaultID() + "}" + encoded, nil
}

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
