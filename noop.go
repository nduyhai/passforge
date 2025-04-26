package passforge

// NoOpPasswordEncoder is a password encoder that does not perform any encoding
// It's useful for testing and development purposes only and should not be used in production
type NoOpPasswordEncoder struct{}

// NewNoOpPasswordEncoder creates a new NoOpPasswordEncoder
func NewNoOpPasswordEncoder() *NoOpPasswordEncoder {
	return &NoOpPasswordEncoder{}
}

// Encode returns the raw password as-is without any encoding
func (n *NoOpPasswordEncoder) Encode(rawPassword string) (string, error) {
	return rawPassword, nil
}

// Verify checks if the raw password matches the encoded password
// Since NoOpPasswordEncoder doesn't perform any encoding, it just compares the strings directly
func (n *NoOpPasswordEncoder) Verify(rawPassword, encodedPassword string) (bool, error) {
	return rawPassword == encodedPassword, nil
}
