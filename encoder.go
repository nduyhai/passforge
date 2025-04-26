package passforge

// PasswordEncoder is an interface for password encoding and verification
type PasswordEncoder interface {
	// Encode returns the encoded password
	Encode(rawPassword string) (string, error)

	// Verify returns true if the raw password matches the encoded password
	Verify(rawPassword, encodedPassword string) (bool, error)

	// Name returns the name of the encoder.
	Name() string
}
