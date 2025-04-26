package passforge

import (
	"testing"
)

func TestDelegatingPasswordEncoder_Encode(t *testing.T) {
	// Create encoders
	bcryptEncoder := NewBcryptPasswordEncoder(WithCost(10))
	noopEncoder := NewNoOpPasswordEncoder()

	// Create a map of encoders
	encoders := map[string]PasswordEncoder{
		"bcrypt": bcryptEncoder,
		"noop":   noopEncoder,
	}

	// Test with bcrypt as default
	t.Run("with bcrypt as default", func(t *testing.T) {
		delegatingEncoder := NewDelegatingPasswordEncoder("bcrypt", encoders)

		rawPassword := "password123"
		encoded, err := delegatingEncoder.Encode(rawPassword)

		if err != nil {
			t.Errorf("Encode() error = %v", err)
			return
		}

		// Check that the encoded password has the expected format
		if encoded == "" {
			t.Errorf("Encode() returned empty string")
		}

		// Check that it has the correct prefix
		if encoded[:8] != "{bcrypt}" {
			t.Errorf("Encode() result doesn't have expected prefix, got = %v", encoded[:8])
		}

		// Verify the password
		match, err := delegatingEncoder.Verify(rawPassword, encoded)
		if err != nil {
			t.Errorf("Verify() error = %v", err)
			return
		}

		if !match {
			t.Errorf("Verify() returned false for matching password")
		}
	})

	// Test with noop as default
	t.Run("with noop as default", func(t *testing.T) {
		delegatingEncoder := NewDelegatingPasswordEncoder("noop", encoders)

		rawPassword := "password123"
		encoded, err := delegatingEncoder.Encode(rawPassword)

		if err != nil {
			t.Errorf("Encode() error = %v", err)
			return
		}

		// Check that the encoded password has the expected format
		if encoded == "" {
			t.Errorf("Encode() returned empty string")
		}

		// Check that it has the correct prefix
		if encoded[:6] != "{noop}" {
			t.Errorf("Encode() result doesn't have expected prefix, got = %v", encoded[:6])
		}

		// Verify the password
		match, err := delegatingEncoder.Verify(rawPassword, encoded)
		if err != nil {
			t.Errorf("Verify() error = %v", err)
			return
		}

		if !match {
			t.Errorf("Verify() returned false for matching password")
		}
	})
}

func TestDelegatingPasswordEncoder_Verify(t *testing.T) {
	// Create encoders
	bcryptEncoder := NewBcryptPasswordEncoder(WithCost(10))
	noopEncoder := NewNoOpPasswordEncoder()

	// Create a map of encoders
	encoders := map[string]PasswordEncoder{
		"bcrypt": bcryptEncoder,
		"noop":   noopEncoder,
	}

	delegatingEncoder := NewDelegatingPasswordEncoder("bcrypt", encoders)

	// Test verification with different encoder prefixes
	testCases := []struct {
		name        string
		rawPassword string
		encoderID   string
		wantMatch   bool
		wantErr     bool
	}{
		{
			name:        "bcrypt matching password",
			rawPassword: "password123",
			encoderID:   "bcrypt",
			wantMatch:   true,
			wantErr:     false,
		},
		{
			name:        "noop matching password",
			rawPassword: "password123",
			encoderID:   "noop",
			wantMatch:   true,
			wantErr:     false,
		},
		{
			name:        "unknown encoder",
			rawPassword: "password123",
			encoderID:   "unknown",
			wantMatch:   false,
			wantErr:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var encodedPassword string
			var err error

			// Encode the password with the specified encoder
			if tc.encoderID == "unknown" {
				// For an unknown encoder, create a fake encoded password
				encodedPassword = "{unknown}password123"
			} else {
				// Get the encoder
				encoder := encoders[tc.encoderID]

				// Encode the password
				rawEncoded, errEncoder := encoder.Encode(tc.rawPassword)
				if errEncoder != nil {
					t.Fatalf("Failed to encode password: %v", errEncoder)
				}

				// Add the prefix
				encodedPassword = "{" + tc.encoderID + "}" + rawEncoded
			}

			// Verify the password
			match, err := delegatingEncoder.Verify(tc.rawPassword, encodedPassword)

			if (err != nil) != tc.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr && match != tc.wantMatch {
				t.Errorf("Verify() got = %v, want %v", match, tc.wantMatch)
			}
		})
	}
}

func TestDelegatingPasswordEncoder_InvalidFormat(t *testing.T) {
	// Create encoders
	bcryptEncoder := NewBcryptPasswordEncoder(WithCost(10))

	// Create a map of encoders
	encoders := map[string]PasswordEncoder{
		"bcrypt": bcryptEncoder,
	}

	delegatingEncoder := NewDelegatingPasswordEncoder("bcrypt", encoders)

	// Test with invalid format (no prefix)
	_, err := delegatingEncoder.Verify("password", "invalid-format")
	if err != ErrInvalidFormat {
		t.Errorf("Verify() with invalid format should return ErrInvalidFormat, got %v", err)
	}

	// Test with invalid format (no closing brace)
	_, err = delegatingEncoder.Verify("password", "{bcryptinvalid")
	if err != ErrInvalidFormat {
		t.Errorf("Verify() with invalid format should return ErrInvalidFormat, got %v", err)
	}

	// Test with unknown encoder
	_, err = delegatingEncoder.Verify("password", "{unknown}password")
	if err != ErrUnknownEncoding {
		t.Errorf("Verify() with unknown encoder should return ErrUnknownEncoding, got %v", err)
	}
}

func TestDelegatingPasswordEncoder_GetDefaultId(t *testing.T) {
	// Create encoders
	bcryptEncoder := NewBcryptPasswordEncoder(WithCost(10))
	noopEncoder := NewNoOpPasswordEncoder()

	// Create a map of encoders
	encoders := map[string]PasswordEncoder{
		"bcrypt": bcryptEncoder,
		"noop":   noopEncoder,
	}

	// Test with bcrypt as default
	delegatingEncoder := NewDelegatingPasswordEncoder("bcrypt", encoders)

	// Use the Encode method which internally calls getDefaultID
	encoded, err := delegatingEncoder.Encode("password")
	if err != nil {
		t.Errorf("Encode() error = %v", err)
		return
	}

	// Check that it has the correct prefix
	if encoded[:8] != "{bcrypt}" {
		t.Errorf("Encode() result doesn't have expected prefix, got = %v", encoded[:8])
	}
}

func TestExtractIdAndHash(t *testing.T) {
	testCases := []struct {
		name            string
		encodedPassword string
		wantID          string
		wantHash        string
		wantErr         bool
		expectedErr     error
	}{
		{
			name:            "valid format",
			encodedPassword: "{bcrypt}$2a$10$abcdefghijklmnopqrstuv",
			wantID:          "bcrypt",
			wantHash:        "$2a$10$abcdefghijklmnopqrstuv",
			wantErr:         false,
			expectedErr:     nil,
		},
		{
			name:            "empty string",
			encodedPassword: "",
			wantID:          "",
			wantHash:        "",
			wantErr:         true,
			expectedErr:     ErrInvalidFormat,
		},
		{
			name:            "no opening brace",
			encodedPassword: "bcrypt}$2a$10$abcdefghijklmnopqrstuv",
			wantID:          "",
			wantHash:        "",
			wantErr:         true,
			expectedErr:     ErrInvalidFormat,
		},
		{
			name:            "no closing brace",
			encodedPassword: "{bcrypt$2a$10$abcdefghijklmnopqrstuv",
			wantID:          "",
			wantHash:        "",
			wantErr:         true,
			expectedErr:     ErrInvalidFormat,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, hash, err := extractIDAndHash(tc.encodedPassword)

			if (err != nil) != tc.wantErr {
				t.Errorf("extractIDAndHash() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr && err != tc.expectedErr {
				t.Errorf("extractIDAndHash() error = %v, expectedErr %v", err, tc.expectedErr)
				return
			}

			if id != tc.wantID {
				t.Errorf("extractIDAndHash() id = %v, want %v", id, tc.wantID)
			}

			if hash != tc.wantHash {
				t.Errorf("extractIDAndHash() hash = %v, want %v", hash, tc.wantHash)
			}
		})
	}
}
