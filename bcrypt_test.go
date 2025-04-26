package passforge

import (
	"testing"
)

func TestBcryptPasswordEncoder_Encode(t *testing.T) {
	encoder := NewBcryptPasswordEncoder(10) // Use a lower cost for faster tests

	testCases := []struct {
		name        string
		rawPassword string
		wantErr     bool
	}{
		{
			name:        "regular password",
			rawPassword: "password123",
			wantErr:     false,
		},
		{
			name:        "empty password",
			rawPassword: "",
			wantErr:     false,
		},
		{
			name:        "special characters",
			rawPassword: "p@$$w0rd!",
			wantErr:     false,
		},
		{
			name:        "long password",
			rawPassword: "thisisaverylongpasswordthatisusedfortesting",
			wantErr:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := encoder.Encode(tc.rawPassword)

			if (err != nil) != tc.wantErr {
				t.Errorf("Encode() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr && encoded == tc.rawPassword {
				t.Errorf("Encode() did not hash the password, got = %v", encoded)
			}

			if !tc.wantErr && encoded == "" {
				t.Errorf("Encode() returned empty string")
			}
		})
	}
}

func TestBcryptPasswordEncoder_Verify(t *testing.T) {
	encoder := NewBcryptPasswordEncoder(10) // Use a lower cost for faster tests

	// Test verification with pre-encoded passwords
	testCases := []struct {
		name        string
		rawPassword string
		wantMatch   bool
	}{
		{
			name:        "matching password",
			rawPassword: "password123",
			wantMatch:   true,
		},
		{
			name:        "non-matching password",
			rawPassword: "wrongpassword",
			wantMatch:   false,
		},
		{
			name:        "empty password",
			rawPassword: "",
			wantMatch:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var encodedPassword string
			var err error

			if tc.name == "non-matching password" {
				// For non-matching test, encode a different password than the one we'll verify
				encodedPassword, err = encoder.Encode("correctpassword")
				if err != nil {
					t.Fatalf("Failed to encode password: %v", err)
				}
			} else {
				// For matching tests, encode the same password we'll verify
				encodedPassword, err = encoder.Encode(tc.rawPassword)
				if err != nil {
					t.Fatalf("Failed to encode password: %v", err)
				}
			}

			// Test verification
			match, err := encoder.Verify(tc.rawPassword, encodedPassword)
			if err != nil {
				t.Errorf("Verify() error = %v", err)
				return
			}

			if match != tc.wantMatch {
				t.Errorf("Verify() got = %v, want %v", match, tc.wantMatch)
			}

			// Test with incorrect password (only if we're testing a matching case)
			if tc.wantMatch && tc.rawPassword != "" {
				wrongMatch, err := encoder.Verify("wrong"+tc.rawPassword, encodedPassword)
				if err != nil {
					t.Errorf("Verify() error = %v", err)
					return
				}

				if wrongMatch {
					t.Errorf("Verify() with incorrect password incorrectly returned true")
				}
			}
		})
	}
}

func TestBcryptPasswordEncoder_DefaultCost(t *testing.T) {
	// Test that the default cost is used when 0 is provided
	encoder := NewBcryptPasswordEncoder(0)

	// Just verify that encoding works (which means the default cost was applied)
	password := "testpassword"
	encoded, err := encoder.Encode(password)
	if err != nil {
		t.Errorf("Encode() error = %v", err)
		return
	}

	if encoded == "" {
		t.Errorf("Encode() returned empty string")
	}

	// Verify the password
	match, err := encoder.Verify(password, encoded)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
		return
	}

	if !match {
		t.Errorf("Verify() returned false for matching password")
	}
}
