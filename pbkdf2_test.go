package passforge

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestPBKDF2PasswordEncoder_Encode(t *testing.T) {
	// Use smaller parameters for faster tests
	encoder := NewPBKDF2PasswordEncoder(WithPBKDF2Iterations(1000), WithPBKDF2KeyLen(32), WithPBKDF2SaltLen(16), WithPBKDF2HashFunc(sha256.New, "sha256"))

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

			if !tc.wantErr {
				// Check that the encoded password has the expected format
				if !strings.HasPrefix(encoded, "iterations=") {
					t.Errorf("Encode() result doesn't have expected format, got = %v", encoded)
				}

				// Check that it contains the parameters and two $ separators
				parts := strings.Split(encoded, "$")
				if len(parts) != 3 {
					t.Errorf("Encode() result doesn't have expected format with 3 parts, got = %v", encoded)
				}

				// Check that the parameters section contains all expected parameters
				params := parts[0]
				if !strings.Contains(params, "iterations=") || !strings.Contains(params, "keyLen=") ||
					!strings.Contains(params, "hashFunc=") {
					t.Errorf("Encode() parameters section missing expected parameters, got = %v", params)
				}
			}
		})
	}
}

func TestPBKDF2PasswordEncoder_Verify(t *testing.T) {
	// Use smaller parameters for faster tests
	encoder := NewPBKDF2PasswordEncoder(WithPBKDF2Iterations(1000), WithPBKDF2KeyLen(32), WithPBKDF2SaltLen(16), WithPBKDF2HashFunc(sha256.New, "sha256"))

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
			name:        "empty password",
			rawPassword: "",
			wantMatch:   true,
		},
		{
			name:        "special characters",
			rawPassword: "p@$$w0rd!",
			wantMatch:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// First encode the password
			encodedPassword, err := encoder.Encode(tc.rawPassword)
			if err != nil {
				t.Fatalf("Failed to encode password: %v", err)
			}

			// Test with matching password
			match, err := encoder.Verify(tc.rawPassword, encodedPassword)
			if err != nil {
				t.Errorf("Verify() error = %v", err)
				return
			}

			if match != tc.wantMatch {
				t.Errorf("Verify() with correct password got = %v, want %v", match, tc.wantMatch)
			}

			// Test with incorrect password (only if we're testing a matching case and not empty password)
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

func TestPBKDF2PasswordEncoder_InvalidFormat(t *testing.T) {
	encoder := NewPBKDF2PasswordEncoder(WithPBKDF2Iterations(1000), WithPBKDF2KeyLen(32), WithPBKDF2SaltLen(16), WithPBKDF2HashFunc(sha256.New, "sha256"))

	// Test with invalid format
	_, err := encoder.Verify("password", "invalid-format")
	if err == nil {
		t.Errorf("Verify() with invalid format should return error")
	}

	// Test with missing parts
	_, err = encoder.Verify("password", "iterations=1000,keyLen=32,hashFunc=sha256$salt")
	if err == nil {
		t.Errorf("Verify() with missing parts should return error")
	}

	// Test with invalid parameters
	_, err = encoder.Verify("password", "invalid,params$salt$hash")
	if err == nil {
		t.Errorf("Verify() with invalid parameters should return error")
	}
}

func TestPBKDF2PasswordEncoder_DefaultParameters(t *testing.T) {
	// Test that default parameters are used when zeros are provided
	encoder := NewPBKDF2PasswordEncoder()

	// Just verify that encoding works (which means default parameters were applied)
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

func TestPBKDF2PasswordEncoder_Name(t *testing.T) {
	encoder := NewPBKDF2PasswordEncoder()

	expected := "pbkdf2"
	actual := encoder.Name()

	if actual != expected {
		t.Errorf("Name() = %v, want %v", actual, expected)
	}
}
