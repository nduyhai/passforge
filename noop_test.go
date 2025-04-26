package passforge

import (
	"testing"
)

func TestNoOpPasswordEncoder_Encode(t *testing.T) {
	encoder := NewNoOpPasswordEncoder()

	testCases := []struct {
		name        string
		rawPassword string
		want        string
		wantErr     bool
	}{
		{
			name:        "regular password",
			rawPassword: "password123",
			want:        "password123",
			wantErr:     false,
		},
		{
			name:        "empty password",
			rawPassword: "",
			want:        "",
			wantErr:     false,
		},
		{
			name:        "special characters",
			rawPassword: "p@$$w0rd!",
			want:        "p@$$w0rd!",
			wantErr:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encoder.Encode(tc.rawPassword)

			if (err != nil) != tc.wantErr {
				t.Errorf("Encode() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if got != tc.want {
				t.Errorf("Encode() got = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNoOpPasswordEncoder_Verify(t *testing.T) {
	encoder := NewNoOpPasswordEncoder()

	testCases := []struct {
		name            string
		rawPassword     string
		encodedPassword string
		want            bool
		wantErr         bool
	}{
		{
			name:            "matching passwords",
			rawPassword:     "password123",
			encodedPassword: "password123",
			want:            true,
			wantErr:         false,
		},
		{
			name:            "non-matching passwords",
			rawPassword:     "password123",
			encodedPassword: "password456",
			want:            false,
			wantErr:         false,
		},
		{
			name:            "empty passwords",
			rawPassword:     "",
			encodedPassword: "",
			want:            true,
			wantErr:         false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encoder.Verify(tc.rawPassword, tc.encodedPassword)

			if (err != nil) != tc.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if got != tc.want {
				t.Errorf("Verify() got = %v, want %v", got, tc.want)
			}
		})
	}
}
