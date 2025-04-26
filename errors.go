package passforge

import "errors"

// ErrUnknownEncoding is returned when the encoding ID is not recognized
var ErrUnknownEncoding = errors.New("unknown encoding")

// ErrInvalidFormat is returned when the encoded password format is invalid
var ErrInvalidFormat = errors.New("invalid format")
