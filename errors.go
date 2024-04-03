package totp

import "errors"

var (
	// ErrEmptyAlgorithm algorithm value required
	ErrEmptyAlgorithm = errors.New("algorithm cannot be empty")
	// ErrEmptyDigits digits value was required
	ErrEmptyDigits = errors.New("digits cannot be empty")
	// ErrEmptyPeriod period value was required
	ErrEmptyPeriod = errors.New("period cannot be empty")
	// ErrEmptyIssuer issue value was required
	ErrEmptyIssuer = errors.New("issuer cannot be empty")
	// ErrEmptyAccountName account name value required
	ErrEmptyAccountName = errors.New("account name cannot be empty")
	// ErrEmptySecret secret value required
	ErrEmptySecret = errors.New("secret cannot be empty")
	// ErrInvalidAlgorithm invalid or unsupported algorithm
	ErrInvalidAlgorithm = errors.New("invalid or unsupported algorithm")
	// ErrInvalidDigits invalid or unsupported digits, supported value are 6 and 8
	ErrInvalidDigits = errors.New("invalid or unsupported digits")
	// ErrInvalidSecret invalid secret value
	ErrInvalidSecret = errors.New("secret is not a valid base32")
)
