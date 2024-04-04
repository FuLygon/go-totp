package totp

import "errors"

var (
	// ErrEmptyIssuer issue value was required
	ErrEmptyIssuer = errors.New("issuer cannot be empty")
	// ErrEmptyAccountName account name value required
	ErrEmptyAccountName = errors.New("account name cannot be empty")
	// ErrInvalidAlgorithm invalid or unsupported algorithm
	ErrInvalidAlgorithm = errors.New("invalid or unsupported algorithm")
	// ErrInvalidDigits invalid or unsupported digits allowed value range is between 1 and 10
	ErrInvalidDigits = errors.New("invalid or unsupported digits")
	// ErrInvalidPeriod invalid period value
	ErrInvalidPeriod = errors.New("period cannot be empty")
	// ErrInvalidSecret invalid secret value
	ErrInvalidSecret = errors.New("secret is not a valid base32")
)
