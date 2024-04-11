package totp

import "errors"

var (
	// ErrEmptyIssuer value for issuer is required
	ErrEmptyIssuer = errors.New("issuer cannot be empty")
	// ErrEmptyAccountName value for account name is required
	ErrEmptyAccountName = errors.New("account name cannot be empty")
	// ErrInvalidAlgorithm invalid or unsupported algorithm
	ErrInvalidAlgorithm = errors.New("invalid or unsupported algorithm")
	// ErrInvalidDigits invalid or unsupported digits, supported values are from 1 to 10
	ErrInvalidDigits = errors.New("invalid or unsupported digits")
	// ErrInvalidPeriod invalid period value
	ErrInvalidPeriod = errors.New("period cannot be empty")
	// ErrInvalidSecret invalid secret value
	ErrInvalidSecret = errors.New("secret is not a valid base32")
)
