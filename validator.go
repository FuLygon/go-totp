package totp

import (
	"regexp"
	"time"
)

// Validator defines the structure used for TOTP validation
type Validator struct {
	// Hashing function of the TOTP.
	Algorithm Algorithm
	// Number of digits of the TOTP.
	Digits uint8
	// Time period (seconds) of the TOTP
	Period uint64
	// Base32 encoded shared secret key of the TOTP.
	Secret string
}

// Validate validates the provided TOTP code against the current timestamp
func (v Validator) Validate(code string) (bool, error) {
	// validate validator info
	err := v.validateData()
	if err != nil {
		return false, err
	}

	// generate totp based on current timestamp
	generatedCode, err := generateTotp(v.Secret, time.Now().UTC().Unix(), v.Algorithm, v.Digits, v.Period)
	if err != nil {
		return false, err
	}

	// check if code is valid
	if code == generatedCode {
		return true, nil
	}

	return false, nil
}

// ValidateWithTimestamp validates the provided TOTP code against a specific timestamp
func (v Validator) ValidateWithTimestamp(code string, timestamp int64) (bool, error) {
	// validate validator info
	err := v.validateData()
	if err != nil {
		return false, err
	}

	// generate totp based on timestamp parameter
	generatedCode, err := generateTotp(v.Secret, timestamp, v.Algorithm, v.Digits, v.Period)
	if err != nil {
		return false, err
	}

	// check if code is valid
	if code == generatedCode {
		return true, nil
	}

	return false, nil
}

// validateData validates validator data.
func (v Validator) validateData() error {
	// validate algorithm
	if v.Algorithm != AlgorithmSHA1 && v.Algorithm != AlgorithmSHA256 && v.Algorithm != AlgorithmSHA512 {
		return ErrInvalidAlgorithm
	}

	// validate digits
	if v.Digits == 0 || v.Digits > 10 {
		return ErrInvalidDigits
	}

	// validate period
	if v.Period == 0 {
		return ErrInvalidPeriod
	}

	// validate secret
	if !regexp.MustCompile("^[A-Z2-7]+$").MatchString(v.Secret) {
		return ErrInvalidSecret
	}

	return nil
}
