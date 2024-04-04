package totp

import (
	"regexp"
	"time"
)

type Validator struct {
	Algorithm Algorithm
	Digits    uint8
	Period    uint64
	Secret    string
}

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

func (v Validator) validateData() error {
	// validate algorithm
	if v.Algorithm != AlgorithmSHA1 && v.Algorithm != AlgorithmSHA256 && v.Algorithm != AlgorithmSHA512 {
		return ErrInvalidAlgorithm
	}

	// validate digits
	if v.Digits != 6 && v.Digits != 8 {
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
