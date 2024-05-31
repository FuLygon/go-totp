package totp

import (
	"errors"
	"testing"
	"time"
)

func TestValidator(t *testing.T) {
	secret, _ := generateSecret(10)
	timestamp := time.Now().Unix()
	algorithm := AlgorithmSHA1
	digits := uint8(6)
	period := uint64(30)

	// generate code for timestamp
	code, _ := generateTotp(secret, timestamp, algorithm, digits, period)

	validator := Validator{
		Algorithm: algorithm,
		Digits:    digits,
		Period:    period,
		Secret:    secret,
		Skew:      0,
	}

	// validate code against current timestamp
	valid, err := validator.Validate(code)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !valid {
		t.Errorf("expected code to be valid")
	}

	// validate code against timestamp
	valid, err = validator.ValidateWithTimestamp(code, timestamp)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !valid {
		t.Errorf("expected code to be valid")
	}
}

func TestValidatorSkew(t *testing.T) {
	secret, _ := generateSecret(10)
	timestamp := time.Now().Unix()
	algorithm := AlgorithmSHA1
	digits := uint8(6)
	period := uint64(30)

	// generate code for timestamp
	code, _ := generateTotp(secret, timestamp, algorithm, digits, period)

	validator := Validator{
		Algorithm: algorithm,
		Digits:    digits,
		Period:    period,
		Secret:    secret,
		Skew:      1,
	}

	// validate code against timestamp
	valid, err := validator.ValidateWithTimestamp(code, timestamp)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !valid {
		t.Errorf("expected code to be valid")
	}

	// validate code against timestamp + period
	valid, err = validator.ValidateWithTimestamp(code, timestamp+int64(period))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !valid {
		t.Errorf("expected code to be valid with skew of 1")
	}

	// validate code against timestamp - period
	valid, err = validator.ValidateWithTimestamp(code, timestamp-int64(period))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !valid {
		t.Errorf("expected code to be valid with skew of 1")
	}
}

func TestValidatorErrorCases(t *testing.T) {
	validator := Validator{
		Algorithm: "InvalidAlgorithm",
		Digits:    0,
		Period:    0,
		Secret:    "InvalidSecret",
		Skew:      1,
	}
	otp := "123456"

	// err invalid algorithm
	_, err := validator.Validate(otp)
	if !errors.Is(err, ErrInvalidAlgorithm) {
		t.Errorf("expected error to be ErrInvalidAlgorithm, got %v", err)
	}
	validator.Algorithm = AlgorithmSHA1

	// err invalid digits
	_, err = validator.Validate(otp)
	if !errors.Is(err, ErrInvalidDigits) {
		t.Errorf("expected error to be ErrInvalidDigits, got %v", err)
	}
	validator.Digits = 6

	// err invalid period
	_, err = validator.Validate(otp)
	if !errors.Is(err, ErrInvalidPeriod) {
		t.Errorf("expected error to be ErrInvalidPeriod, got %v", err)
	}
	validator.Period = 30

	// err invalid secret
	_, err = validator.Validate(otp)
	if !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("expected error to be ErrInvalidSecret, got %v", err)
	}
}
