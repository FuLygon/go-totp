package totp

import (
	"errors"
	"testing"
)

func TestNew(t *testing.T) {
	totp, err := New(TOTP{
		AccountName: "testAccountName",
		Issuer:      "testIssuer",
	})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if totp.AccountName != "testAccountName" {
		t.Errorf("expected AccountName to be 'testAccountName', got %s", totp.AccountName)
	}

	if totp.Issuer != "testIssuer" {
		t.Errorf("expected Issuer to be 'testIssuer', got %s", totp.Issuer)
	}

	if totp.Algorithm != AlgorithmSHA1 {
		t.Errorf("expected Algorithm to be AlgorithmSHA1, got %s", totp.Algorithm)
	}

	if totp.Digits != 6 {
		t.Errorf("expected Digits to be 6, got %d", totp.Digits)
	}

	if totp.Period != 30 {
		t.Errorf("expected Period to be 30, got %d", totp.Period)
	}

	if totp.Secret == "" {
		t.Errorf("expected value for Secret, got empty string")
	}
}

func TestGetURL(t *testing.T) {
	totp, _ := New(TOTP{
		AccountName: "testAccountName",
		Issuer:      "testIssuer",
	})

	url, err := totp.GetURL()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if url == "" {
		t.Errorf("expected value for URL, got empty string")
	}
}

func TestNewErrorCases(t *testing.T) {
	// err empty account name
	_, err := New(TOTP{
		Issuer: "testIssuer",
	})
	if !errors.Is(err, ErrEmptyAccountName) {
		t.Errorf("expected error to be ErrEmptyAccountName, got %v", err)
	}

	// err empty issuer
	_, err = New(TOTP{
		AccountName: "testAccountName",
	})
	if !errors.Is(err, ErrEmptyIssuer) {
		t.Errorf("expected error to be ErrEmptyIssuer, got %v", err)
	}

	// err invalid algorithm
	_, err = New(TOTP{
		AccountName: "testAccountName",
		Issuer:      "testIssuer",
		Algorithm:   "InvalidAlgorithm",
	})
	if !errors.Is(err, ErrInvalidAlgorithm) {
		t.Errorf("expected error to be ErrInvalidAlgorithm, got %v", err)
	}

	// err invalid digits
	_, err = New(TOTP{
		AccountName: "testAccountName",
		Issuer:      "testIssuer",
		Digits:      11,
	})
	if !errors.Is(err, ErrInvalidDigits) {
		t.Errorf("expected error to be ErrInvalidDigits, got %v", err)
	}
}

func TestGetURLErrorCases(t *testing.T) {
	var totp TOTP

	// err empty account name
	_, err := totp.GetURL()
	if !errors.Is(err, ErrEmptyAccountName) {
		t.Errorf("expected error to be ErrEmptyAccountName, got %v", err)
	}

	// err empty issuer
	totp.AccountName = "testAccountName"
	_, err = totp.GetURL()
	if !errors.Is(err, ErrEmptyIssuer) {
		t.Errorf("expected error to be ErrEmptyIssuer, got %v", err)
	}
	totp.Issuer = "testIssuer"

	// err invalid algorithm
	totp.Algorithm = "invalidAlgorithm"
	_, err = totp.GetURL()
	if !errors.Is(err, ErrInvalidAlgorithm) {
		t.Errorf("expected error to be ErrInvalidAlgorithm, got %v", err)
	}
	totp.Algorithm = AlgorithmSHA1

	// err invalid digits
	totp.Digits = 0
	_, err = totp.GetURL()
	if !errors.Is(err, ErrInvalidDigits) {
		t.Errorf("expected error to be ErrInvalidDigits, got %v", err)
	}
	totp.Digits = 11
	_, err = totp.GetURL()
	if !errors.Is(err, ErrInvalidDigits) {
		t.Errorf("expected error to be ErrInvalidDigits, got %v", err)
	}
	totp.Digits = 6

	// err invalid period
	totp.Period = 0
	_, err = totp.GetURL()
	if !errors.Is(err, ErrInvalidPeriod) {
		t.Errorf("expected error to be ErrInvalidPeriod, got %v", err)
	}
	totp.Period = 30

	// err invalid secret
	totp.Secret = "invalidSecret"
	_, err = totp.GetURL()
	if !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("expected error to be ErrInvalidSecret, got %v", err)
	}
}
