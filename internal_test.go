package totp

import (
	"testing"
	"time"
)

func TestGenerateSecret(t *testing.T) {
	length := 10
	secret, err := generateSecret(length)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(secret) != length {
		t.Errorf("expected length of %d, got %d", length, len(secret))
	}
}

func TestGenerateTotp(t *testing.T) {
	secret, _ := generateSecret(10)
	timestamp := time.Now().Unix()
	algorithm := AlgorithmSHA1
	digits := uint8(6)
	period := uint64(30)

	code, err := generateTotp(secret, timestamp, algorithm, digits, period)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(code) != int(digits) {
		t.Errorf("expected length of %d, got %d", digits, len(code))
	}
}
