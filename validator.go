package totp

import "time"

type Validator struct {
	Algorithm Algorithm
	Digits    uint8
	Period    uint64
	Secret    string
}

func (v Validator) Validate(code string) (bool, error) {
	// generate totp based on current timestamp
	generatedCode, err := generateTotp(v.Secret, time.Now().Unix(), v.Algorithm, v.Digits, v.Period)
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
