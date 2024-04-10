package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// url format for totp
const (
	totpScheme = "otpauth"
	totpHost   = "totp"
)

// totp url query parameters
const (
	paramAlgorithm = "algorithm"
	paramDigits    = "digits"
	paramIssuer    = "issuer"
	paramPeriod    = "period"
	paramSecret    = "secret"
)

// Algorithm represents hashing functions for generating OTP
type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

func (a Algorithm) hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	}
	panic("failed to get hash interfaces")
}
