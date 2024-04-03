package totp

const (
	totpScheme = "otpauth"
	totpHost   = "totp"
)

type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)
