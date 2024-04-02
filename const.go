package totp

const (
	totpScheme = "otpauth"
	totpHost   = "totp"
	digits     = "6"
	period     = "30"
)

type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "sha1"
	AlgorithmSHA256 Algorithm = "sha256"
	AlgorithmSHA512 Algorithm = "sha512"
)
