package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
)

func generateSecret(length int) (string, error) {
	buffer := make([]byte, (length*5)/8)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buffer)[:length], nil
}

func generateTotp(secretKey string, timestamp int64, algorithm Algorithm, digits uint8, period uint64) (string, error) {
	base32Decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	// convert secret to uppercase and remove extra spaces
	secretKey = strings.ToUpper(strings.TrimSpace(secretKey))
	// decode the base32-encoded secret key into bytes
	secretBytes, err := base32Decoder.DecodeString(secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: " + err.Error())
	}

	// The truncated timestamp / period is converted to an 8-byte big-endian
	// unsigned integer slice
	// convert timestamp to bytes, divide by period
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp)/period)

	// timestamp bytes are concatenated with the decoded secret key bytes
	// then a 20-byte hash is calculated from the byte slice
	// and the hash with 0x0F (15) to get a single-digit offset
	h := hmac.New(getHashInterfaces(algorithm), secretBytes)
	h.Write(timeBytes)
	b := h.Sum(nil)
	offset := b[len(b)-1] & 0x0F

	// truncate hash by the offset and convert it into a 32-bit
	// unsigned int and the 32-bit int with 0x7FFFFFFF (2147483647)
	// to get a 31-bit unsigned int.
	truncatedHash := binary.BigEndian.Uint32(b[offset:]) & 0x7FFFFFFF

	// return generated TOTP code by taking the modulo of the truncated hash
	switch digits {
	case 6:
		return fmt.Sprintf("%06d", truncatedHash%1_000_000), nil
	case 8:
		return fmt.Sprintf("%08d", truncatedHash%100_000_000), nil
	default:
		panic("invalid digits value")
	}
}

func getHashInterfaces(algorithm Algorithm) func() hash.Hash {
	switch algorithm {
	case AlgorithmSHA1:
		return sha1.New
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	}
	panic(fmt.Sprintf("error getting hash interfaces for algorithm")
}
