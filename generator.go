package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

func generateSecret(length int) (string, error) {
	buffer := make([]byte, (length*5)/8)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buffer)[:length], nil
}

func generateTotp(secretKey string) (uint32, error) {
	base32Decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	// convert secret to uppercase and remove extra spaces
	secretKey = strings.ToUpper(strings.TrimSpace(secretKey))
	// decode the base32-encoded secret key into bytes
	secretBytes, err := base32Decoder.DecodeString(secretKey)
	if err != nil {
		return 0, fmt.Errorf("failed to decode secret: " + err.Error())
	}

	// The truncated timestamp / 30 is converted to an 8-byte big-endian
	// unsigned integer slice
	// convert timestamp to bytes, divide by 30
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix())/30)

	// timestamp bytes are concatenated with the decoded secret key bytes
	// then a 20-byte SHA-1 hash is calculated from the byte slice
	// and the hash with 0x0F (15) to get a single-digit offset
	hash := hmac.New(sha1.New, secretBytes)
	hash.Write(timeBytes)
	h := hash.Sum(nil)
	offset := h[len(h)-1] & 0x0F

	// truncate the SHA-1 by the offset and convert it into a 32-bit
	// unsigned int and the 32-bit int with 0x7FFFFFFF (2147483647)
	// to get a 31-bit unsigned int.
	truncatedHash := binary.BigEndian.Uint32(h[offset:]) & 0x7FFFFFFF

	// generate TOTP code by taking the modulo of the truncated hash
	return truncatedHash % 1_000_000, nil
}
