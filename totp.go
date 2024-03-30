package totp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/skip2/go-qrcode"
	"image"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

const secretCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

type TOTP struct {
	Issuer      string
	AccountName string
	Secret      string
}

type TOTPQR struct {
	Base64 string
	Image  image.Image
}

func Generate(issuer, accountName string) TOTP {
	return TOTP{
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      generateSecret(20),
	}
}

func (t TOTP) GetURL() string {
	totpUrl := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   label(t.Issuer, t.AccountName),
	}

	// query parameter
	parameters := url.Values{}
	parameters.Add("algorithm", "SHA1")
	parameters.Add("digits", "6")
	parameters.Add("issuer", t.Issuer)
	parameters.Add("period", "30")
	parameters.Add("secret", t.Secret)
	totpUrl.RawQuery = parameters.Encode()

	return totpUrl.String()
}

func (t TOTP) GetQR(size int) (TOTPQR, error) {
	totpUrl := t.GetURL()

	// generate qrcode
	bQR, err := qrcode.Encode(totpUrl, qrcode.Medium, size)
	if err != nil {
		return TOTPQR{}, errors.New("failed to encode QR code: " + err.Error())
	}

	// create base64 string
	strB64 := base64.StdEncoding.EncodeToString(bQR)

	// create image
	reader := bytes.NewReader(bQR)
	img, _, err := image.Decode(reader)
	if err != nil {
		return TOTPQR{}, errors.New("failed to decode image: " + err.Error())
	}
	return TOTPQR{Base64: strB64, Image: img}, nil
}

func Validate(code int, secret string) (bool, error) {
	// generate totp based on current timestamp
	generatedCode, err := generateTotp(secret)
	if err != nil {
		return false, err
	}

	// check if code is valid
	if code == int(generatedCode) {
		return true, nil
	}

	return false, nil
}

func label(issuer, accountName string) string {
	return fmt.Sprintf("%s:%s", issuer, accountName)
}

func generateSecret(length int) string {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = secretCharset[seededRand.Intn(len(secretCharset))]
	}
	return string(b)
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
