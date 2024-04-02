package totp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/skip2/go-qrcode"
	"image"
	"net/url"
	"regexp"
	"time"
)

type TOTP struct {
	Issuer      string
	AccountName string
	Secret      string
}

type TOTPQR struct {
	Base64 string
	Image  image.Image
}

func Generate(issuer, accountName string) (totp TOTP, err error) {
	totp.Issuer = issuer
	totp.AccountName = accountName

	// generate a base32 secret
	totp.Secret, err = generateSecret(20)
	if err != nil {
		return
	}

	// validate totp info
	err = totp.validateData()
	if err != nil {
		return
	}

	return
}

func (t TOTP) GetURL() (string, error) {
	// validate totp info
	err := t.validateData()
	if err != nil {
		return "", err
	}

	totpUrl := url.URL{
		Scheme: totpScheme,
		Host:   totpHost,
		Path:   fmt.Sprintf("%s:%s", t.Issuer, t.AccountName),
	}

	parameters := url.Values{}
	parameters.Add("algorithm", algorithmSHA1)
	parameters.Add("digits", digits)
	parameters.Add("issuer", t.Issuer)
	parameters.Add("period", period)
	parameters.Add("secret", t.Secret)
	totpUrl.RawQuery = parameters.Encode()

	return totpUrl.String(), nil
}

func (t TOTP) GetQR(size int, qrRecoveryLevel ...qrcode.RecoveryLevel) (TOTPQR, error) {
	totpUrl, err := t.GetURL()
	if err != nil {
		return TOTPQR{}, err
	}

	// assign default value for qrcode recovery level if not provided
	if len(qrRecoveryLevel) < 1 {
		qrRecoveryLevel = append(qrRecoveryLevel, qrcode.Medium)
	}

	// generate qrcode
	bQR, err := qrcode.Encode(totpUrl, qrRecoveryLevel[0], size)
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

func (t TOTP) validateData() error {
	if t.Issuer == "" {
		return errors.New("issuer cannot be empty")
	}

	if t.AccountName == "" {
		return errors.New("account name cannot be empty")
	}

	if t.Secret == "" {
		return errors.New("secret cannot be empty")
	}

	if !regexp.MustCompile("^[A-Z2-7]+$").MatchString(t.Secret) {
		return errors.New("secret is not a valid base32")
	}

	return nil
}

func Validate(code int, secret string) (bool, error) {
	// generate totp based on current timestamp
	generatedCode, err := generateTotp(secret, time.Now().Unix())
	if err != nil {
		return false, err
	}

	// check if code is valid
	if code == int(generatedCode) {
		return true, nil
	}

	return false, nil
}

func ValidateWithTimestamp(code int, secret string, timestamp int64) (bool, error) {
	// generate totp based on timestamp parameter
	generatedCode, err := generateTotp(secret, timestamp)
	if err != nil {
		return false, err
	}

	// check if code is valid
	if code == int(generatedCode) {
		return true, nil
	}

	return false, nil
}
