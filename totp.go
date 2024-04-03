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
	"strconv"
)

type TOTP struct {
	Algorithm   Algorithm
	Digits      uint8
	Period      uint64
	Issuer      string
	AccountName string
	Secret      string
}

type QR struct {
	Base64 string
	Image  image.Image
}

func Generate(issuer, accountName string, algorithm Algorithm, digits uint8, period uint64) (totp TOTP, err error) {
	totp.Issuer = issuer
	totp.AccountName = accountName

	// assign default value for algorithm
	if algorithm == "" {
		totp.Algorithm = AlgorithmSHA1
	} else {
		totp.Algorithm = algorithm
	}

	// assign default value for digits
	if digits == 0 {
		totp.Digits = 6
	} else {
		totp.Digits = digits
	}

	// assign default value for period
	if period == 0 {
		totp.Period = 30
	} else {
		totp.Period = period
	}

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
		Path:   label(t.Issuer, t.AccountName),
	}

	parameters := url.Values{}
	parameters.Add("algorithm", fmt.Sprintf("%s", t.Algorithm))
	parameters.Add("digits", strconv.FormatUint(uint64(t.Digits), 10))
	parameters.Add("issuer", t.Issuer)
	parameters.Add("period", strconv.FormatUint(t.Period, 10))
	parameters.Add("secret", t.Secret)
	totpUrl.RawQuery = parameters.Encode()

	return totpUrl.String(), nil
}

func (t TOTP) GetQR(size int, qrRecoveryLevel ...qrcode.RecoveryLevel) (QR, error) {
	totpUrl, err := t.GetURL()
	if err != nil {
		return QR{}, err
	}

	// assign default value for qrcode recovery level if not provided
	if len(qrRecoveryLevel) < 1 {
		qrRecoveryLevel = append(qrRecoveryLevel, qrcode.Medium)
	}

	// generate qrcode
	bQR, err := qrcode.Encode(totpUrl, qrRecoveryLevel[0], size)
	if err != nil {
		return QR{}, errors.New("failed to encode QR code: " + err.Error())
	}

	// create base64 string
	strB64 := base64.StdEncoding.EncodeToString(bQR)

	// create image
	reader := bytes.NewReader(bQR)
	img, _, err := image.Decode(reader)
	if err != nil {
		return QR{}, errors.New("failed to decode image: " + err.Error())
	}
	return QR{Base64: strB64, Image: img}, nil
}

func (t TOTP) validateData() error {
	// validate algorithm
	if t.Algorithm == "" {
		return errors.New("algorithm cannot be empty")
	}

	if t.Algorithm != AlgorithmSHA1 && t.Algorithm != AlgorithmSHA256 && t.Algorithm != AlgorithmSHA512 {
		return errors.New("invalid or unsupported algorithm")
	}

	// validate digits
	if t.Digits == 0 {
		return errors.New("digits cannot be empty")
	}

	if t.Digits != 6 && t.Digits != 8 {
		return errors.New("invalid or unsupported digits")
	}

	// validate period
	if t.Period == 0 {
		return errors.New("period cannot be empty")
	}

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

func label(issuer, accountName string) string {
	return fmt.Sprintf("%s:%s", issuer, accountName)
}
