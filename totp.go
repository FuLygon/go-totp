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
	AccountName string
	Issuer      string
	Algorithm   Algorithm
	Digits      uint8
	Period      uint64
	Secret      string
}

type QR struct {
	Base64 string
	Image  image.Image
}

func New(options TOTP) (totp TOTP, err error) {
	// assign default value for algorithm
	if algorithm := options.Algorithm; algorithm == "" {
		options.Algorithm = AlgorithmSHA1
	} else {
		options.Algorithm = algorithm
	}

	// assign default value for digits
	if digits := options.Digits; digits == 0 {
		options.Digits = 6
	} else {
		options.Digits = digits
	}

	// assign default value for period
	if period := options.Period; period == 0 {
		options.Period = 30
	} else {
		options.Period = period
	}

	// generate a base32 secret
	options.Secret, err = generateSecret(20)
	if err != nil {
		return
	}

	// validate totp info
	err = options.validateData()
	if err != nil {
		return
	}

	return options, nil
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
	parameters.Add(paramAlgorithm, fmt.Sprintf("%s", t.Algorithm))
	parameters.Add(paramDigits, strconv.FormatUint(uint64(t.Digits), 10))
	parameters.Add(paramIssuer, t.Issuer)
	parameters.Add(paramPeriod, strconv.FormatUint(t.Period, 10))
	parameters.Add(paramSecret, t.Secret)
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
	if t.Algorithm != AlgorithmSHA1 && t.Algorithm != AlgorithmSHA256 && t.Algorithm != AlgorithmSHA512 {
		return ErrInvalidAlgorithm
	}

	// validate digits
	if t.Digits == 0 || t.Digits > 10 {
		return ErrInvalidDigits
	}

	// validate period
	if t.Period == 0 {
		return ErrInvalidPeriod
	}

	// validate issuer
	if t.Issuer == "" {
		return ErrEmptyIssuer
	}

	// validate account name
	if t.AccountName == "" {
		return ErrEmptyAccountName
	}

	// validate secret
	if !regexp.MustCompile("^[A-Z2-7]+$").MatchString(t.Secret) {
		return ErrInvalidSecret
	}

	return nil
}

func label(issuer, accountName string) string {
	return fmt.Sprintf("%s:%s", issuer, accountName)
}
