package totp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/skip2/go-qrcode"
	"image"
	"net/url"
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

func Generate(issuer, accountName string) (TOTP, error) {
	secret, err := generateSecret(20)
	if err != nil {
		return TOTP{}, err
	}

	return TOTP{
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      secret,
	}, nil
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
