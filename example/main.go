package main

import (
	"fmt"
	"github.com/FuLygon/go-totp"
	"github.com/skip2/go-qrcode"
	"image/png"
	"os"
	"strings"
)

var (
	issuer              = "example.com"
	accountName         = "example@example.com"
	algorithm           = totp.AlgorithmSHA1
	digits       uint8  = 6
	period       uint64 = 30 // period might get ignored in some app like Google Authenticator
	customSecret        = "IZMPDHTBXXOYYWR4SC4Q"
)

func main() {
	// generate totp info with random secret
	totpInfo, err := totp.Generate(issuer, accountName, algorithm, digits, period)
	if err != nil {
		panic(err)
	}

	// or manually create totp info
	totpInfo = totp.TOTP{
		Algorithm:   algorithm,
		Digits:      digits,
		Period:      period,
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      customSecret,
	}

	// get totp url
	totpUrl, err := totpInfo.GetURL()
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nTOTP URL: %s", totpUrl)

	// get qr code info
	qrInfo, err := totpInfo.GetQR(256)
	if err != nil {
		panic(err)
	}

	// or get qr code with custom qrcode.RecoveryLevel
	qrInfo, err = totpInfo.GetQR(512, qrcode.Highest)
	if err != nil {
		panic(err)
	}

	// base64 value
	fmt.Printf("\n\nBase64: %s", qrInfo.Base64)

	// save qr as qrcode.png
	file, err := os.Create("qrcode.png")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err = file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	err = png.Encode(file, qrInfo.Image)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n\nQR code saved as qrcode.png\n\n")

	// prompt
	for {
		validator := totp.Validator{
			Algorithm: totpInfo.Algorithm,
			Digits:    totpInfo.Digits,
			Period:    totpInfo.Period,
			Secret:    totpInfo.Secret,
		}

		// showing cli prompt
		fmt.Printf("==============================================================\nEnter 2FA code: ")
		var code string
		fmt.Scanln(&code)

		valid, err := validator.Validate(code)
		if err != nil {
			panic(err)
		}

		// invalid 2fa code
		if !valid {
			fmt.Printf("Invalid 2FA code.\n")
			continue
		}

		// valid 2fa code
		fmt.Printf("Valid 2FA code. Do you want to try another 2FA code? [y/N] ")
		var loop string
		fmt.Scanln(&loop)
		if strings.ToLower(loop) == "y" || strings.ToLower(loop) == "yes" {
			continue
		} else {
			break
		}
	}
}
