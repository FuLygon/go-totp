package main

import (
	"fmt"
	"github.com/FuLygon/go-totp/v2"
	"github.com/skip2/go-qrcode"
	"image/png"
	"os"
	"strings"
)

// all parameters were fully supported by Aegis Authenticator (https://play.google.com/store/apps/details?id=com.beemdevelopment.aegis)
var (
	issuer              = "example.com"
	accountName         = "example@example.com"
	algorithm           = totp.AlgorithmSHA1 // the commonly supported value is AlgorithmSHA1, other value might get ignored or unsupported by some app.
	digits       uint8  = 6                  // the commonly supported values are 6 and 8, other value might get ignored or unsupported by some app, the allowed value range is between 1 and 10.
	period       uint64 = 30                 // the commonly supported values are 30 and 60, other value might get ignored or unsupported by most app.
	skew         uint   = 1
	customSecret        = "IZMPDHTBXXOYYWR4SC4Q"
)

func main() {
	// generate totp info with random secret
	totpInfo, err := totp.New(totp.TOTP{
		AccountName: accountName,
		Issuer:      issuer,
	})
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
			Skew:      skew,
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
