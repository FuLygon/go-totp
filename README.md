# go-totp

Package `go-totp` library implements functionalities to create and validate Time-Based One-Time Password (TOTP) for Two-Factor Authentication (2FA) applications. 

TOTP generates temporary, single-use codes based on a shared secret key, enhancing login security.

## Installation
Use `go get`
```shell
go get -u github.com/FuLygon/go-totp/v2
```
Import package
```go
import "github.com/FuLygon/go-totp/v2"
```

## Example
See [Example](example/main.go)

## Usage

### Create TOTP

#### Generate or define a TOTP instance
```go
t, err := totp.New(totp.TOTP{
    AccountName: "your_account_name",
    Issuer:      "your_issuer_name",
})
if err != nil {
    // handle error
    log.Println("error generating QR code:", err)
    return
}

// optionally, define TOTP details:
t := totp.TOTP{
    AccountName: "your_account_name",
    Issuer:      "your_issuer_name",
    Algorithm:   totp.AlgorithmSHA1,
    Digits:      6,
    Period:      30,
    Secret:      "your_shared_secret",
}
```

#### Generate TOTP URL and QR code
```go
// generate TOTP URL
url, err := t.GetURL()
if err != nil {
    // handle error
    log.Println("error generating TOTP URL:", err)
    return
}
fmt.Println("TOTP URL:", url)

// generate QR code
qr, err := t.GetQR(256)
if err != nil {
    // handle error
    log.Println("error generating QR code:", err)
    return
}
fmt.Println("QR Code Base64:", qr.Base64)
```

### Validating TOTP code

#### Create a validator instance
```go
v := totp.Validator{
  Algorithm: totp.AlgorithmSHA1,
  Digits:    6,
  Period:    30,
  Secret:    "your_shared_secret",
}
```

#### Validate a TOTP code
```go
code := "123456" // user-provided TOTP code

valid, err := v.Validate(code)
if err != nil {
    // handle error
    fmt.Println("error validating TOTP code:", err)
    return
}

if valid {
    fmt.Println("TOTP code is valid!")
} else {
    fmt.Println("TOTP code is invalid.")
}
```