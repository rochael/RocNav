package auth

import (
	"fmt"
	"net/url"

	"github.com/pquerna/otp/totp"
)

func GenerateTOTPSecret(email, issuer string) (secret string, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: email})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func ValidateTOTP(secret, passcode string) bool {
	if secret == "" {
		return false
	}
	return totp.Validate(passcode, secret)
}

func URL(secret, email, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", urlQuery(issuer), urlQuery(email), secret, urlQuery(issuer))
}

func urlQuery(s string) string {
	r := url.QueryEscape(s)
	return r
}

func QRDataURL(keyURL string) string {
	return fmt.Sprintf("otpauth://%s", keyURL)
}
