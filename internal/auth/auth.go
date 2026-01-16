package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func HashPassword(pwd string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	return string(b), err
}

func VerifyPassword(hash, pwd string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pwd))
}

func GenerateJWT(secret []byte, issuer string, ttl time.Duration, userID uint, email string) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "auth",
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func ParseJWT(secret []byte, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("invalid signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if c, ok := token.Claims.(*Claims); ok && token.Valid {
		return c, nil
	}
	return nil, errors.New("invalid token")
}
