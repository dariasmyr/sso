package jwt

import (
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"time"

	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"encoding/base64"
	"encoding/json"
)

type CustomClaims struct {
	AccountID int64  `json:"uid"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	AppID     int32  `json:"app_id"`
	jwt.RegisteredClaims
}

func NewToken(account *models.Account, app *models.App, duration time.Duration) (string, error) {
	if account.ID == 0 || app.ID == 0 || app.Secret == "" {
		return "", errors.New("not enough data for token generation")
	}

	claims := CustomClaims{
		AccountID: account.ID,
		Email:     account.Email,
		Role:      account.Role,
		Status:    account.Status,
		AppID:     app.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			ID:        generateJTI(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ParseToken(tokenString string, secret string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func generateJTI() string {
	return uuid.New().String()
}

func DecodeTokenPayload(tokenString string) (*CustomClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding payload: %w", err)
	}

	var claims CustomClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("error parsing claims: %w", err)
	}

	return &claims, nil
}
