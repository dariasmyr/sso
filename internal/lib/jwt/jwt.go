package jwt

import (
	"fmt"
	"sso/internal/domain/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// NewToken creates new JWT token for given user and app.
func NewToken(user models.Account, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID
	claims["jti"] = generateJTI()

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func generateJTI() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
