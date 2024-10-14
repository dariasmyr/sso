package tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/dariasmyr/protos/gen/go/sso"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sso/tests/suite"
	"testing"
	"time"
)

const (
	appID     = 1
	appSecret = "test-secret"
)

func TestRegisterAccountLogin_Login_Happy_Path(t *testing.T) {
	ctx, st := suite.New(t) // Create suite

	email := gofakeit.Email()
	pass := randomFakePassword()
	ipAddress := randomFakeIPAddress()
	userAgent := randomFakeUserAgent()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetAccountId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:     email,
		Password:  pass,
		AppId:     appID,
		IpAddress: ipAddress,
		UserAgent: userAgent,
	})

	require.NoError(t, err)

	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	loginTime := time.Now()

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})

	require.NoError(t, err)

	// Convert to the jwt.MapClaims type (where we saved the data in)
	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	//Check token data parsed
	assert.Equal(t, respReg.GetAccountId(), int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}

func randomFakePassword() string {
	const passDefaultLen = 10
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}

func randomFakeIPAddress() string {
	return gofakeit.IPv4Address()
}

func randomFakeUserAgent() string {
	return gofakeit.UserAgent()
}

func TestRegisterAccountLogin_DuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t) // Initialized test suite

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetAccountId())

	// Try to register same email
	respRegDup, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})

	// Wait for error for duplicate registration
	require.Error(t, err)
	assert.Empty(t, respRegDup.GetAccountId())
	assert.ErrorContains(t, err, "account already exists")
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		expectedErr string
	}{
		{
			name:        "Register with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			expectedErr: "password is required",
		},
		{
			name:        "Register with Empty Email",
			email:       "",
			password:    randomFakePassword(),
			expectedErr: "email is required",
		},
		{
			name:        "Register with Both Empty",
			email:       "",
			password:    "",
			expectedErr: "email and password are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)

		})
	}
}
