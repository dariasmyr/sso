package main

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/dariasmyr/protos/gen/go/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sso/tests/suite"
	"testing"
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

	// Check results respLogin

	// Get access token (JWT) and validate the data
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}

func randomFakeIPAddress() string {
	return gofakeit.IPv4Address()
}

func randomFakeUserAgent() string {
	return gofakeit.UserAgent()
}
