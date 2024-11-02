package tests

import (
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"sso/tests/suite"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/dariasmyr/protos/gen/go/sso"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	appID     = 1
	appSecret = "test-secret"
)

func TestRegisterAccountLogin_Login_Happy_Path(t *testing.T) {
	ctx, st := suite.New(t) // Create suite

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetAccountId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
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
				AppId:    appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)

		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appID,
			expectedErr: "password is required",
		},
		{
			name:        "Login with Empty Email",
			email:       "",
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "email is required",
		},
		{
			name:        "Login with Both Empty Email and Password",
			email:       "",
			password:    "",
			appID:       appID,
			expectedErr: "email is required",
		},
		{
			name:        "Login with Non-Matching Password",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "invalid email or password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    gofakeit.Email(),
				Password: randomFakePassword(),
				AppId:    appID,
			})
			require.NoError(t, err)

			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Email:    tt.email,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestChangePassword_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)
	accountID := respReg.GetAccountId()
	require.NotEmpty(t, accountID)

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respLogin.GetToken())
	require.NotEmpty(t, respLogin.GetRefreshToken())

	md := metadata.Pairs(
		"authorization", respLogin.GetToken(),
		"refresh-token", respLogin.GetRefreshToken(),
	)

	ctxWithTokens := metadata.NewOutgoingContext(ctx, md)

	newPass := randomFakePassword()
	_, err = st.AuthClient.ChangePassword(ctxWithTokens, &ssov1.ChangePasswordRequest{
		OldPassword: pass,
		NewPassword: newPass,
	})

	respLogin, err = st.AuthClient.Login(ctxWithTokens, &ssov1.LoginRequest{
		Email:    email,
		Password: newPass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respLogin.GetToken())
}

func TestChangePassword_InvalidOldPassword(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)
	accountID := respReg.GetAccountId()
	require.NotEmpty(t, accountID)

	newPass := randomFakePassword()
	_, err = st.AuthClient.ChangePassword(ctx, &ssov1.ChangePasswordRequest{
		OldPassword: "wrong-old-password",
		NewPassword: newPass,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid credentials")
}

func TestLogout_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)
	accountID := respReg.GetAccountId()

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respLogin.GetToken())

	_, err = st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
		AccountId: accountID,
	})
	require.NoError(t, err)

	_, err = st.SessionClient.ValidateSession(ctx, &emptypb.Empty{})
	require.Error(t, err)
}

func TestRefreshSession_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	refreshToken := respLogin.GetRefreshToken()
	require.NotEmpty(t, refreshToken)

	respRefresh, err := st.SessionClient.RefreshSession(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotEmpty(t, respRefresh.GetToken())
}

func TestRegisterNewApp_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	appName := gofakeit.AppName()
	secret := randomFakePassword()
	redirectUrl := "https://example.com/callback"

	resp, err := st.AuthClient.RegisterClient(ctx, &ssov1.RegisterClientRequest{
		AppName:     appName,
		Secret:      secret,
		RedirectUrl: redirectUrl,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetAppId())
}

func TestRegisterNewApp_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		appName     string
		secret      string
		redirectUrl string
		expectedErr string
	}{
		{
			name:        "Empty App Name",
			appName:     "",
			secret:      randomFakePassword(),
			redirectUrl: "https://example.com/callback",
			expectedErr: "app_name is required",
		},
		{
			name:        "Invalid Redirect URL",
			appName:     gofakeit.AppName(),
			secret:      randomFakePassword(),
			redirectUrl: "invalid-url",
			expectedErr: "invalid redirect_url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.RegisterClient(ctx, &ssov1.RegisterClientRequest{
				AppName:     tt.appName,
				Secret:      tt.secret,
				RedirectUrl: tt.redirectUrl,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestChangeStatus_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)
	accountID := respReg.GetAccountId()

	newStatus := ssov1.AccountStatus_INACTIVE
	updatedStatus, err := st.AuthClient.ChangeStatus(ctx, &ssov1.ChangeStatusRequest{
		AccountId: accountID,
		Status:    newStatus,
	})
	require.NoError(t, err)
	assert.Equal(t, newStatus, updatedStatus.GetStatus())
}

func TestChangeStatus_UnauthorizedRole(t *testing.T) {
	ctx, st := suite.New(t)

	validAccountID := int64(1)
	_, err := st.AuthClient.ChangeStatus(ctx, &ssov1.ChangeStatusRequest{
		AccountId: validAccountID,
		Status:    ssov1.AccountStatus_ACTIVE,
	})

	require.Error(t, err)
	assert.ErrorContains(t, err, "no permission to access this RPC")
}

func TestChangeStatus_InvalidAccount(t *testing.T) {
	ctx, st := suite.New(t)

	invalidAccountID := int64(99999)
	_, err := st.AuthClient.ChangeStatus(ctx, &ssov1.ChangeStatusRequest{
		AccountId: invalidAccountID,
		Status:    ssov1.AccountStatus_ACTIVE,
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "account not found")
}

func TestGetActiveAccountSessions_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)

	_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)

	sessions, err := st.SessionClient.GetActiveSessions(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Greater(t, len(sessions.GetSessions()), 0)
}

func TestGetActiveAccountSessions_NoSessions(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)

	sessions, err := st.SessionClient.GetActiveSessions(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, 0, len(sessions.GetSessions()))
}

func TestValidateAccountSession_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	pass := randomFakePassword()

	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)

	_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)

	valid, err := st.SessionClient.ValidateSession(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.True(t, valid.GetValid())
}

func TestValidateAccountSession_InvalidToken(t *testing.T) {
	ctx, st := suite.New(t)

	invalidToken := "invalid-token"
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", invalidToken)

	_, err := st.SessionClient.ValidateSession(ctx, &emptypb.Empty{})

	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to validate session")
}
