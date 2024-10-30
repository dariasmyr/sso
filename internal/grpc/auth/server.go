package authgrpc

import (
	"context"
	"errors"
	"net/netip"
	"sso/internal/services/auth"
	"sso/internal/storage"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	ssov1 "github.com/dariasmyr/protos/gen/go/sso"

	interceptorauth "sso/internal/interceptors"
	jwt "sso/internal/lib/jwt"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	ssov1.UnimplementedSessionsServer
	auth Auth
}

type Auth interface {
	Login(ctx context.Context, email string, password string) (accountId int64, token string, refreshToken string, err error)
	Logout(ctx context.Context, accountID int64) (success bool, err error)
	RegisterNewAccount(ctx context.Context, email string, password string, role ssov1.AccountRole, appId int32) (accountID int64, err error)
	RegisterNewApp(ctx context.Context, appName string, secret string, redirectUrl string) (appId int64, err error)
	ChangePassword(ctx context.Context, accountID int64, oldPassword, newPassword string) (success bool, err error)
	ChangeStatus(ctx context.Context, accountID int64, status ssov1.AccountStatus) (updatedStatus ssov1.AccountStatus, err error)
	GetActiveAccountSessions(ctx context.Context, accountID int64) ([]*ssov1.Session, error)
	RefreshAccountSession(ctx context.Context, accountID int64, refreshToken string, userAgent string, ipAddress string) (token string, newRefreshToken string, expiresAt int64, err error)
	ValidateAccountSession(ctx context.Context, token string) (valid bool, err error)
	RevokeAccountSession(ctx context.Context, token string) (success bool, err error)
}

func Register(gRPCServer *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPCServer, &serverAPI{auth: auth})
	ssov1.RegisterSessionsServer(gRPCServer, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, in *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	claims, ok := ctx.Value(interceptorauth.UserClaimsKey).(*jwt.CustomClaims)
	if !ok || claims.AppID == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required or missing")
	}

	if in.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	if claims.AppID == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	ipAddress, ok := realip.FromContext(ctx)
	if !ok {
		ipAddress = netip.Addr{}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "metadata is missing")
	}

	userAgent := "unknown"
	if ua, found := md["user-agent"]; found && len(ua) > 0 {
		userAgent = ua[0]
	}

	if in.Email == "" && in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	userAgent := in.GetUserAgent()
	if userAgent == "" {
		userAgent = "unknown"
	}

	ipAddress := in.GetIpAddress()
	if ipAddress == "" {
		ipAddress = "unknown"
	}

	accountId, accessToken, refreshToken, err := s.auth.Login(ctx, in.GetEmail(), in.GetPassword(), userAgent, ipAddress, in.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &ssov1.LoginResponse{
		AccountId:    accountId,
		Token:        accessToken,
		RefreshToken: refreshToken}, nil
}

func (s *serverAPI) Register(ctx context.Context, in *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if in.Email == "" && in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	if in.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	if in.AppId == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	uid, err := s.auth.RegisterNewAccount(ctx, in.GetEmail(), in.GetPassword(), in.GetRole(), in.GetAppId())
	if err != nil {
		if errors.Is(err, storage.ErrAccountExists) {
			return nil, status.Error(codes.AlreadyExists, "account already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register account")
	}

	return &ssov1.RegisterResponse{AccountId: uid}, nil
}

func (s *serverAPI) RegisterClient(ctx context.Context, in *ssov1.RegisterClientRequest) (*ssov1.RegisterClientResponse, error) {
	if in.AppName == "" && in.Secret == "" && in.RedirectUrl == "" {
		return nil, status.Error(codes.InvalidArgument, "app_name, secret, and redirect_url are required")
	}

	if in.AppName == "" {
		return nil, status.Error(codes.InvalidArgument, "app_name is required")
	}

	if in.Secret == "" {
		return nil, status.Error(codes.InvalidArgument, "service is required")
	}

	if in.RedirectUrl == "" {
		return nil, status.Error(codes.InvalidArgument, "redirect_url is required")
	}

	if !isValidRedirectUrl(in.RedirectUrl) {
		return nil, status.Error(codes.InvalidArgument, "invalid redirect_url format")
	}

	uid, err := s.auth.RegisterNewApp(ctx, in.GetAppName(), in.GetSecret(), in.GetRedirectUrl())
	if err != nil {
		if errors.Is(err, storage.ErrAppExists) {
			return nil, status.Error(codes.AlreadyExists, "app already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register app")
	}

	return &ssov1.RegisterClientResponse{AppId: uid}, nil
}

func (s *serverAPI) Logout(ctx context.Context, in *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	if in.AccountId == 0 {
		return nil, status.Error(codes.InvalidArgument, "account_id is required")
	}

	success, err := s.auth.Logout(ctx, in.GetAccountId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to logout")
	}

	return &ssov1.LogoutResponse{Success: success}, nil
}

func (s *serverAPI) ChangePassword(ctx context.Context, in *ssov1.ChangePasswordRequest) (*ssov1.ChangePasswordResponse, error) {
	if in.AccountId == 0 || in.OldPassword == "" || in.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "account_id, old_password, and new_password are required")
	}

	success, err := s.auth.ChangePassword(ctx, in.GetAccountId(), in.GetOldPassword(), in.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "invalid credentials")
	}

	return &ssov1.ChangePasswordResponse{Success: success}, nil
}

func (s *serverAPI) ChangeStatus(ctx context.Context, in *ssov1.ChangeStatusRequest) (*ssov1.ChangeStatusResponse, error) {
	if in.AccountId == 0 {
		return nil, status.Error(codes.InvalidArgument, "account_id is required")
	}

	updatedStatus, err := s.auth.ChangeStatus(ctx, in.GetAccountId(), in.GetStatus())
	if err != nil {
		if errors.Is(err, storage.ErrAccountNotFound) {
			return nil, status.Error(codes.NotFound, "account not found")
		}
		return nil, status.Error(codes.Internal, "failed to change status")
	}

	return &ssov1.ChangeStatusResponse{AccountId: in.GetAccountId(), Status: updatedStatus}, nil
}

func (s *serverAPI) GetActiveSessions(ctx context.Context, in *ssov1.GetActiveAccountSessionsRequest) (*ssov1.GetActiveAccountSessionsResponse, error) {
	if in.AccountId == 0 {
		return nil, status.Error(codes.InvalidArgument, "account_id is required")
	}

	sessions, err := s.auth.GetActiveAccountSessions(ctx, in.GetAccountId())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get active sessions")
	}

	return &ssov1.GetActiveAccountSessionsResponse{Sessions: sessions}, nil
}

func (s *serverAPI) RefreshSession(ctx context.Context, in *ssov1.RefreshAccountSessionRequest) (*ssov1.RefreshAccountSessionResponse, error) {
	if in.AccountId == 0 || in.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "account_id and refresh_token are required")
	}

	userAgent := in.GetUserAgent()
	if userAgent == "" {
		userAgent = "unknown"
	}

	ipAddress := in.GetIpAddress()
	if ipAddress == "" {
		ipAddress = "unknown"
	}

	token, refreshToken, expiresAt, err := s.auth.RefreshAccountSession(ctx, in.GetAccountId(), in.GetRefreshToken(), userAgent, ipAddress)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to refresh session")
	}

	return &ssov1.RefreshAccountSessionResponse{Token: token, RefreshToken: refreshToken, ExpiresAt: expiresAt}, nil
}

func (s *serverAPI) ValidateSession(ctx context.Context, in *ssov1.ValidateAccountSessionRequest) (*ssov1.ValidateAccountSessionResponse, error) {
	if in.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	valid, err := s.auth.ValidateAccountSession(ctx, in.GetToken())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to validate session")
	}

	return &ssov1.ValidateAccountSessionResponse{Valid: valid}, nil
}

func (s *serverAPI) RevokeSession(ctx context.Context, in *ssov1.RevokeAccountSessionRequest) (*ssov1.RevokeAccountSessionResponse, error) {
	if in.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	success, err := s.auth.RevokeAccountSession(ctx, in.GetToken())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to revoke session")
	}

	return &ssov1.RevokeAccountSessionResponse{Success: success}, nil
}
