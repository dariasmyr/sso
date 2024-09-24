package authgrpc

import (
	"context"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/services/auth"

	ssov1 "github.com/dariasmyr/protos/gen/go/sso"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	ssov1.UnimplementedSessionsServer
	auth Auth
}

type Auth interface {
	Login(ctx context.Context, email string, password string, appID int) (accountId int64, token string, refreshToken string, err error)
	Logout(ctx context.Context, accountID int64) (success bool, err error)
	RegisterNewAccount(ctx context.Context, email string, password string, role ssov1.AccountRole) (accountID int64, err error)
	ChangePassword(ctx context.Context, accountID int64, oldPassword, newPassword string) (success bool, err error)
	ChangeStatus(ctx context.Context, accountID int64, status ssov1.AccountStatus) (updatedStatus ssov1.AccountStatus, err error)
	GetActiveAccountSessions(ctx context.Context, accountID int64) ([]*ssov1.Session, error)
	RefreshAccountSession(ctx context.Context, accountID int64, refreshToken string) (token string, newRefreshToken string, expiresAt int64, err error)
	ValidateAccountSession(ctx context.Context, token string) (valid bool, expiresAt int64, err error)
	RevokeAccountSession(ctx context.Context, token string) (success bool, err error)
}

func Register(gRPCServer *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPCServer, &serverAPI{auth: auth})
	ssov1.RegisterSessionsServer(gRPCServer, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, in *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if in.Email == "" || in.Password == "" || in.GetAppId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "email, password, and app_id are required")
	}

	accountId, accessToken, refreshToken, err := s.auth.Login(ctx, in.GetEmail(), in.GetPassword(), int(in.GetAppId()))
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
	if in.Email == "" || in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	uid, err := s.auth.RegisterNewAccount(ctx, in.GetEmail(), in.GetPassword(), ssov1.AccountRole(in.GetRole()))
	if err != nil {
		if errors.Is(err, storage.ErrAccountExists) {
			return nil, status.Error(codes.AlreadyExists, "account already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register account")
	}

	return &ssov1.RegisterResponse{AccountId: uid}, nil
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
		return nil, status.Error(codes.Internal, "failed to change password")
	}

	return &ssov1.ChangePasswordResponse{Success: success}, nil
}

func (s *serverAPI) ChangeStatus(ctx context.Context, in *ssov1.ChangeStatusRequest) (*ssov1.ChangeStatusResponse, error) {
	if in.AccountId == 0 {
		return nil, status.Error(codes.InvalidArgument, "account_id is required")
	}

	updatedStatus, err := s.auth.ChangeStatus(ctx, in.GetAccountId(), in.GetStatus())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to change status")
	}

	return &ssov1.ChangeStatusResponse{AccountId: in.GetAccountId(), Status: ssov1.AccountStatus(updatedStatus)}, nil
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

	token, refreshToken, expiresAt, err := s.auth.RefreshAccountSession(ctx, in.GetAccountId(), in.GetRefreshToken())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to refresh session")
	}

	return &ssov1.RefreshAccountSessionResponse{Token: token, RefreshToken: refreshToken, ExpiresAt: expiresAt}, nil
}

func (s *serverAPI) ValidateSession(ctx context.Context, in *ssov1.ValidateAccountSessionRequest) (*ssov1.ValidateAccountSessionResponse, error) {
	if in.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	valid, expiresAt, err := s.auth.ValidateAccountSession(ctx, in.GetToken())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to validate session")
	}

	return &ssov1.ValidateAccountSessionResponse{Valid: valid, ExpiresAt: expiresAt}, nil
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
