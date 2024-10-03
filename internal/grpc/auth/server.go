package authgrpc

import (
	"context"
	"errors"
	"sso/internal/services/auth"
	"sso/internal/storage"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ssov1 "github.com/dariasmyr/protos/gen/go/sso"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	ssov1.UnimplementedSessionsServer
	auth Auth
}

type Auth interface {
	ssov1.AuthServer
	ssov1.SessionsServer
}

func Register(gRPCServer *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPCServer, &serverAPI{auth: auth})
	ssov1.RegisterSessionsServer(gRPCServer, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, in *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if in.Email == "" || in.Password == "" || in.AppId == 0 {
		return nil, status.Error(codes.InvalidArgument, "email, password, and app_id are required")
	}

	loginRequest := ssov1.LoginRequest{
		Email:     in.GetEmail(),
		Password:  in.GetPassword(),
		UserAgent: in.GetUserAgent(),
		IpAddress: in.GetIpAddress(),
		AppId:     in.GetAppId(),
	}

	loginResponse, err := s.auth.Login(ctx, &loginRequest)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &ssov1.LoginResponse{
		AccountId:    loginResponse.AccountId,
		Token:        loginResponse.RefreshToken, /// ??????? TODO: access token
		RefreshToken: loginResponse.RefreshToken}, nil
}

func (s *serverAPI) Register(ctx context.Context, in *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if in.Email == "" || in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	registerReq := ssov1.RegisterRequest{
		Email:    in.GetEmail(),
		Password: in.GetPassword(),
		Role:     in.GetRole(),
		AppId:    in.GetAppId(),
	}

	registerResp, err := s.auth.Register(ctx, &registerReq)
	if err != nil {
		if errors.Is(err, storage.ErrAccountExists) {
			return nil, status.Error(codes.AlreadyExists, "account already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register account")
	}

	return &ssov1.RegisterResponse{AccountId: registerResp.AccountId}, nil
}

func (s *serverAPI) Logout(ctx context.Context, in *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	if in.AccountId == 0 {
		return nil, status.Error(codes.InvalidArgument, "account_id is required")
	}

	success, err := s.auth.Logout(ctx, &ssov1.LogoutRequest{AccountId: in.GetAccountId()})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to logout")
	}

	return &ssov1.LogoutResponse{Success: success.Success}, nil
}

func (s *serverAPI) ChangePassword(ctx context.Context, in *ssov1.ChangePasswordRequest) (*ssov1.ChangePasswordResponse, error) {
	if in.AccountId == 0 || in.OldPassword == "" || in.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "account_id, old_password, and new_password are required")
	}

	success, err := s.auth.ChangePassword(ctx, &ssov1.ChangePasswordRequest{
		AccountId:   in.GetAccountId(),
		OldPassword: in.GetOldPassword(),
		NewPassword: in.GetNewPassword(),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to change password")
	}

	return &ssov1.ChangePasswordResponse{Success: success.Success}, nil
}

func (s *serverAPI) ChangeStatus(ctx context.Context, in *ssov1.ChangeStatusRequest) (*ssov1.ChangeStatusResponse, error) {
	if in.AccountId == 0 {
		return nil, status.Error(codes.InvalidArgument, "account_id is required")
	}

	updatedStatus, err := s.auth.ChangeStatus(ctx, &ssov1.ChangeStatusRequest{
		AccountId: in.GetAccountId(),
		Status:    in.GetStatus(),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to change status")
	}

	return &ssov1.ChangeStatusResponse{AccountId: in.GetAccountId(), Status: updatedStatus.Status}, nil
}

func (s *serverAPI) GetActiveSessions(ctx context.Context, in *ssov1.GetActiveAccountSessionsRequest) (*ssov1.GetActiveAccountSessionsResponse, error) {
	if in.AccountId == 0 {
		return nil, status.Error(codes.InvalidArgument, "account_id is required")
	}

	sessions, err := s.auth.GetActiveSessions(ctx, &ssov1.GetActiveAccountSessionsRequest{AccountId: in.GetAccountId()})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get active sessions")
	}

	return &ssov1.GetActiveAccountSessionsResponse{Sessions: sessions.Sessions}, nil
}

func (s *serverAPI) RefreshSession(ctx context.Context, in *ssov1.RefreshAccountSessionRequest) (*ssov1.RefreshAccountSessionResponse, error) {
	if in.AccountId == 0 || in.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "account_id and refresh_token are required")
	}

	req := ssov1.RefreshAccountSessionRequest{
		AccountId:    in.GetAccountId(),
		RefreshToken: in.GetRefreshToken(),
	}

	resp, err := s.auth.RefreshSession(ctx, &req)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to refresh session")
	}

	return &ssov1.RefreshAccountSessionResponse{Token: resp.Token, RefreshToken: resp.RefreshToken, ExpiresAt: resp.ExpiresAt}, nil
}

func (s *serverAPI) ValidateSession(ctx context.Context, in *ssov1.ValidateAccountSessionRequest) (*ssov1.ValidateAccountSessionResponse, error) {
	if in.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	resp, err := s.auth.ValidateSession(ctx, &ssov1.ValidateAccountSessionRequest{Token: in.GetToken()})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to validate session")
	}

	return &ssov1.ValidateAccountSessionResponse{Valid: resp.Valid, ExpiresAt: resp.ExpiresAt}, nil
}

func (s *serverAPI) RevokeSession(ctx context.Context, in *ssov1.RevokeAccountSessionRequest) (*ssov1.RevokeAccountSessionResponse, error) {
	if in.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	success, err := s.auth.RevokeSession(ctx, &ssov1.RevokeAccountSessionRequest{Token: in.GetToken()})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to revoke session")
	}

	return &ssov1.RevokeAccountSessionResponse{Success: success.Success}, nil
}
