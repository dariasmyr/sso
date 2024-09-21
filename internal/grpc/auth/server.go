package authgrpc

import (
	"context"
	"google.golang.org/grpc"

	ssov1 "github.com/dariasmyr/protos/gen/go/sso"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	ssov1.UnimplementedSessionsServer
	auth Auth
}

type Auth interface {
	Login(ctx context.Context, email string, password string, appID int) (token string, err error)
	RegisterNewUser(ctx context.Context, email string, password string) (userID int64, err error)
	ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) (success bool, err error)
	ChangeStatus(ctx context.Context, userID int64, status ssov1.AccountStatus) (updatedStatus ssov1.AccountStatus, err error)
}

func Register(gRPCServer *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPCServer, &serverAPI{auth: auth})
	ssov1.RegisterSessionsServer(gRPCServer, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, in *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	// TODO: implement me
	return nil, nil
}

func (s *serverAPI) Register(ctx context.Context, in *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	// TODO: implement me
	return nil, nil
}

func (s *serverAPI) Logout(ctx context.Context, in *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	// TODO: implement me
	return nil, nil
}

func (s *serverAPI) ChangePassword(ctx context.Context, in *ssov1.ChangePasswordRequest) (*ssov1.ChangePasswordResponse, error) {
	// TODO: implement me
	return nil, nil
}

func (s *serverAPI) ChangeStatus(ctx context.Context, in *ssov1.ChangeStatusRequest) (*ssov1.ChangeStatusResponse, error) {
	// TODO: implement me
	return nil, nil
}

func (s *serverAPI) GetActiveSessions(ctx context.Context, in *ssov1.GetActiveUserSessionsRequest) (*ssov1.GetActiveUserSessionsResponse, error) {
	// TODO: implement me
	return nil, nil
}

func (s *serverAPI) RefreshSession(ctx context.Context, in *ssov1.RefreshUserSessionRequest) (*ssov1.RefreshUserSessionResponse, error) {
	// TODO: implement me
	return nil, nil
}

func (s *serverAPI) ValidateSession(ctx context.Context, in *ssov1.ValidateUserSessionRequest) (*ssov1.ValidateUserSessionResponse, error) {
	// TODO: implement me
	return nil, nil
}

func (s *serverAPI) RevokeSession(ctx context.Context, in *ssov1.RevokeUserSessionRequest) (*ssov1.RevokeUserSessionResponse, error) {
	// TODO: implement me
	return nil, nil
}
