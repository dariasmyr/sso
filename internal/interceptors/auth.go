package interceptors

import (
	"context"
	"sso/internal/lib/jwt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type UserClaimsKeyType struct{}

var UserClaimsKey = UserClaimsKeyType{}

type AuthInterceptor struct {
	accessibleRoles map[string][]int32
}

func NewAuthInterceptor(accessibleRoles map[string][]int32) *AuthInterceptor {
	return &AuthInterceptor{accessibleRoles}
}

func (interceptor *AuthInterceptor) authorize(ctx context.Context, method string) (context.Context, error) {
	accessibleRoles, ok := interceptor.accessibleRoles[method]

	if !ok {
		// everyone can access
		return ctx, nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return ctx, status.Errorf(codes.Unauthenticated, "missing authorization token")
	}

	accessToken := values[0]
	claims, err := jwt.DecodeTokenPayload(accessToken)
	if err != nil {
		ctx = context.WithValue(ctx, UserClaimsKey, claims)
		return ctx, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	for _, role := range accessibleRoles {
		if role == claims.Role {
			ctx = context.WithValue(ctx, UserClaimsKey, claims)
			return ctx, nil
		}
	}

	return ctx, status.Error(codes.PermissionDenied, "no permission to access this RPC")
}

func (interceptor *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {

		newCtx, err := interceptor.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		return handler(newCtx, req)
	}
}
