package interceptors

import (
	"context"
	"sso/internal/lib/jwt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthInterceptor struct {
	secret          string
	accessibleRoles map[string][]int32
}

func NewAuthInterceptor(secret string, accessibleRoles map[string][]int32) *AuthInterceptor {
	return &AuthInterceptor{secret, accessibleRoles}
}

func (interceptor *AuthInterceptor) authorize(ctx context.Context, method string) error {
	secret := interceptor.secret

	if secret == "" {
		return status.Errorf(codes.Unauthenticated, "missing secret")
	}

	accessibleRoles, ok := interceptor.accessibleRoles[method]

	if !ok {
		// everyone can access
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing authorization token")
	}

	accessToken := values[0]
	claims, err := jwt.ParseToken(accessToken, secret)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "invalid token")
	}

	for _, role := range accessibleRoles {
		if role == claims.Role {
			return nil
		}
	}

	return status.Error(codes.PermissionDenied, "no permission to access this RPC")
}

func (interceptor *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {

		err := interceptor.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}
