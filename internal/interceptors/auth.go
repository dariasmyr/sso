package interceptors

import (
	"context"
	"sso/internal/lib/jwt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type userClaimsKeyType struct{}

var userClaimsKey = userClaimsKeyType{}

type AuthInterceptor struct {
	secret          string
	accessibleRoles map[string][]int32
}

func NewAuthInterceptor(secret string, accessibleRoles map[string][]int32) *AuthInterceptor {
	return &AuthInterceptor{secret, accessibleRoles}
}

func (interceptor *AuthInterceptor) authorize(ctx context.Context, method string) (context.Context, error) {
	secret := interceptor.secret

	if secret == "" {
		return ctx, status.Errorf(codes.Unauthenticated, "missing secret")
	}

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
	claims, err := jwt.ParseToken(accessToken, secret)
	if err != nil {
		ctx = context.WithValue(ctx, userClaimsKey, claims)
		return ctx, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	for _, role := range accessibleRoles {
		if role == claims.Role {
			ctx = context.WithValue(ctx, userClaimsKey, claims)
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
