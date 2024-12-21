package interceptors

import (
	"context"
	"log"
	"sso/internal/lib/jwt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type UserClaimsKeyType struct{}

var UserClaimsKey = UserClaimsKeyType{}

type AuthInterceptor struct {
	accessibleRoles        map[string][]int32
	unauthenticatedMethods map[string]struct{}
}

func NewAuthInterceptor(accessibleRoles map[string][]int32, unauthenticatedMethods []string) *AuthInterceptor {
	unauthenticatedMap := make(map[string]struct{})
	for _, method := range unauthenticatedMethods {
		unauthenticatedMap[method] = struct{}{}
	}
	return &AuthInterceptor{accessibleRoles, unauthenticatedMap}
}

func (interceptor *AuthInterceptor) extractClaims(ctx context.Context) (*jwt.CustomClaims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	log.Printf("Metedata: %v", md)

	values := md["authorization"]
	if len(values) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing authorization token")
	}

	accessToken := values[0]
	claims, err := jwt.DecodeTokenPayload(accessToken)
	if err != nil {
		log.Printf("Error decoding token: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	log.Printf("Decoded claims: %v", claims)
	return claims, nil
}

func (interceptor *AuthInterceptor) authorize(ctx context.Context, method string) (context.Context, error) {
	if _, ok := interceptor.unauthenticatedMethods[method]; ok {
		log.Printf("Skipping authorization for unauthenticated method: %s", method)
		return ctx, nil
	}

	claims, err := interceptor.extractClaims(ctx)
	if err != nil {
		return ctx, err
	}

	ctx = context.WithValue(ctx, UserClaimsKey, claims)
	log.Printf("Claims added to context: %v", claims)

	accessibleRoles, ok := interceptor.accessibleRoles[method]
	if !ok {
		return ctx, nil
	}

	for _, role := range accessibleRoles {
		if role == claims.Role {
			return ctx, nil
		}
	}

	log.Printf("Claims do not match any accessible roles: %v", claims)

	return ctx, status.Error(codes.PermissionDenied, "no permission to access this RPC")
}

func (interceptor *AuthInterceptor) AuthorizeUnary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		newCtx, err := interceptor.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		retrievedClaims, ok := newCtx.Value(UserClaimsKey).(*jwt.CustomClaims)
		if !ok {
			log.Println("User claims not found in new context.")
		} else {
			log.Printf("User claims found in new context: %v", retrievedClaims)
		}

		return handler(newCtx, req)
	}
}
