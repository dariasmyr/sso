package interceptors

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type LogHeadersInterceptor struct {
	logger *slog.Logger
}

func NewLogHeadersInterceptor(logger *slog.Logger) *LogHeadersInterceptor {
	return &LogHeadersInterceptor{logger: logger}
}

func (i *LogHeadersInterceptor) LogHeadersUnary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			for key, values := range md {
				// Log values from metadata
				for _, value := range values {
					i.logger.Info("Header", slog.String("key", key), slog.String("value", value))
				}
			}
		}

		// Call next handler
		return handler(ctx, req)
	}
}
