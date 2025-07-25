package grpcapp

import (
	"context"
	"fmt"
	ssov1 "github.com/dariasmyr/protos/gen/go/sso"
	"log/slog"
	"net"
	"sso/internal/interceptors"

	authgrpc "sso/internal/grpc/auth"

	"net/netip"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"google.golang.org/grpc"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		maskedFields := MaskSensitiveFields(fields)
		l.Log(ctx, slog.Level(lvl), msg, maskedFields...)
	})
}

func accessibleRoles() map[string][]string {
	const authServicePath = "/auth.Auth/"
	const sessionsServicePath = "/auth.Sessions/"

	return map[string][]string{
		authServicePath + "ChangeStatus":      {ssov1.AccountRole_ADMIN.String()},
		sessionsServicePath + "RevokeSession": {ssov1.AccountRole_ADMIN.String()},
	}
}

func unauthenticatedMethods() []string {
	return []string{
		"/auth.Auth/Register",
		"/auth.Auth/RegisterClient",
		"/auth.Auth/Login",
	}
}

// New creates new gRPC server app.
func New(log *slog.Logger, authService authgrpc.Auth, port int, trustedPeers []string) *App {
	loggingOpts := []logging.Option{
		logging.WithLogOnEvents(
			logging.PayloadReceived, logging.PayloadSent,
		),
	}

	recoveryOpts := []recovery.Option{
		recovery.WithRecoveryHandler(func(p interface{}) (err error) {
			log.Error("Recovered from panic", slog.Any("panic", p))

			return status.Errorf(codes.Internal, "Panic occurred: %v", p)
			// return status.Errorf(codes.Internal, "internal error") in case we want the error to be hidden from client
		}),
	}

	var trustedPeersParsed []netip.Prefix
	for _, peer := range trustedPeers {
		parsedPeer, err := netip.ParsePrefix(peer)
		if err != nil {
			log.Error("Invalid IP or subnet", slog.String("peer", peer))
			continue
		}
		trustedPeersParsed = append(trustedPeersParsed, parsedPeer)
	}
	log.Info("Trusted peers", slog.Any("peers", trustedPeersParsed))
	headers := []string{realip.XForwardedFor, realip.XRealIp}

	realIpOpts := []realip.Option{
		realip.WithTrustedPeers(trustedPeersParsed),
		realip.WithHeaders(headers),
		realip.WithTrustedProxiesCount(1),
	}

	authInterceptor := interceptors.NewAuthInterceptor(accessibleRoles(), unauthenticatedMethods())

	logHeadersInterceptor := interceptors.NewLogHeadersInterceptor(log)

	// Create new gRPC server and add logging and recovery interceptors
	gRPCServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		recovery.UnaryServerInterceptor(recoveryOpts...),
		realip.UnaryServerInterceptorOpts(realIpOpts...),
		authInterceptor.AuthorizeUnary(),
		logHeadersInterceptor.LogHeadersUnary(),
		logging.UnaryServerInterceptor(InterceptorLogger(log), loggingOpts...),
	))

	// Register GRPC Auth server with gRPC server
	authgrpc.Register(gRPCServer, authService)

	// Return new app with gRPC server
	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

func (a *App) MustRun() error {
	if err := a.Run(); err != nil {
		return err
	}
	return nil
}

func (a *App) Run() error {
	const op = "grpcapp.Run"

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	a.log.Info("grpc server started", slog.String("addr", l.Addr().String()))

	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) GracefulStop() {
	const op = "grpcapp.GracefullStop"

	a.log.With(slog.String("op", op)).
		Info("gracefully stopping gRPC server", slog.Int("port", a.port))

	a.gRPCServer.GracefulStop()
}

func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).
		Info("forcefully stopping gRPC server", slog.Int("port", a.port))

	a.gRPCServer.Stop()
}
