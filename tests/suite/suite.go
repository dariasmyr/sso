package suite

import (
	"context"
	ssov1 "github.com/dariasmyr/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"os"
	"sso/config"
	"strconv"
	"testing"
)

type Suite struct {
	*testing.T
	Cfg           *config.Config
	AuthClient    ssov1.AuthClient
	SessionClient ssov1.SessionsClient
}

const (
	grpcHost = "localhost"
)

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := config.MustLoadFromPath(getConfigPath())

	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
	})

	grpcAddress := net.JoinHostPort(grpcHost, strconv.Itoa(cfg.GRPC.Port))

	cc, err := grpc.NewClient(
		grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc server connection failed: %v", err)
	}

	authClient := ssov1.NewAuthClient(cc)
	sessionClient := ssov1.NewSessionsClient(cc)

	return ctx, &Suite{
		T:             t,
		Cfg:           cfg,
		AuthClient:    authClient,
		SessionClient: sessionClient,
	}
}

func getConfigPath() string {
	const key = "CONFIG_PATH"

	if v := os.Getenv(key); v != "" {
		return v
	}

	return "../config/config_local_tests.yaml"
}
