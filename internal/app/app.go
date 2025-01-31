package app

import (
	"log/slog"
	"time"

	grpcapp "sso/internal/app/grpc"
	"sso/internal/services/auth"
)

type App struct {
	GRPCServer *grpcapp.App
	StorageApp *StorageApp
}

func New(
	log *slog.Logger,
	grpcPort int,
	storageApp *StorageApp,
	tokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	trustedPeers []string,
) *App {

	authService := auth.New(log, storageApp.Storage(), storageApp.Storage(), storageApp.Storage(), storageApp.Storage(), storageApp.Storage(), storageApp.Storage(), tokenTTL, refreshTokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort, trustedPeers)

	return &App{
		GRPCServer: grpcApp,
		StorageApp: storageApp,
	}
}
