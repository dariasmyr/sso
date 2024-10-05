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
	storagePath string,
	tokenTTL time.Duration,
	refreshTokenTTL time.Duration,
) *App {
	storageApp, err := NewStorageApp(storagePath)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storageApp.Storage(), storageApp.Storage(), storageApp.Storage(), storageApp.Storage(), storageApp.Storage(), storageApp.Storage(), tokenTTL, refreshTokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{
		GRPCServer: grpcApp,
		StorageApp: storageApp,
	}
}
