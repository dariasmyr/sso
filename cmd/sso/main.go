package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sso/config"
	"sso/internal/app"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

const (
	_shutdownPeriod      = 15 * time.Second
	_shutdownHardPeriod  = 3 * time.Second
	_readinessDrainDelay = 5 * time.Second
)

var isShuttingDown atomic.Bool

func main() {
	cfg := config.MustLoad()
	log := setupLogger(cfg.Env)

	log.Info("sso", "env", cfg.Env)

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	storageApp, initStorageErr := app.NewStorageApp(cfg.StoragePath)
	if initStorageErr != nil {
		panic(initStorageErr)
	}
	defer func(storageApp *app.StorageApp) {
		closeStorageApp := storageApp.Stop()
		if closeStorageApp != nil {
			log.Error("closing storage app", "err", closeStorageApp)
		}
	}(storageApp)

	application := app.New(log, cfg.GRPC.Port, storageApp, cfg.TokenTTL, cfg.RefreshTTL, cfg.GRPC.Trusted)

	go func() {
		log.Info("Server starting on protocol", "port", cfg.GRPC.Port)
		if appRunErr := application.GRPCServer.MustRun(); appRunErr != nil {
			panic(appRunErr)
		}
	}()

	// Waiting for SIGINT (pkill -2) or SIGTERM
	<-rootCtx.Done()
	stop()

	isShuttingDown.Store(true)
	log.Info("Received shutdown signal, shutting down gracefully")

	// Give time for readiness check to propagate
	time.Sleep(_readinessDrainDelay)
	log.Info("Readiness check propagated, now waiting for ongoing requests to finish.")

	closeStorageApp := storageApp.Stop()
	if closeStorageApp != nil {
		log.Error("closing storage app", "err", closeStorageApp)
	}

	timer := time.AfterFunc(_shutdownPeriod, func() {
		log.Error("Server couldn't stop gracefully in time. Doing force stop.")
		application.GRPCServer.Stop()
	})
	defer timer.Stop()

	application.GRPCServer.GracefulStop()
	log.Info("Server shut down gracefully.")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
