package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/techbudol1/gmr-vault/internal/config"
	"github.com/techbudol1/gmr-vault/internal/httpapi"
	"github.com/techbudol1/gmr-vault/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	vaultStore, err := store.NewMemgraphStore(ctx, cfg.MemgraphURI, cfg.MemgraphUser, cfg.MemgraphPassword)
	if err != nil {
		log.Fatalf("memgraph error: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer shutdownCancel()
		_ = vaultStore.Close(shutdownCtx)
	}()

	app := httpapi.New(cfg, vaultStore)
	go func() {
		if err := app.Listen(cfg.Addr); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("vault server stopped: %v", err)
		}
	}()
	log.Printf("GMR Vault listening on %s", cfg.Addr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	_ = app.ShutdownWithContext(shutdownCtx)
}
