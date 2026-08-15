package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cameronle/dsh-auth-gateway/internal/config"
	"github.com/cameronle/dsh-auth-gateway/internal/gateway"
)

func main() {
	configPath := flag.String("config", "/etc/dsh-auth-gateway/config.env", "config file")
	keygen := flag.Bool("keygen", false, "generate management key and versioned hash")
	flag.Parse()
	if *keygen {
		plain, hash, err := gateway.GenerateKeyHash()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("MANAGEMENT_KEY=%s\nKEY_HASH=%s\n", plain, hash)
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	g, err := gateway.New(gateway.Config{
		KeySalt: cfg.KeySalt, KeyHash: cfg.KeyHash, SessionTTL: cfg.SessionTTL,
		CookieName: cfg.CookieName, PublicScheme: cfg.PublicScheme, ExpectedHost: cfg.ExpectedHost,
		TrustedProxyIP: cfg.TrustedProxyIP, ClientIPHeader: cfg.ClientIPHeader, RequireClientIdentity: cfg.RequireClientIdentity,
		FailureBurst: cfg.FailureBurst, FailureRefill: cfg.FailureRefill, GlobalBurst: cfg.GlobalBurst, GlobalRefill: cfg.GlobalRefill,
		StateTTL: cfg.StateTTL, StateMaxClients: cfg.StateMaxClients, CleanupInterval: cfg.CleanupInterval, SessionMax: cfg.SessionMax,
		KeyCheckConcurrency: cfg.KeyCheckConcurrency, KeyCheckBurst: cfg.KeyCheckBurst, KeyCheckRefill: cfg.KeyCheckRefill,
		AuditWriter: os.Stdout,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer g.Close()
	server := &http.Server{Addr: cfg.Listen, Handler: g.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	log.Printf("dsh-auth-gateway listening on %s", cfg.Listen)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown: %v", err)
		}
		if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server exit: %v", err)
		}
	}
}
