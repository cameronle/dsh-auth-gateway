package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/cameronle/dsh-auth-gateway/internal/config"
	"github.com/cameronle/dsh-auth-gateway/internal/gateway"
)

func main() {
	configPath := flag.String("config", "/etc/dsh-auth-gateway/config.env", "config file")
	keygen := flag.Bool("keygen", false, "generate management key and hash values")
	flag.Parse()
	if *keygen {
		plain, salt, hash, err := gateway.GenerateKeyHash()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("MANAGEMENT_KEY=%s\nKEY_SALT=%s\nKEY_HASH=%s\n", plain, salt, hash)
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	g, err := gateway.New(gateway.Config{
		KeySalt: cfg.KeySalt, KeyHash: cfg.KeyHash, SessionTTL: cfg.SessionTTL,
		CookieName: cfg.CookieName, SecureCookie: cfg.SecureCookie,
		MaxFailures: cfg.MaxFailures, FailureWindow: cfg.FailureWindow,
		Lockout: cfg.Lockout, TrustedProxyIP: cfg.TrustedProxyIP, AuditWriter: os.Stdout,
	})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr: cfg.Listen, Handler: g.Handler(),
		ReadHeaderTimeout: 5e9, ReadTimeout: 10e9, WriteTimeout: 10e9, IdleTimeout: 60e9,
		MaxHeaderBytes: 16 << 10,
	}
	log.Printf("dsh-auth-gateway listening on %s", cfg.Listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
