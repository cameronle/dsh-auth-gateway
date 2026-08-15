package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsToDynamicHTTPSWithoutTransportFlags(t *testing.T) {
	cfg := loadTransportConfig(t, "")
	if cfg.PublicScheme != "https" || cfg.ExpectedHost != "" {
		t.Fatalf("bad HTTPS defaults: %#v", cfg)
	}
}

func TestLoadAcceptsPrivateHTTPWithOnlyPublicScheme(t *testing.T) {
	cfg := loadTransportConfig(t, "PUBLIC_SCHEME=http\n")
	if cfg.PublicScheme != "http" || cfg.ExpectedHost != "" {
		t.Fatalf("bad HTTP mode: %#v", cfg)
	}
}

func TestLoadRejectsInvalidPublicScheme(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.env")
	body := "KEY_HASH=sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nPUBLIC_SCHEME=ftp\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected invalid scheme rejection")
	}
}

func TestLoadRejectsRemovedTransportKeys(t *testing.T) {
	for _, extra := range []string{
		"SECURE_COOKIE=true\n",
		"HOST_POLICY=request\n",
	} {
		d := t.TempDir()
		p := filepath.Join(d, "config.env")
		body := "KEY_HASH=sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" + extra
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("expected removed key rejection for %q", extra)
		}
	}
}

func TestLoadTreatsLegacyExpectedHostAsOptionalFixedHost(t *testing.T) {
	cfg := loadTransportConfig(t, "EXPECTED_HOST=DSH.EXAMPLE.TEST\n")
	if cfg.PublicScheme != "https" || cfg.ExpectedHost != "dsh.example.test" {
		t.Fatalf("legacy compatibility failed: %#v", cfg)
	}
}

func TestLoadAllowsHTTPWithLegacyFixedHost(t *testing.T) {
	cfg := loadTransportConfig(t, "PUBLIC_SCHEME=http\nEXPECTED_HOST=dsh-host\n")
	if cfg.PublicScheme != "http" || cfg.ExpectedHost != "dsh-host" {
		t.Fatalf("HTTP fixed compatibility failed: %#v", cfg)
	}
}

func loadTransportConfig(t *testing.T, extra string) Config {
	t.Helper()
	d := t.TempDir()
	p := filepath.Join(d, "config.env")
	body := "KEY_HASH=sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" + extra
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
