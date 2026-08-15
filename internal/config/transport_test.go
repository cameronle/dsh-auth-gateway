package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsToDynamicHTTPSWithoutExpectedHost(t *testing.T) {
	cfg := loadTransportConfig(t, "SECURE_COOKIE=true\n")
	if cfg.PublicScheme != "https" || cfg.HostPolicy != "request" || cfg.ExpectedHost != "" {
		t.Fatalf("bad dynamic defaults: %#v", cfg)
	}
}

func TestLoadAcceptsPrivateHTTPModeWithoutKnownHost(t *testing.T) {
	cfg := loadTransportConfig(t, "PUBLIC_SCHEME=http\nHOST_POLICY=request\nSECURE_COOKIE=false\n")
	if cfg.PublicScheme != "http" || cfg.HostPolicy != "request" || cfg.SecureCookie {
		t.Fatalf("bad HTTP mode: %#v", cfg)
	}
}

func TestLoadRejectsSchemeCookieAndHostPolicyContradictions(t *testing.T) {
	for _, extra := range []string{
		"PUBLIC_SCHEME=http\nSECURE_COOKIE=true\n",
		"PUBLIC_SCHEME=https\nSECURE_COOKIE=false\n",
		"PUBLIC_SCHEME=ftp\nSECURE_COOKIE=true\n",
		"HOST_POLICY=fixed\nSECURE_COOKIE=true\n",
		"HOST_POLICY=request\nEXPECTED_HOST=dsh.example.test\nSECURE_COOKIE=true\n",
		"HOST_POLICY=anything\nSECURE_COOKIE=true\n",
	} {
		d := t.TempDir()
		p := filepath.Join(d, "config.env")
		body := "KEY_HASH=sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" + extra
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("expected rejection for %q", extra)
		}
	}
}

func TestLoadTreatsLegacyExpectedHostAsFixedHTTPS(t *testing.T) {
	cfg := loadTransportConfig(t, "EXPECTED_HOST=DSH.EXAMPLE.TEST\nSECURE_COOKIE=true\n")
	if cfg.PublicScheme != "https" || cfg.HostPolicy != "fixed" || cfg.ExpectedHost != "dsh.example.test" {
		t.Fatalf("legacy compatibility failed: %#v", cfg)
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
