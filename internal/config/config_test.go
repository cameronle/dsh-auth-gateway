package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsWorldReadableConfig(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.env")
	if err := os.WriteFile(p, []byte("LISTEN=127.0.0.1:18081\nKEY_SALT=x\nKEY_HASH=y\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected permission error")
	}
}

func TestLoadAllowsGroupReadableConfig(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.env")
	body := "LISTEN=127.0.0.1:18081\nKEY_SALT=c2FsdHNhbHRzYWx0c2FsdA\nKEY_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEXPECTED_HOST=dsh.example.test\n"
	if err := os.WriteFile(p, []byte(body), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("group-readable service config should be allowed: %v", err)
	}
}

func TestLoadParsesDurationsAndRequiredValues(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.env")
	body := "LISTEN=127.0.0.1:18081\nKEY_SALT=c2FsdHNhbHRzYWx0c2FsdA\nKEY_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nSESSION_TTL=12h\nCOOKIE_NAME=dsh_gateway_session\nSECURE_COOKIE=true\nTRUSTED_PROXY_IP=127.0.0.1\nEXPECTED_HOST=dsh.example.test\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:18081" || cfg.SessionTTL.String() != "12h0m0s" || !cfg.SecureCookie {
		t.Fatalf("bad config: %#v", cfg)
	}
}

func TestLoadParsesExpectedHost(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.env")
	body := "LISTEN=127.0.0.1:18081\nKEY_SALT=c2FsdHNhbHRzYWx0c2FsdA\nKEY_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEXPECTED_HOST=dsh.example.test\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExpectedHost != "dsh.example.test" {
		t.Fatalf("expected host=%q", cfg.ExpectedHost)
	}
}

func TestLoadRejectsExpectedHostWithSchemeOrPath(t *testing.T) {
	for _, value := range []string{"https://dsh.example.test", "dsh.example.test/path", ""} {
		d := t.TempDir()
		p := filepath.Join(d, "config.env")
		body := "LISTEN=127.0.0.1:18081\nKEY_SALT=c2FsdHNhbHRzYWx0c2FsdA\nKEY_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEXPECTED_HOST=" + value + "\n"
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("expected invalid EXPECTED_HOST %q", value)
		}
	}
}

func TestLoadRejectsNonLoopbackListen(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.env")
	body := "LISTEN=0.0.0.0:18081\nKEY_SALT=c2FsdHNhbHRzYWx0c2FsdA\nKEY_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEXPECTED_HOST=dsh.example.test\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected loopback error")
	}
}
