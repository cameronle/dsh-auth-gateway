package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestLoadRejectsUnknownAndDuplicateKeys(t *testing.T) {
	for _, extra := range []string{
		"SURPRISE=value\n",
		"SESSION_TTL=12h\nSESSION_TTL=24h\n",
	} {
		d := t.TempDir()
		p := filepath.Join(d, "config.env")
		body := "LISTEN=127.0.0.1:18081\nKEY_SALT=c2FsdHNhbHRzYWx0c2FsdA\nKEY_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEXPECTED_HOST=dsh.example.test\n" + extra
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("expected rejection for %q", extra)
		}
	}
}

func TestLoadRejectsInvalidCookieNameAndUnboundedValues(t *testing.T) {
	for _, extra := range []string{
		"COOKIE_NAME=bad cookie\n",
		"SESSION_TTL=0s\n",
		"SESSION_TTL=87601h\n",
		"FAILURE_WINDOW=-1s\n",
		"LOCKOUT=0s\n",
		"MAX_FAILURES=1000001\n",
	} {
		d := t.TempDir()
		p := filepath.Join(d, "config.env")
		body := "LISTEN=127.0.0.1:18081\nKEY_SALT=c2FsdHNhbHRzYWx0c2FsdA\nKEY_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEXPECTED_HOST=dsh.example.test\n" + extra
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("expected rejection for %q", extra)
		}
	}
}

func TestLoadRejectsMalformedExpectedHost(t *testing.T) {
	for _, host := range []string{"bad host", ".example.test", "example..test", "example.test.", "example.test:443", "[::1]"} {
		d := t.TempDir()
		p := filepath.Join(d, "config.env")
		body := "LISTEN=127.0.0.1:18081\nKEY_SALT=c2FsdHNhbHRzYWx0c2FsdA\nKEY_HASH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEXPECTED_HOST=" + host + "\n"
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("expected invalid host %q", host)
		}
	}
}

func TestLoadParsesRedesignSettingsWithSHA256Key(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.env")
	body := "LISTEN=127.0.0.1:18081\nKEY_HASH=sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEXPECTED_HOST=dsh.example.test\nCLIENT_IP_HEADER=X-DSH-Client-IP\nREQUIRE_CLIENT_IDENTITY=true\nAUTH_FAILURE_BURST=5\nAUTH_FAILURE_REFILL=30s\nAUTH_GLOBAL_BURST=100\nAUTH_GLOBAL_REFILL=200ms\nAUTH_STATE_TTL=1h\nAUTH_STATE_MAX_CLIENTS=10000\nAUTH_CLEANUP_INTERVAL=1m\nAUTH_SESSION_MAX=10000\nKEY_CHECK_CONCURRENCY=2\nKEY_CHECK_BURST=4\nKEY_CHECK_REFILL=2s\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequireClientIdentity || cfg.FailureBurst != 5 || cfg.GlobalRefill != 200*time.Millisecond || cfg.SessionMax != 10000 {
		t.Fatalf("bad redesign config: %#v", cfg)
	}
}

func TestLoadRejectsDeprecatedFixedWindowKeys(t *testing.T) {
	for _, key := range []string{"MAX_FAILURES=5", "FAILURE_WINDOW=5m", "LOCKOUT=15m"} {
		d := t.TempDir()
		p := filepath.Join(d, "config.env")
		body := "KEY_HASH=sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nEXPECTED_HOST=dsh.example.test\n" + key + "\n"
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "deprecated") {
			t.Fatalf("%s err=%v", key, err)
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
