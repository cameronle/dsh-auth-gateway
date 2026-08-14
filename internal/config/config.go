package config

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen         string
	KeySalt        string
	KeyHash        string
	SessionTTL     time.Duration
	CookieName     string
	SecureCookie   bool
	MaxFailures    int
	FailureWindow  time.Duration
	Lockout        time.Duration
	TrustedProxyIP string
}

func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, err
	}
	// The service commonly runs as an unprivileged user reading a root-owned,
	// group-readable file. Refuse all permissions for "other" and any write or
	// execute permission for the group; 0600 and 0640 are accepted.
	if info.Mode().Perm()&0007 != 0 || info.Mode().Perm()&0030 != 0 {
		return Config{}, errors.New("config permissions must be 0600 or 0640")
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	m := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, errors.New("invalid config line")
		}
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if err := s.Err(); err != nil {
		return Config{}, err
	}
	cfg := Config{Listen: m["LISTEN"], KeySalt: m["KEY_SALT"], KeyHash: m["KEY_HASH"], CookieName: m["COOKIE_NAME"], TrustedProxyIP: m["TRUSTED_PROXY_IP"]}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:18081"
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return Config{}, errors.New("LISTEN must be a loopback IP:port")
	}
	if cfg.KeySalt == "" || cfg.KeyHash == "" {
		return Config{}, errors.New("KEY_SALT and KEY_HASH are required")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "dsh_gateway_session"
	}
	cfg.SessionTTL, err = duration(m["SESSION_TTL"], 12*time.Hour)
	if err != nil {
		return Config{}, err
	}
	cfg.FailureWindow, err = duration(m["FAILURE_WINDOW"], 5*time.Minute)
	if err != nil {
		return Config{}, err
	}
	cfg.Lockout, err = duration(m["LOCKOUT"], 15*time.Minute)
	if err != nil {
		return Config{}, err
	}
	cfg.MaxFailures, err = integer(m["MAX_FAILURES"], 5)
	if err != nil {
		return Config{}, err
	}
	cfg.SecureCookie, err = boolean(m["SECURE_COOKIE"], true)
	if err != nil {
		return Config{}, err
	}
	if cfg.TrustedProxyIP == "" {
		cfg.TrustedProxyIP = "127.0.0.1"
	}
	if ip := net.ParseIP(cfg.TrustedProxyIP); ip == nil || !ip.IsLoopback() {
		return Config{}, errors.New("TRUSTED_PROXY_IP must be loopback")
	}
	return cfg, nil
}

func duration(s string, d time.Duration) (time.Duration, error) {
	if s == "" {
		return d, nil
	}
	return time.ParseDuration(s)
}
func integer(s string, d int) (int, error) {
	if s == "" {
		return d, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return 0, errors.New("invalid positive integer")
	}
	return v, nil
}
func boolean(s string, d bool) (bool, error) {
	if s == "" {
		return d, nil
	}
	return strconv.ParseBool(s)
}
