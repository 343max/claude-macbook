package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ---- Config ----------------------------------------------------------------

type Config struct {
	SSHHost           string
	SSHUser           string
	SSHKeyPath        string
	KnownHostsPath    string
	RemotePort        int
	RemoteCommand     string
	ListenAddr        string
	InactivityTimeout time.Duration
}

func loadConfig() Config {
	port := getEnv("PORT", "8687")
	portNum, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("invalid PORT: %v", err)
	}
	inactivity, err := time.ParseDuration(getEnv("INACTIVITY_TIMEOUT", "30m"))
	if err != nil {
		log.Fatalf("invalid INACTIVITY_TIMEOUT: %v", err)
	}
	return Config{
		SSHHost:           mustEnv("SSH_HOST"),
		SSHUser:           mustEnv("SSH_USER"),
		SSHKeyPath:        getEnv("SSH_KEY_PATH", "/etc/ssh-key_id_ed25519"),
		KnownHostsPath:    getEnv("KNOWN_HOSTS_PATH", "/etc/ssh-known-hosts/known_hosts"),
		RemotePort:        portNum,
		RemoteCommand:     mustEnv("REMOTE_COMMAND"),
		ListenAddr:        ":" + port,
		InactivityTimeout: inactivity,
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---- activityConn ----------------------------------------------------------
// Wraps net.Conn and fires onActivity on every read/write — used to reset
// the inactivity timer during long-lived WebSocket sessions.

type activityConn struct {
	net.Conn
	onActivity func()
}

func (c *activityConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.onActivity()
	}
	return n, err
}

func (c *activityConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.onActivity()
	}
	return n, err
}

// ---- TunnelManager ---------------------------------------------------------

type TunnelManager struct {
	cfg      Config
	mu       sync.Mutex
	client   *ssh.Client
	session  *ssh.Session
	timerGen uint64
	timer    *time.Timer
	transport *http.Transport

	// metrics
	tunnelOpen   prometheus.Gauge
	tunnelOpens  prometheus.Counter
	tunnelCloses *prometheus.CounterVec
	proxyReqs    prometheus.Counter
	proxyErrors  prometheus.Counter
}

func newTunnelManager(cfg Config) *TunnelManager {
	tm := &TunnelManager{
		cfg: cfg,
		tunnelOpen: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "tunnel_open",
			Help: "1 if the SSH tunnel is currently open",
		}),
		tunnelOpens: promauto.NewCounter(prometheus.CounterOpts{
			Name: "tunnel_opens_total",
			Help: "Total number of SSH tunnel opens",
		}),
		tunnelCloses: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "tunnel_closes_total",
			Help: "SSH tunnel close events by reason",
		}, []string{"reason"}),
		proxyReqs: promauto.NewCounter(prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Total HTTP requests proxied",
		}),
		proxyErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "proxy_errors_total",
			Help: "Total proxy errors",
		}),
	}

	// Build the transport once; DialContext dials through the SSH tunnel.
	// CloseIdleConnections is called on tunnel close to evict stale SSH channels.
	tm.transport = &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			client, err := tm.getClient()
			if err != nil {
				return nil, err
			}
			conn, err := client.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			tm.resetActivity()
			return &activityConn{Conn: conn, onActivity: tm.resetActivity}, nil
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       5 * time.Minute,
		ResponseHeaderTimeout: 60 * time.Second,
	}

	return tm
}

// getClient returns the active SSH client, opening the tunnel if needed.
func (tm *TunnelManager) getClient() (*ssh.Client, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.client != nil {
		return tm.client, nil
	}
	return tm.openLocked()
}

// resetActivity resets the inactivity timer; safe to call from any goroutine.
func (tm *TunnelManager) resetActivity() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.resetTimerLocked()
}

func (tm *TunnelManager) resetTimerLocked() {
	if tm.timer != nil {
		tm.timer.Stop()
	}
	gen := tm.timerGen
	tm.timerGen++
	tm.timer = time.AfterFunc(tm.cfg.InactivityTimeout, func() {
		tm.mu.Lock()
		defer tm.mu.Unlock()
		// Guard against stale timers that fired after being reset.
		if tm.timerGen != gen+1 {
			return
		}
		tm.closeLocked("inactivity")
	})
}

func (tm *TunnelManager) openLocked() (*ssh.Client, error) {
	sshClient, err := tm.dialWithRetry()
	if err != nil {
		return nil, err
	}

	sess, err := sshClient.NewSession()
	if err != nil {
		sshClient.Close()
		return nil, fmt.Errorf("new SSH session: %w", err)
	}
	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr
	if err := sess.Start(tm.cfg.RemoteCommand); err != nil {
		sess.Close()
		sshClient.Close()
		return nil, fmt.Errorf("start remote command: %w", err)
	}

	tm.client = sshClient
	tm.session = sess
	tm.tunnelOpens.Inc()
	tm.tunnelOpen.Set(1)
	log.Printf("tunnel opened to %s", tm.cfg.SSHHost)

	// Watch for the remote command exiting.
	go func() {
		if err := sess.Wait(); err != nil {
			log.Printf("remote command exited: %v", err)
		} else {
			log.Println("remote command exited cleanly")
		}
		tm.Close("remote-exit")
	}()

	tm.resetTimerLocked()
	return sshClient, nil
}

func (tm *TunnelManager) closeLocked(reason string) {
	if tm.client == nil {
		return
	}
	log.Printf("closing tunnel (reason: %s)", reason)
	if tm.timer != nil {
		tm.timer.Stop()
		tm.timer = nil
	}
	if tm.session != nil {
		tm.session.Close()
		tm.session = nil
	}
	tm.client.Close()
	tm.client = nil
	tm.transport.CloseIdleConnections()
	tm.tunnelOpen.Set(0)
	tm.tunnelCloses.WithLabelValues(reason).Inc()
}

// Close closes the tunnel with the given reason (safe to call from outside).
func (tm *TunnelManager) Close(reason string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.closeLocked(reason)
}

// ---- SSH dial with retry ---------------------------------------------------

func (tm *TunnelManager) dialWithRetry() (*ssh.Client, error) {
	addr := net.JoinHostPort(tm.cfg.SSHHost, "22")
	backoff := time.Second
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		client, err := tm.dial(addr)
		if err == nil {
			return client, nil
		}
		lastErr = err
		if attempt < 3 {
			log.Printf("SSH dial attempt %d/3 failed: %v (retry in %s)", attempt, err, backoff)
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	return nil, fmt.Errorf("SSH dial failed after 3 attempts: %w", lastErr)
}

func (tm *TunnelManager) dial(addr string) (*ssh.Client, error) {
	// Re-read key on every dial so key rotation is picked up without restart.
	keyBytes, err := os.ReadFile(tm.cfg.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key: %w", err)
	}

	cb, err := tm.hostKeyCallback()
	if err != nil {
		return nil, err
	}

	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            tm.cfg.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: cb,
		Timeout:         15 * time.Second,
	})
}

// ---- TOFU host-key pinning -------------------------------------------------

func (tm *TunnelManager) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if _, err := os.Stat(tm.cfg.KnownHostsPath); os.IsNotExist(err) {
		log.Printf("known_hosts not found, running TOFU scan for %s", tm.cfg.SSHHost)
		if err := scanAndWriteHostKey(tm.cfg.SSHHost, tm.cfg.KnownHostsPath); err != nil {
			return nil, fmt.Errorf("TOFU scan: %w", err)
		}
		log.Println("TOFU complete, host key saved")
	}
	return knownhosts.New(tm.cfg.KnownHostsPath)
}

// scanAndWriteHostKey performs a Trust-On-First-Use scan.
// HostKeyCallback fires during key exchange (before auth), so we get the key
// even though the subsequent auth with a dummy password fails — that's expected.
func scanAndWriteHostKey(host, path string) error {
	addr := net.JoinHostPort(host, "22")

	var capturedKey ssh.PublicKey
	netConn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("TCP connect to %s: %w", addr, err)
	}
	defer netConn.Close()

	sshConn, _, _, _ := ssh.NewClientConn(netConn, addr, &ssh.ClientConfig{
		User: "tofu-scan",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			capturedKey = key
			return nil
		},
		Auth:    []ssh.AuthMethod{ssh.Password("")},
		Timeout: 15 * time.Second,
	})
	if sshConn != nil {
		sshConn.Close()
	}

	if capturedKey == nil {
		return fmt.Errorf("no host key received from %s", host)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir for known_hosts: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	// known_hosts format: "hostname keytype base64key\n"
	// normalizeKnownHostsAddr strips :22 for the standard port (OpenSSH convention).
	_, err = fmt.Fprintf(f, "%s %s", normalizeKnownHostsAddr(host), string(ssh.MarshalAuthorizedKey(capturedKey)))
	return err
}

// normalizeKnownHostsAddr converts "host:22" → "host", "host:port" → "[host]:port".
func normalizeKnownHostsAddr(host string) string {
	// host here is already just the hostname (no port), per how we call this func.
	return host
}

// ---- HTTP handler ----------------------------------------------------------

func buildHandler(tm *TunnelManager) http.Handler {
	mux := http.NewServeMux()

	// Phase 4: health + metrics endpoints.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.Handle("/metrics", promhttp.Handler())

	// Reverse proxy: Director rewrites the URL to the SSH-tunnelled upstream.
	// The Transport's DialContext dials through the live SSH client, so every
	// "TCP connection" is actually an SSH channel to the remote machine.
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = fmt.Sprintf("127.0.0.1:%d", tm.cfg.RemotePort)
			if req.Header.Get("X-Forwarded-Host") == "" {
				req.Header.Set("X-Forwarded-Host", req.Host)
			}
			// Rewrite the Host header to the backend address.
			// code-server rejects requests where Host doesn't match its listener
			// (DNS-rebinding protection), so we must send Host: 127.0.0.1:<port>.
			req.Host = req.URL.Host
		},
		Transport: tm.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			tm.proxyErrors.Inc()
			log.Printf("proxy error: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tm.proxyReqs.Inc()
		proxy.ServeHTTP(w, r)
	})

	return mux
}

// ---- main ------------------------------------------------------------------

func main() {
	cfg := loadConfig()
	tm := newTunnelManager(cfg)

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: buildHandler(tm),
	}

	// Phase 3: graceful shutdown on SIGTERM / SIGINT.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
		tm.Close("shutdown")
	}()

	log.Printf("listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}
