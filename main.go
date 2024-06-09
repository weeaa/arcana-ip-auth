package main

import (
	"crypto/subtle"
	"crypto/tls"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

var passphrase string

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := godotenv.Load(); err != nil {
		return err
	}

	passphrase = os.Getenv("PASSPHRASE")

	db, err := newDatabase()
	if err != nil {
		return err
	}

	if err = db.initialize(); err != nil {
		return err
	}

	router := chi.NewRouter()
	router.Use(banMiddleware)
	router.Use(middleware.Logger)

	limiter := rate.NewLimiter(rate.Every(4*time.Second), 1)

	router.Post("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		authenticate(w, r, db, limiter)
	})

	router.Post("/allow", func(w http.ResponseWriter, r *http.Request) {
		allowIpAddress(w, r, db)
	})

	certFile := "cert.pem"
	keyFile := "key.pem"

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
	}

	server := &http.Server{
		Addr:      ":3042",
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	return server.ListenAndServeTLS(certFile, keyFile)
}

// allowIpAddress whitelists an IP address.
func allowIpAddress(w http.ResponseWriter, r *http.Request, db *Database) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Passphrase")), []byte(passphrase)) != 1 {
		http.Error(w, "invalid passphrase", http.StatusBadRequest)
		return
	}

	if err := db.InsertIp(r.Header.Get("X-Ip")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func authenticate(w http.ResponseWriter, r *http.Request, db *Database, limiter *rate.Limiter) {
	if !limiter.Allow() {
		http.Error(w, "chill, stop spamming", http.StatusTooManyRequests)
		return
	}

	headers := r.Header.Clone()

	ip := headers.Get("X-Ip")
	if !isValidIP(ip) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if host != ip {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ips, err := db.RetrieveIps()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !isIPInList(ip, ips) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func isIPInList(ip string, ips []string) bool {
	for _, dbIp := range ips {
		if ip == dbIp {
			return true
		}
	}
	return false
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

var bannedIPs sync.Map

func init() {
	bannedIPs.Store("206.168.34.47", struct{}{}) // used to do weird reqs
}

func banIP(ip string) {
	bannedIPs.Store(ip, struct{}{})
}

func isBannedIP(ip string) bool {
	_, ok := bannedIPs.Load(ip)
	return ok
}

func banMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid IP address", http.StatusInternalServerError)
			return
		}

		if isBannedIP(ip) {
			http.Error(w, "access forbidden", http.StatusForbidden)
			return
		}

		switch r.URL.Path {
		case "/allow", "/authenticate":
			next.ServeHTTP(w, r)
			return
		default:
			banIP(ip)
			http.Error(w, "access forbidden", http.StatusForbidden)
			return
		}
	})
}
