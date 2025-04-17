package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/creasty/defaults"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/verifier/attestation"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	"github.com/tinfoilsh/sev-shim/dcode"
	"github.com/tinfoilsh/sev-shim/key"
	"github.com/tinfoilsh/sev-shim/key/online"
	tlsutil "github.com/tinfoilsh/sev-shim/tls"
)

var version = "dev"

var config struct {
	Domains       []string `yaml:"domains"`
	ListenPort    int      `yaml:"listen-port" default:"443"`
	MetricsPort   int      `yaml:"metrics-port"`
	UpstreamPort  int      `yaml:"upstream-port"`
	Paths         []string `yaml:"paths"`
	OriginDomains []string `yaml:"origins"`

	ControlPlane string `yaml:"control-plane"`

	RateLimit float64 `yaml:"rate-limit"`
	RateBurst int     `yaml:"rate-burst"`
	CacheDir  string  `yaml:"cache-dir" default:"/mnt/ramdisk/certs"`
	Email     string  `yaml:"email" default:"tls@tinfoil.sh"`
	Verbose   bool    `yaml:"verbose"`
}

var (
	configFile = flag.String("c", "/mnt/ramdisk/shim.yml", "Path to config file")
)

func cors(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if !slices.Contains(config.OriginDomains, origin) {
		log.Debugf("%s not in %v", origin, config.OriginDomains)
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
}

func main() {
	flag.Parse()

	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		log.Fatalf("Failed to unmarshal config: %v", err)
	}
	if err := defaults.Set(&config); err != nil {
		log.Fatalf("Failed to set defaults: %v", err)
	}

	if config.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.Printf("Starting SEV-SNP attestation shim %s: %+v", version, config)

	var validator key.Validator
	var controlPlaneURL *url.URL

	if config.ControlPlane != "" {
		controlPlaneURL, err = url.Parse(config.ControlPlane)
		if err != nil {
			log.Fatalf("Failed to parse control plane URL: %v", err)
		}

		validator, err = online.NewValidator(controlPlaneURL.JoinPath("api", "shim", "validate").String())
		if err != nil {
			log.Fatalf("Failed to initialize online API key verifier: %v", err)
		}
	} else {
		validator = nil
		log.Warn("API key verification disabled")
	}

	mux := http.NewServeMux()

	requestsMetric := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sev_shim_proxy_requests_total",
			Help: "Number of HTTP requests",
		},
		[]string{},
	)
	r := prometheus.NewRegistry()
	r.MustRegister(requestsMetric)

	// Generate key for TLS certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	var domain string
	if len(config.Domains) == 0 {
		domain = "localhost"
	} else if len(config.Domains) == 1 {
		domain = config.Domains[0]
	} else {
		log.Fatalf("Multiple domains configured, only one is supported")
	}

	// Request SEV-SNP attestation
	keyFP := tlsutil.KeyFP(privateKey.Public().(*ecdsa.PublicKey))
	log.Printf("Fetching attestation over %s", keyFP)
	var att *attestation.Document
	if domain == "localhost" {
		log.Warn("No domain configured, using dummy attestation report")
		att = &attestation.Document{
			Format: "https://tinfoil.sh/predicate/dummy/v1",
			Body:   keyFP,
		}
	} else {
		att, err = attestationReport(keyFP)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Encode attestation into domains
	attDomains, err := dcode.Encode(att, domain)
	if err != nil {
		log.Fatalf("Failed to encode attestation: %v", err)
	}
	domains := append([]string{domain}, attDomains...)
	for _, d := range domains {
		log.Debugf("Domain: %s", d)
	}

	// Request TLS certificate
	var cert *tls.Certificate
	if domain != "localhost" {
		certManager, err := tlsutil.NewCertManager(config.Email, config.CacheDir, privateKey)
		if err != nil {
			log.Fatalf("Failed to create cert manager: %v", err)
		}
		cert, err = certManager.RequestCert(domains)
		if err != nil {
			log.Fatalf("Failed to request TLS certificate: %v", err)
		}
	} else {
		log.Warn("No domain configured, using self signed TLS certificate")
		cert, err = tlsutil.Certificate(privateKey, domains...)
		if err != nil {
			log.Fatalf("Failed to generate self signed TLS certificate: %v", err)
		}
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cert, nil
		},
	}

	var rateLimiter *RateLimiter
	if config.RateLimit > 0 {
		rateLimiter = NewRateLimiter(rate.Limit(config.RateLimit), config.RateBurst)
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)

		requestsMetric.WithLabelValues().Inc()

		apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if validator != nil && r.URL.Path == "/v1/chat/completions" {
			if len(apiKey) == 0 {
				http.Error(w, key.ErrAPIKeyRequired.Error(), http.StatusUnauthorized)
				return
			}

			if err := validator.Validate(apiKey); err != nil {
				log.Warnf("Failed to validate API key: %v", err)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
		}

		if rateLimiter != nil {
			if apiKey == "" {
				http.Error(w, key.ErrAPIKeyRequired.Error(), http.StatusUnauthorized)
				return
			}
			limiter := rateLimiter.Limit(apiKey)
			if !limiter.Allow() {
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}
		}

		if len(config.Paths) > 0 {
			allowed := false
			for _, path := range config.Paths {
				if r.URL.Path == path {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "shim: 403", http.StatusForbidden)
				return
			}
		}

		var writer = w
		if controlPlaneURL != nil && r.URL.Path == "/v1/chat/completions" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Warnf("Failed to read request body: %v", err)
				http.Error(w, "shim: 400", http.StatusBadRequest)
				return
			}
			r.Body.Close()

			var chatRequest chatRequest
			if err := json.Unmarshal(body, &chatRequest); err != nil {
				log.Warnf("Failed to decode chat request: %v", err)
				http.Error(w, "shim: 400", http.StatusBadRequest)
				return
			}

			var inputTokens int
			for _, message := range chatRequest.Messages {
				inputTokens += len(message.Content) / 4
				log.Debugf("Input tokens: %d", inputTokens)
			}

			writer = &responseWriter{
				InputTokens:    inputTokens,
				Server:         controlPlaneURL.JoinPath("api", "shim", "collect").String(),
				ResponseWriter: w,
				APIKey:         apiKey,
			}

			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		proxy := httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = fmt.Sprintf("127.0.0.1:%d", config.UpstreamPort)
				req.Header.Set("Host", "localhost")
				req.Host = "localhost"
				log.Debugf("Proxying request to %+v", req.URL.String())
			},
		}

		proxy.ServeHTTP(writer, r)
	})

	mux.HandleFunc("/.well-known/tinfoil-attestation", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(att)
	})

	if config.MetricsPort > 0 {
		log.Printf("Starting metrics server on port %d", config.MetricsPort)
		go func() {
			listenAddr := fmt.Sprintf(":%d", config.MetricsPort)
			log.Fatal(http.ListenAndServe(listenAddr, promhttp.HandlerFor(r, promhttp.HandlerOpts{})))
		}()
	}

	listenAddr := fmt.Sprintf(":%d", config.ListenPort)
	httpServer := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Listening on %s", listenAddr)
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}
