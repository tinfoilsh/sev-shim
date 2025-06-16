package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/creasty/defaults"
	"github.com/go-acme/lego/v4/lego"
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
	ListenPort   int `yaml:"listen-port" default:"443"`
	UpstreamPort int `yaml:"upstream-port"`
	ControlPort  int `yaml:"control-port" default:"8086"`

	Paths         []string `yaml:"paths"`
	OriginDomains []string `yaml:"origins"`

	TLSMode          string `yaml:"tls-mode" default:"production"` // self-signed | staging | production
	TLSChallengeMode string `yaml:"tls-challenge" default:"tls"`   // tls | dns

	ControlPlane string `yaml:"control-plane"`

	RateLimit float64 `yaml:"rate-limit"`
	RateBurst int     `yaml:"rate-burst"`
	CacheDir  string  `yaml:"cache-dir" default:"/mnt/ramdisk/certs"`
	Email     string  `yaml:"email" default:"tls@tinfoil.sh"`

	PublishAttestation bool `yaml:"publish-attestation"`
	DummyAttestation   bool `yaml:"dummy-attestation"`

	Verbose bool `yaml:"verbose"`
}

var externalConfig struct {
	Domain              string `yaml:"domain"`
	CloudflareDNSToken  string `yaml:"cloudflare-dns-token"`
	CloudflareZoneToken string `yaml:"cloudflare-zone-token"`
}

var (
	configFile         = flag.String("c", "/mnt/ramdisk/shim.yml", "Path to config file")
	externalConfigFile = flag.String("e", "/mnt/ramdisk/external-config.yml", "Path to external config file")
	dev                = flag.Bool("d", false, "Skip dcode domains, use dummy attestation, and enable verbose logging")
)

func cors(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return // same‑origin request
	}

	// Allow only configured origins
	if len(config.OriginDomains) > 0 && !slices.Contains(config.OriginDomains, origin) {
		log.Debugf("CORS origin not allowed: %s", origin)
		http.Error(w, "shim: 403 CORS origin not allowed", http.StatusForbidden)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin") // cache
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")

	// Echo requested headers or use a safe default
	reqHdr := r.Header.Get("Access-Control-Request-Headers")
	if reqHdr == "" {
		reqHdr = "Authorization,Content-Type"
	}
	w.Header().Set("Access-Control-Allow-Headers", reqHdr)

	if r.Method == http.MethodOptions {
		log.Debugf("CORS OPTIONS request: %s", origin)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.Tracef("CORS request allowed: %s", origin)
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

	if config.UpstreamPort == 0 {
		log.Fatalf("Upstream port is not set")
	}
	if !slices.Contains([]string{"self-signed", "staging", "production"}, config.TLSMode) {
		log.Fatalf("Invalid TLS mode: %s", config.TLSMode)
	}

	externalConfigBytes, err := os.ReadFile(*externalConfigFile)
	if err != nil {
		log.Fatalf("Failed to read external config file: %v", err)
	}
	if err := yaml.Unmarshal(externalConfigBytes, &externalConfig); err != nil {
		log.Fatalf("Failed to unmarshal external config: %v", err)
	}
	if err := defaults.Set(&externalConfig); err != nil {
		log.Fatalf("Failed to set defaults: %v", err)
	}

	if config.Verbose || *dev {
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

	log.Printf("Starting control server on port %d", config.ControlPort)
	controlServer := newControlServer()
	go controlServer.Start(config.ControlPort)

	// Generate key for TLS certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	if externalConfig.Domain == "" {
		externalConfig.Domain = "localhost"
	}

	// Request SEV-SNP attestation
	keyFP := tlsutil.KeyFP(privateKey.Public().(*ecdsa.PublicKey))
	log.Printf("Fetching attestation over %s", keyFP)
	var att *attestation.Document
	if externalConfig.Domain == "localhost" || *dev || config.DummyAttestation {
		log.Warn("Using dummy attestation report")
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

	domains := []string{externalConfig.Domain}

	// Encode attestation into domains
	if config.PublishAttestation {
		attDomains, err := dcode.Encode(att, externalConfig.Domain)
		if err != nil {
			log.Fatalf("Failed to encode attestation: %v", err)
		}
		domains = append(domains, attDomains...)
	}

	for _, d := range domains {
		log.Debugf("Domain: %s", d)
	}

	// Request prod cert if needed
	var cert *tls.Certificate
	if externalConfig.Domain == "localhost" || config.TLSMode == "self-signed" {
		cert, err = tlsutil.Certificate(privateKey, domains...)
		if err != nil {
			log.Fatalf("Failed to generate self signed TLS certificate: %v", err)
		}
	} else { // Prod TLS cert
		dir := lego.LEDirectoryProduction
		if config.TLSMode == "staging" {
			dir = lego.LEDirectoryStaging
		}
		certManager, err := tlsutil.NewCertManager(
			domains,
			config.Email, config.CacheDir, dir,
			tlsutil.ChallengeMode(config.TLSChallengeMode),
			config.ListenPort,
			privateKey,
			externalConfig.CloudflareDNSToken,
			externalConfig.CloudflareZoneToken,
		)
		if err != nil {
			log.Fatalf("Failed to create cert manager: %v", err)
		}

		cert, err = certManager.Certificate()
		if err != nil {
			log.Fatalf("Failed to request TLS certificate: %v", err)
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

	var tokenRecorder *TokenRecorder
	if controlPlaneURL != nil {
		log.Printf("Starting token recorder")
		tokenRecorder = NewTokenRecorder(controlPlaneURL.JoinPath("api", "shim", "collect").String())
		tokenRecorder.Start()
	}

	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = fmt.Sprintf("127.0.0.1:%d", config.UpstreamPort)
			req.Header.Set("Host", "localhost")
			req.Host = "localhost"
			log.Debugf("Proxying request to %+v", req.URL.String())
		},
		Transport: &streamTransport{
			tokenRecorder: tokenRecorder,
			base:          http.DefaultTransport,
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del("Access-Control-Allow-Origin")

			if tokenRecorder != nil && res.Request != nil && res.Request.URL.Path == "/v1/audio/transcriptions" {
				tokenCount, err := tokenizeAudioResponse(res)
				if err != nil {
					log.Warnf("Failed to tokenize audio response: %v", err)
					return err
				}

				apiKey := strings.TrimPrefix(res.Request.Header.Get("Authorization"), "Bearer ")
				tokenRecorder.Record(apiKey, "whisper", tokenCount)
				log.Debugf("Transcribed %d tokens for %s", tokenCount, apiKey)
			}

			return nil
		},
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		if r.Method == "OPTIONS" {
			return
		}

		apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if validator != nil && r.URL.Path == "/v1/chat/completions" {
			if len(apiKey) == 0 {
				http.Error(w, "shim: 401 API key required", http.StatusUnauthorized)
				return
			}

			if err := validator.Validate(apiKey); err != nil {
				log.Warnf("Failed to validate API key: %v", err)
				http.Error(w, "shim: 401 invalid API key", http.StatusUnauthorized)
				return
			}
		}

		if rateLimiter != nil {
			if apiKey == "" {
				http.Error(w, "shim: 401 API key required", http.StatusUnauthorized)
				return
			}
			limiter := rateLimiter.Limit(apiKey)
			if !limiter.Allow() {
				http.Error(w, "shim: 429 rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		if len(config.Paths) > 0 && !slices.Contains(config.Paths, r.URL.Path) {
			http.Error(w, "shim: 403 path not allowed", http.StatusForbidden)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	mux.HandleFunc("/.well-known/tinfoil-attestation", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(att)
	})

	listenAddr := fmt.Sprintf(":%d", config.ListenPort)
	httpServer := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Listening on %s", listenAddr)
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}
