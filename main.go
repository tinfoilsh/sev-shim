package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/time/rate"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
)

var version = "dev"

var config struct {
	Domain       string   `yaml:"domain"`
	ListenPort   int      `yaml:"listen-port"`
	UpstreamPort int      `yaml:"upstream-port"`
	Paths        []string `yaml:"paths"`
	KeyServer    string   `yaml:"key-server"`
	StagingCA    bool     `yaml:"staging-ca"`
	RateLimit    float64  `yaml:"rate-limit"`
	RateBurst    int      `yaml:"rate-burst"`
	Verbose      bool     `yaml:"verbose"`
}

var (
	configFile = flag.String("c", "/mnt/ramdisk/shim.yml", "Path to config file")

	email     = "tls@tinfoil.sh"
	certCache = "/mnt/ramdisk/certs"
)

// attestationReport gets a SEV-SNP signed attestation report over a TLS certificate fingerprint
func attestationReport(certFP string) (*attestation.Document, error) {
	var userData [64]byte
	copy(userData[:], certFP)

	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote provider: %v", err)
	}
	report, err := qp.GetRawQuote(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %v", err)
	}

	if len(report) > abi.ReportSize {
		report = report[:abi.ReportSize]
	}

	return &attestation.Document{
		Format: attestation.SevGuestV1,
		Body:   base64.StdEncoding.EncodeToString(report),
	}, nil
}

func cors(w http.ResponseWriter, r *http.Request) {
	w.Header().Del("Access-Control-Allow-Origin")
	w.Header().Del("Access-Control-Allow-Methods")
	w.Header().Del("Access-Control-Allow-Headers")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

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

	if config.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	if config.ListenPort == 0 {
		config.ListenPort = 443
	}
	if config.UpstreamPort == 0 {
		log.Fatalf("Upstream port must be set")
	}

	log.Printf("Starting SEV-SNP attestation shim %s: %+v", version, config)

	mux := http.NewServeMux()

	// Request TLS certificate
	var tlsConfig *tls.Config
	if config.Domain != "" {
		certmagic.Default.Storage = &certmagic.FileStorage{Path: certCache}
		certmagic.DefaultACME.Email = email
		if config.StagingCA {
			certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
		} else {
			certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
		}
		tlsConfig, err = certmagic.TLS([]string{config.Domain})
		if err != nil {
			log.Fatalf("Failed to get TLS config: %v", err)
		}
	} else {
		cert, err := tlsCertificate("localhost")
		if err != nil {
			log.Fatalf("Failed to generate self signed TLS certificate: %v", err)
		}
		tlsConfig = &tls.Config{
			GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return cert, nil
			},
		}
	}

	var rateLimiter *RateLimiter
	if config.RateLimit > 0 {
		rateLimiter = NewRateLimiter(rate.Limit(config.RateLimit), config.RateBurst)
	}

	// Get certificate from TLS config
	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{
		ServerName: config.Domain,
	})
	if err != nil {
		log.Fatalf("Failed to get certificate: %v", err)
	}
	certFP := sha256.Sum256(cert.Leaf.Raw)
	certFPHex := hex.EncodeToString(certFP[:])

	// Request SEV-SNP attestation
	var att any
	if config.Domain == "" {
		log.Warn("No domain configured, using dummy attestation report")
		att = []byte(`DUMMY ATTESTATION`)
	} else {
		log.Printf("Fetching attestation over %s", certFPHex)
		att, err = attestationReport(certFPHex)
		if err != nil {
			log.Fatal(err)
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		if config.KeyServer != "" {
			req, err := http.NewRequest("POST", config.KeyServer, nil)
			if err != nil {
				log.Warnf("Failed to create request: %v", err)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			req.Header.Set("Authorization", auth)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Warnf("Failed to proxy request: %v", err)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			if resp.StatusCode != http.StatusOK {
				w.WriteHeader(resp.StatusCode)
				w.Write([]byte("unauthorized"))
				return
			}
		}

		if rateLimiter != nil {
			if auth == "" {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			limiter := rateLimiter.Limit(auth)
			if !limiter.Allow() {
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}
		}

		// cors(w, r)

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

		proxy := httputil.ReverseProxy{
			Director: func(req *http.Request) {
				log.Debugf("Orig to %+v", req.Header)
				req.URL.Scheme = "http"
				req.URL.Host = fmt.Sprintf("127.0.0.1:%d", config.UpstreamPort)
				req.Header.Set("Host", "localhost")
				req.Host = "localhost"
				log.Debugf("Proxying request to %+v", req.URL.String())
			},
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
