package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	log "github.com/sirupsen/logrus"
)

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.Email
}
func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type CertManager struct {
	config   *lego.Config
	client   *lego.Client
	cacheDir string
}

func NewCertManager(email, cacheDir string, privateKey *ecdsa.PrivateKey) (*CertManager, error) {
	user := &acmeUser{Email: email, key: privateKey}
	config := &lego.Config{
		CADirURL:   lego.LEDirectoryProduction,
		User:       user,
		HTTPClient: http.DefaultClient,
		Certificate: lego.CertificateConfig{
			KeyType: certcrypto.RSA2048,
			Timeout: 30 * time.Second,
		},
	}
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	if err := client.Challenge.SetTLSALPN01Provider(
		tlsalpn01.NewProviderServer("", "443"),
	); err != nil {
		return nil, fmt.Errorf("failed to set TLS-ALPN-01 provider: %w", err)
	}

	log.Debug("Registering ACME account")
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register account: %w", err)
	}
	user.Registration = reg

	return &CertManager{
		config:   config,
		client:   client,
		cacheDir: cacheDir,
	}, nil
}

func (m *CertManager) RequestCert(domains []string) (*tls.Certificate, error) {
	certFile := filepath.Join(m.cacheDir, "cert.pem")
	keyFile := filepath.Join(m.cacheDir, "key.pem")

	if _, err := os.Stat(certFile); err == nil {
		log.Debug("Certificate found in cache, using cached certificate")
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load cached certificate: %w", err)
		}
		return &cert, nil
	}

	log.Debugf("Requesting certificate for: %v", domains)
	certResource, err := m.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	// Write to cache
	if err := os.WriteFile(certFile, certResource.Certificate, 0644); err != nil {
		return nil, fmt.Errorf("failed to write certificate to cache: %w", err)
	}
	if err := os.WriteFile(keyFile, certResource.PrivateKey, 0644); err != nil {
		return nil, fmt.Errorf("failed to write private key to cache: %w", err)
	}

	cert, err := tls.X509KeyPair(certResource.Certificate, certResource.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Debug("Certificate obtained")
	return &cert, nil
}
