package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"net/http"
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
	config *lego.Config
	client *lego.Client
}

func NewCertManager(email string, privateKey *ecdsa.PrivateKey) (*CertManager, error) {
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
		config: config,
		client: client,
	}, nil
}

func (m *CertManager) RequestCert(domains []string) (*tls.Certificate, error) {
	log.Debugf("Requesting certificate for: %v", domains)
	certResource, err := m.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	cert, err := tls.X509KeyPair(certResource.Certificate, certResource.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Debug("Certificate obtained")
	return &cert, nil
}
