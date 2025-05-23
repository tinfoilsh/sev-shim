package dcode

import (
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tinfoilsh/verifier/attestation"
)

func TestDcode(t *testing.T) {
	attJSON := `{"format":"https://tinfoil.sh/predicate/sev-snp-guest/v1","body":"AgAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAHAAAAAAAOSAEAAAAAAAAAAAAAAAAAAAA0NWUzYzMzMGUwNmJmOWMxZjhhMTk3MjY2YWNhNWIyZjYwNjdjYTY3MTliNjFiZTY2ZDA0M2I5M2RiOTkwYTg1pbDO1EKABUY06EUsfj2O0Mck9pCpNNU09zjmp0q75OMmy7Ri71JFfU/fjzZf6hhEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACfpCeQfLGlscId5BeSdU7L9KPEStDMwQBd808awA+Lv//////////////////////////////////////////BwAAAAAADkgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADyerBPBb0BVIg1GpCjfyjOa7GVEfbmBlI2UlOv2mBy2PUlhAoxzCPRyGlUox+FWyw/5T1fgVISjEAzuoWzsKeXBwAAAAAADkgVNwEAFTcBAAcAAAAAAA5IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1Mswgg2AZ5e1wct6QcyLfOAKrb6jCKQRNateCyHdAdEKBTusDgtrXpEFXR/39cQVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc9yN4XkSVWve3jGL93egyyv2O6hLAdV5JVm/j1qugeFIfr+DKUBYB5WcU+jSeKy5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`
	var att attestation.Document
	if err := json.Unmarshal([]byte(attJSON), &att); err != nil {
		panic(err)
	}

	domains, err := Encode(&att, "example.com")
	assert.Nil(t, err)

	for _, domain := range domains {
		assert.True(t, strings.HasSuffix(domain, ".example.com"))
	}

	t.Logf("encoded %d bytes into %d domains", len(attJSON), len(domains))

	// Randomize domain order
	rand.Shuffle(len(domains), func(i, j int) {
		domains[i], domains[j] = domains[j], domains[i]
	})

	for _, domain := range domains {
		t.Logf("domain: %s", domain)
	}

	decoded, err := Decode(domains)
	assert.Nil(t, err)
	assert.Equal(t, att, *decoded)
}
