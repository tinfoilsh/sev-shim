package key

import (
	"errors"
	"github.com/tinfoilsh/sev-shim/key/offline"
	"github.com/tinfoilsh/sev-shim/key/online"
)

var ErrAPIKeyRequired = errors.New("API key required")

type Validator interface {
	Validate(apiKey string) error
}

var (
	_ Validator = &offline.Validator{}
	_ Validator = &online.Validator{}
)
