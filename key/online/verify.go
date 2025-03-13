package online

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

type Validator struct {
	server string
}

func NewValidator(server string) (*Validator, error) {
	return &Validator{
		server: server,
	}, nil
}

func (v *Validator) Validate(apiKey string) error {
	resp, err := http.Post(v.server, "application/json", bytes.NewBufferString(apiKey))
	if err != nil {
		return err
	}
	if resp.StatusCode == 200 {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return fmt.Errorf("failed to validate key: %s", string(body))
}
