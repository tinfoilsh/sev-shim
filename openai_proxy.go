package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

type streamingResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Delta struct {
			Role    string `json:"role"`
			Content string `json:"content"`
			Padding string `json:"p"`
		} `json:"delta"`
	} `json:"choices"`
}

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"` // String or array of content parts
	} `json:"messages"`
}

func tokenizeAudioResponse(resp *http.Response) (int, error) {
	reqBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read request body: %w", err)
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(reqBody))

	var body struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(reqBody, &body); err != nil {
		return 0, fmt.Errorf("failed to unmarshal request body: %w", err)
	}
	return len(body.Text) / 4, nil
}

type streamTransport struct {
	tokenRecorder *TokenRecorder
	base          http.RoundTripper
}

func (t *streamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if this is a streaming request
	var isStreaming bool
	if req.URL.Path == "/v1/chat/completions" {
		var cr chatRequest
		if body, err := io.ReadAll(req.Body); err == nil {
			if err := json.Unmarshal(body, &cr); err == nil {
				isStreaming = cr.Stream
			}
			// Restore the body
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	// Make the actual request
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if !isStreaming || resp.Header.Get("Content-Type") != "text/event-stream" {
		return resp, nil
	}

	// SSE headers
	resp.Header.Set("Cache-Control", "no-cache")
	resp.Header.Set("Connection", "keep-alive")
	resp.Header.Del("Content-Length")

	// Create a pipe to modify the response stream
	pr, pw := io.Pipe()
	originalBody := resp.Body
	resp.Body = pr

	go func() {
		defer originalBody.Close()
		defer pw.Close()

		scanner := bufio.NewScanner(originalBody)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") && line != "data: [DONE]" {
				var stream streamingResponse
				data := strings.TrimPrefix(line, "data: ")
				if err := json.Unmarshal([]byte(data), &stream); err != nil {
					pw.Write([]byte(line + "\n"))
					continue
				}

				// Count tokens from this chunk
				chunkTokens := 0
				for _, choice := range stream.Choices {
					if choice.Delta.Content != "" {
						chunkTokens += max(len(choice.Delta.Content)/4, 1)
					}
				}

				if chunkTokens > 0 && t.tokenRecorder != nil {
					apiKey := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
					t.tokenRecorder.Record(apiKey, stream.Model, chunkTokens)
				}

				// Add padding to first choice if available
				if len(stream.Choices) > 0 {
					const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
					minLength := 4
					maxLength := len(charset)
					r, err := rand.Int(rand.Reader, big.NewInt(int64(maxLength-minLength+1)))
					if err != nil {
						log.Warnf("Failed to generate random padding: %v", err)
						continue
					}
					stream.Choices[0].Delta.Padding = charset[:minLength+int(r.Int64())]
				}

				// Write modified data
				modifiedData, err := json.Marshal(stream)
				if err != nil {
					pw.Write([]byte(line + "\n"))
					continue
				}
				pw.Write([]byte("data: " + string(modifiedData) + "\n"))
			} else {
				pw.Write([]byte(line + "\n"))
			}
		}
	}()

	return resp, nil
}
