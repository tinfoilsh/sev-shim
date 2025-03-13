package main

import (
	"encoding/json"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

type responseWriter struct {
	Server              string
	APIKey              string
	streamContentLength int
	http.ResponseWriter
}

type oneShotResponse struct {
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}

type streamingResponse struct {
	Choices []struct {
		Delta struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

func (w *responseWriter) account(tokens int) {
	var b struct {
		APIKey string `json:"api_key"`
		Tokens int    `json:"tokens"`
	}
	b.APIKey = w.APIKey
	b.Tokens = tokens

	body, err := json.Marshal(b)
	if err != nil {
		log.Warnf("Failed to marshal response: %v", err)
		return
	}

	resp, err := http.Post(w.Server, "application/json", strings.NewReader(string(body)))
	if err != nil {
		log.Warnf("Failed to post response: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Warnf("Failed to post response: %v", resp.Status)
		return
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)

	isStream := strings.Contains(w.Header().Get("Content-Type"), "text/event-stream")
	if isStream {
		lines := strings.Split(string(b), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if strings.TrimSpace(data) == "" {
				continue
			}

			if data == "[DONE]" {
				tokens := w.streamContentLength / 4
				w.account(tokens)
				continue
			}

			var resp streamingResponse
			if err := json.Unmarshal([]byte(data), &resp); err != nil {
				log.Warnf("Failed to unmarshal streaming response for data '%s': %v", data, err)
				continue
			}

			if len(resp.Choices) > 0 {
				choice := resp.Choices[0]
				if choice.Delta.Content != "" {
					w.streamContentLength += len(choice.Delta.Content)
				}
			}
		}
	} else {
		var resp oneShotResponse
		if err := json.Unmarshal(b, &resp); err != nil {
			log.Warnf("Failed to unmarshal response: %v", err)
		} else {
			w.account(resp.Usage.TotalTokens)
		}
	}

	return n, err
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}
