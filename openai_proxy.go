package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

type responseWriter struct {
	Model  string
	APIKey string
	Tokens int

	tokenRecorder *TokenRecorder
	http.ResponseWriter
}

type streamingResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Delta struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

func (w *responseWriter) Write(b []byte) (int, error) {
	// Check content type to determine how to handle the response
	contentType := w.Header().Get("Content-Type")
	if strings.Contains(contentType, "application/json") { // Handle non-streaming JSON responses
		var response struct {
			Model string `json:"model"`
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(b, &response); err == nil {
			w.Tokens += response.Usage.CompletionTokens
			w.tokenRecorder.Record(w.APIKey, w.Model, w.Tokens)
		}
	} else if strings.Contains(contentType, "text/event-stream") { // Handle streaming responses
		lines := strings.Split(string(b), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "data: ") && line != "data: [DONE]" {
				data := strings.TrimPrefix(line, "data: ")
				var stream streamingResponse
				if err := json.Unmarshal([]byte(data), &stream); err == nil {
					chunkTextLength := 0
					for _, choice := range stream.Choices {
						chunkTextLength += len(choice.Delta.Content)
					}

					w.Tokens += max(chunkTextLength/4, 1)
				}
			} else if line == "data: [DONE]" {
				w.tokenRecorder.Record(w.APIKey, w.Model, w.Tokens)
			}
		}
	}

	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *responseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
