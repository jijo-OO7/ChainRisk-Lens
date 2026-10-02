package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultOllamaBaseURL = "http://127.0.0.1:11434"
	defaultOllamaTimeout = 5 * time.Minute
	maxOllamaResponse    = 4 << 20
	maxOllamaErrorBody   = 4 << 10
)

const ollamaInvestigationSchema = `{
  "type": "object",
  "properties": {
    "summary": {"type": "string"},
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "statement": {"type": "string"},
          "evidence": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "bomRefs": {"type": "array", "items": {"type": "string"}}
              },
              "required": ["bomRefs"],
              "additionalProperties": false
            }
          }
        },
        "required": ["statement", "evidence"],
        "additionalProperties": false
      }
    },
    "uncertainty": {"type": "array", "items": {"type": "string"}},
    "nextSteps": {"type": "array", "items": {"type": "string"}}
  },
  "required": ["summary", "findings", "uncertainty", "nextSteps"],
  "additionalProperties": false
}`

// OllamaConfig configures the local Ollama chat endpoint and request timeout.
type OllamaConfig struct {
	BaseURL string
	Model   string
	Timeout time.Duration
}

// OllamaModel implements Model using Ollama's local, non-streaming chat API.
type OllamaModel struct {
	endpoint string
	model    string
	client   *http.Client
}

// NewOllamaModel creates an Ollama-backed model. The endpoint must use HTTP on
// a loopback address; model installation and downloading are not performed.
func NewOllamaModel(config OllamaConfig) (*OllamaModel, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = defaultOllamaBaseURL
	}
	endpoint, err := ollamaChatEndpoint(baseURL)
	if err != nil {
		return nil, err
	}

	modelName := strings.TrimSpace(config.Model)
	if modelName == "" {
		return nil, errors.New("Ollama model name is empty")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultOllamaTimeout
	}
	if timeout < 0 {
		return nil, errors.New("Ollama timeout must be positive")
	}

	return &OllamaModel{
		endpoint: endpoint,
		model:    modelName,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy: nil,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Generate sends prompt unchanged as a user message and returns only the
// assistant message content for Investigator's structured-result validation.
func (model *OllamaModel) Generate(ctx context.Context, prompt string) (string, error) {
	requestBody, err := json.Marshal(ollamaChatRequest{
		Model: model.model,
		Messages: []ollamaMessage{{
			Role:    "user",
			Content: prompt,
		}},
		Stream: false,
		Format: json.RawMessage(ollamaInvestigationSchema),
	})
	if err != nil {
		return "", fmt.Errorf("marshal Ollama chat request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, model.endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return "", fmt.Errorf("construct Ollama chat request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := model.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("send Ollama chat request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxOllamaErrorBody))
		if readErr != nil {
			return "", fmt.Errorf("Ollama chat returned %s (read error body: %w)", response.Status, readErr)
		}
		return "", fmt.Errorf("Ollama chat returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxOllamaResponse+1))
	if err != nil {
		return "", fmt.Errorf("read Ollama chat response: %w", err)
	}
	if len(body) > maxOllamaResponse {
		return "", fmt.Errorf("Ollama chat response exceeds %d bytes", maxOllamaResponse)
	}

	var envelope ollamaChatResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("decode Ollama chat response: %w", err)
	}
	if envelope.Message == nil || envelope.Message.Content == nil || strings.TrimSpace(*envelope.Message.Content) == "" {
		return "", errors.New("Ollama chat response is missing message.content")
	}
	return *envelope.Message.Content, nil
}

func ollamaChatEndpoint(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse Ollama base URL: %w", err)
	}
	if parsed.Scheme != "http" || parsed.Opaque != "" || parsed.Host == "" {
		return "", errors.New("Ollama base URL must be an http URL on a loopback address")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("Ollama base URL must not contain credentials, a path, query, or fragment")
	}

	host := parsed.Hostname()
	if !strings.EqualFold(host, "localhost") {
		address := net.ParseIP(host)
		if address == nil || !address.IsLoopback() {
			return "", errors.New("Ollama base URL must use a loopback address; remote endpoints are not allowed")
		}
	}

	return strings.TrimRight(parsed.String(), "/") + "/api/chat", nil
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Format   json.RawMessage `json:"format"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatResponse struct {
	Message *ollamaResponseMessage `json:"message"`
}

type ollamaResponseMessage struct {
	Content  *string `json:"content"`
	Thinking string  `json:"thinking"`
}
