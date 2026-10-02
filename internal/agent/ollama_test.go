package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOllamaGenerateSendsStructuredRequestAndReturnsMessageContent(t *testing.T) {
	const prompt = "opaque investigator prompt"
	const content = `{"summary":"Potential propagation is indicated.","findings":[],"uncertainty":[],"nextSteps":[]}`

	var got ollamaChatRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/chat" {
			t.Errorf("request = %s %s, want POST /api/chat", request.Method, request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"message":{"content":` + mustJSON(t, content) + `,"thinking":"not the result"},"done":true}`))
	}))
	defer server.Close()

	model := newTestOllamaModel(t, server.URL, "gemma4:e2b", time.Second)
	result, err := model.Generate(context.Background(), prompt)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if result != content {
		t.Fatalf("Generate() = %q, want exactly message.content %q", result, content)
	}
	if got.Model != "gemma4:e2b" {
		t.Errorf("request model = %q, want gemma4:e2b", got.Model)
	}
	if got.Stream {
		t.Error("request stream = true, want false")
	}
	if len(got.Messages) != 1 || got.Messages[0].Role != "user" || got.Messages[0].Content != prompt {
		t.Errorf("request messages = %#v, want the prompt unchanged in one user message", got.Messages)
	}
	if !json.Valid(got.Format) {
		t.Fatalf("request format is not valid JSON Schema: %s", got.Format)
	}
	var schema map[string]any
	if err := json.Unmarshal(got.Format, &schema); err != nil {
		t.Fatalf("decode request schema: %v", err)
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Errorf("request schema root = %#v, want a closed JSON object schema", schema)
	}
}

func TestOllamaGenerateReturnsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "model unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	model := newTestOllamaModel(t, server.URL, "gemma4:e2b", time.Second)
	if _, err := model.Generate(context.Background(), "prompt"); err == nil || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("Generate() error = %v, want HTTP status error", err)
	}
}

func TestOllamaGenerateRejectsMalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"message":`))
	}))
	defer server.Close()

	model := newTestOllamaModel(t, server.URL, "gemma4:e2b", time.Second)
	if _, err := model.Generate(context.Background(), "prompt"); err == nil || !strings.Contains(err.Error(), "decode Ollama chat response") {
		t.Fatalf("Generate() error = %v, want malformed response error", err)
	}
}

func TestOllamaGenerateRejectsMissingMessageContent(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing", body: `{"message":{}}`},
		{name: "empty", body: `{"message":{"content":""}}`},
		{name: "whitespace", body: `{"message":{"content":"  "}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()

			model := newTestOllamaModel(t, server.URL, "gemma4:e2b", time.Second)
			if _, err := model.Generate(context.Background(), "prompt"); err == nil || !strings.Contains(err.Error(), "missing message.content") {
				t.Fatalf("Generate() error = %v, want missing-content error", err)
			}
		})
	}
}

func TestOllamaGeneratePropagatesContextCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
	}))
	defer func() {
		releaseHandler()
		server.Close()
	}()

	model := newTestOllamaModel(t, server.URL, "gemma4:e2b", time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := model.Generate(ctx, "prompt")
		errCh <- err
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("request did not reach test server")
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Generate() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Generate() did not return after cancellation")
	}
	releaseHandler()
}

func TestOllamaGenerateTimesOut(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer func() {
		releaseHandler()
		server.Close()
	}()

	model := newTestOllamaModel(t, server.URL, "gemma4:e2b", 40*time.Millisecond)
	if _, err := model.Generate(context.Background(), "prompt"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Generate() error = %v, want context.DeadlineExceeded", err)
	}
	releaseHandler()
}

func TestOllamaSchemaIsDeterministic(t *testing.T) {
	var mu sync.Mutex
	var schemas [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var got ollamaChatRequest
		if err := json.NewDecoder(request.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		mu.Lock()
		schemas = append(schemas, append([]byte(nil), got.Format...))
		mu.Unlock()
		_, _ = writer.Write([]byte(`{"message":{"content":"{}"}}`))
	}))
	defer server.Close()

	model := newTestOllamaModel(t, server.URL, "gemma4:e2b", time.Second)
	for range 2 {
		if _, err := model.Generate(context.Background(), "prompt"); err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
	}
	if len(schemas) != 2 || string(schemas[0]) != string(schemas[1]) {
		t.Fatalf("schemas differ between requests: %q != %q", schemas[0], schemas[1])
	}
}

func TestNewOllamaModelAcceptsNonLoopbackEndpoint(t *testing.T) {
	model, err := NewOllamaModel(OllamaConfig{
		BaseURL: "https://ollama.example.com:11434",
		Model:   "gemma4:e2b",
	})
	if err != nil {
		t.Fatalf("NewOllamaModel() error = %v", err)
	}
	if model.endpoint != "https://ollama.example.com:11434/api/chat" {
		t.Errorf("endpoint = %q, want HTTPS Ollama chat endpoint", model.endpoint)
	}
}

func TestNewOllamaModelRejectsMalformedBaseURL(t *testing.T) {
	if _, err := NewOllamaModel(OllamaConfig{BaseURL: "http://[::1", Model: "gemma4:e2b"}); err == nil {
		t.Fatal("NewOllamaModel() error = nil, want malformed URL error")
	}
}

func TestNewOllamaModelDefaultsToLocalEndpointAndTimeout(t *testing.T) {
	model, err := NewOllamaModel(OllamaConfig{Model: "gemma4:e2b"})
	if err != nil {
		t.Fatal(err)
	}
	if model.endpoint != defaultOllamaBaseURL+"/api/chat" {
		t.Errorf("endpoint = %q, want local default", model.endpoint)
	}
	if model.client.Timeout != defaultOllamaTimeout {
		t.Errorf("timeout = %s, want %s", model.client.Timeout, defaultOllamaTimeout)
	}
}

func newTestOllamaModel(t *testing.T, baseURL, model string, timeout time.Duration) *OllamaModel {
	t.Helper()
	ollamaModel, err := NewOllamaModel(OllamaConfig{BaseURL: baseURL, Model: model, Timeout: timeout})
	if err != nil {
		t.Fatalf("NewOllamaModel() error = %v", err)
	}
	return ollamaModel
}

func mustJSON(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
