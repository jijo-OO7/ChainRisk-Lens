package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jijo-OO7/chainrisk-lens/internal/agent"
	"github.com/jijo-OO7/chainrisk-lens/internal/investigation"
	"github.com/jijo-OO7/chainrisk-lens/internal/sbom"
)

func TestDetectSetupStatusPlatformAndWSL(t *testing.T) {
	probes := setupProbes{
		goos:       "linux",
		goarch:     "arm64",
		lookupExec: func(string) (string, error) { return "/bin/ollama", nil },
		getenv: func(key string) string {
			if key == "WSL_DISTRO_NAME" {
				return "Ubuntu"
			}
			return ""
		},
		readFile: func(string) ([]byte, error) { return nil, errors.New("not needed") },
	}
	status := detectSetupStatus(defaultOllamaConfig(), probes)
	if status.goos != "linux" || status.goarch != "arm64" || status.wsl != "yes" {
		t.Fatalf("platform = %s/%s WSL %s, want linux/arm64 WSL yes", status.goos, status.goarch, status.wsl)
	}
}

func TestDetectSetupStatusExecutableAvailabilityIsSeparateFromAPI(t *testing.T) {
	for _, test := range []struct {
		name       string
		lookup     func(string) (string, error)
		wantBinary string
	}{
		{
			name:       "absent",
			lookup:     func(string) (string, error) { return "", errors.New("not found") },
			wantBinary: "not found",
		},
		{
			name:       "present",
			lookup:     func(string) (string, error) { return "/fake/bin/ollama", nil },
			wantBinary: "available (/fake/bin/ollama)",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTagsServer(t, http.StatusOK, `{"models":[]}`)
			defer server.Close()
			probes := setupTestProbes(server.URL, test.lookup)

			status := detectSetupStatus(setupTestConfig(server.URL), probes)
			if status.executable != test.wantBinary {
				t.Errorf("executable = %q, want %q", status.executable, test.wantBinary)
			}
			if status.api != "available" || status.model != "missing" {
				t.Errorf("API/model = %q/%q, want available/missing independently of executable", status.api, status.model)
			}
		})
	}
}

func TestDetectSetupStatusAPIResponseStates(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantAPI    string
		wantModel  string
	}{
		{
			name:       "unavailable",
			statusCode: http.StatusServiceUnavailable,
			body:       `{"error":"starting"}`,
			wantAPI:    "unavailable (HTTP 503)",
			wantModel:  "unknown (API unavailable)",
		},
		{
			name:       "malformed JSON",
			statusCode: http.StatusOK,
			body:       `{"models":`,
			wantAPI:    "unavailable (malformed response)",
			wantModel:  "unknown (API unavailable)",
		},
		{
			name:       "missing models field",
			statusCode: http.StatusOK,
			body:       `{}`,
			wantAPI:    "unavailable (response is missing models)",
			wantModel:  "unknown (API unavailable)",
		},
		{
			name:       "invalid models field",
			statusCode: http.StatusOK,
			body:       `{"models":null}`,
			wantAPI:    "unavailable (malformed models list)",
			wantModel:  "unknown (API unavailable)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTagsServer(t, test.statusCode, test.body)
			defer server.Close()
			status := detectSetupStatus(setupTestConfig(server.URL), setupTestProbes(server.URL, func(string) (string, error) {
				return "/fake/bin/ollama", nil
			}))
			if status.api != test.wantAPI || status.model != test.wantModel {
				t.Errorf("API/model = %q/%q, want %q/%q", status.api, status.model, test.wantAPI, test.wantModel)
			}
		})
	}
}

func TestDetectSetupStatusConfiguredModel(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "present by name",
			body: `{"models":[{"name":"gemma4:e2b"}]}`,
			want: "available",
		},
		{
			name: "present by model field",
			body: `{"models":[{"model":"gemma4:e2b"}]}`,
			want: "available",
		},
		{
			name: "different model",
			body: `{"models":[{"name":"other:latest"}]}`,
			want: "missing",
		},
		{
			name: "empty list",
			body: `{"models":[]}`,
			want: "missing",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTagsServer(t, http.StatusOK, test.body)
			defer server.Close()
			status := detectSetupStatus(setupTestConfig(server.URL), setupTestProbes(server.URL, func(string) (string, error) {
				return "/fake/bin/ollama", nil
			}))
			if status.api != "available" || status.model != test.want {
				t.Errorf("API/model = %q/%q, want available/%q", status.api, status.model, test.want)
			}
		})
	}
}

func TestDetectSetupStatusRemoteEndpointDoesNotRequireLocalExecutable(t *testing.T) {
	lookupCalls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "ollama.example:11434" || request.URL.Path != "/api/tags" {
			t.Errorf("probe URL = %s, want remote Ollama /api/tags", request.URL)
		}
		return setupHTTPResponse(request, http.StatusOK, `{"models":[{"name":"gemma4:e2b"}]}`), nil
	})}
	probes := setupProbes{
		goos:       "linux",
		goarch:     "amd64",
		lookupExec: func(string) (string, error) { lookupCalls++; return "", errors.New("not found") },
		getenv:     func(string) string { return "" },
		readFile:   func(string) ([]byte, error) { return []byte("linux"), nil },
		httpClient: client,
	}
	config := setupTestConfig("http://ollama.example:11434")
	status := detectSetupStatus(config, probes)
	if !status.remote || status.executable != "not required (remote endpoint)" {
		t.Errorf("remote/executable = %t/%q, want true/not required", status.remote, status.executable)
	}
	if lookupCalls != 0 {
		t.Errorf("local executable lookup called %d times for remote endpoint, want 0", lookupCalls)
	}
	if status.api != "available" || status.model != "available" {
		t.Errorf("API/model = %q/%q, want available/available", status.api, status.model)
	}
}

func TestDetectSetupStatusRejectsMalformedConfiguration(t *testing.T) {
	probes := setupTestProbes("", func(string) (string, error) {
		t.Fatal("executable lookup called with invalid config")
		return "", nil
	})
	status := detectSetupStatus(agent.OllamaConfig{BaseURL: "http://[", Model: defaultOllamaModel}, probes)
	if status.configurationError == "" || status.api != "not checked (invalid configuration)" {
		t.Fatalf("status = %#v, want clear invalid configuration without probing", status)
	}
}

func TestSetupOutputIsDeterministicAndExplainsMissingModel(t *testing.T) {
	server := newTagsServer(t, http.StatusOK, `{"models":[]}`)
	defer server.Close()
	status := detectSetupStatus(setupTestConfig(server.URL), setupTestProbes(server.URL, func(string) (string, error) {
		return "/fake/bin/ollama", nil
	}))
	first := formatSetupStatus(status)
	second := formatSetupStatus(status)
	if first != second {
		t.Fatalf("setup output changed between identical inputs:\n%s\n%s", first, second)
	}
	for _, want := range []string{
		"Core analysis: ready (no Ollama, model, or network required)",
		"Ollama API: available",
		"Configured model: missing",
		"ollama pull gemma4:e2b",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("setup output does not contain %q:\n%s", want, first)
		}
	}
}

func TestSetupAndAnalyzeDoNotInvokeInvestigator(t *testing.T) {
	server := newTagsServer(t, http.StatusOK, `{"models":[]}`)
	defer server.Close()
	factoryCalls := 0
	factory := func(agent.OllamaConfig) (investigation.Investigator, error) {
		factoryCalls++
		return nil, errors.New("investigator must not be created")
	}
	probes := setupTestProbes(server.URL, func(string) (string, error) { return "", errors.New("not found") })

	var setupOutput strings.Builder
	if err := runWithSetupDependencies(context.Background(), []string{"setup"}, &setupOutput, factory, setupTestConfig(server.URL), probes); err != nil {
		t.Fatalf("setup error = %v", err)
	}
	if factoryCalls != 0 {
		t.Fatalf("setup invoked investigator factory %d times", factoryCalls)
	}

	sbomPath := writeSBOM(t, sbom.SBOM{Components: []sbom.Component{{BOMRef: "target", Name: "target", Version: "1"}}})
	var analyzeOutput strings.Builder
	if err := runWithSetupDependencies(context.Background(), []string{"analyze", sbomPath, "--target", "target"}, &analyzeOutput, factory, setupTestConfig(server.URL), setupProbes{
		goos:       "linux",
		goarch:     "amd64",
		lookupExec: func(string) (string, error) { t.Fatal("analyze looked up Ollama"); return "", nil },
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("analyze probed Ollama API")
			return nil, nil
		})},
	}); err != nil {
		t.Fatalf("analyze error = %v", err)
	}
	if factoryCalls != 0 {
		t.Errorf("analyze invoked investigator factory %d times", factoryCalls)
	}
}

func setupTestConfig(baseURL string) agent.OllamaConfig {
	config := defaultOllamaConfig()
	config.BaseURL = baseURL
	return config
}

func setupTestProbes(baseURL string, lookup func(string) (string, error)) setupProbes {
	client := http.DefaultClient
	if baseURL != "" {
		client = &http.Client{Timeout: setupHTTPTimeout}
	}
	return setupProbes{
		goos:       "linux",
		goarch:     "amd64",
		lookupExec: lookup,
		getenv:     func(string) string { return "" },
		readFile:   func(string) ([]byte, error) { return []byte("linux"), nil },
		httpClient: client,
	}
}

func newTagsServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/tags" {
			t.Errorf("request = %s %s, want GET /api/tags", request.Method, request.URL.Path)
		}
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, body)
	}))
	return server
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func setupHTTPResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}
