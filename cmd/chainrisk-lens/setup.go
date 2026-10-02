package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/jijo-OO7/chainrisk-lens/internal/agent"
)

const (
	setupHTTPTimeout = 2 * time.Second
	setupMaxBody     = 1 << 20
)

type setupProbes struct {
	goos       string
	goarch     string
	lookupExec func(string) (string, error)
	getenv     func(string) string
	readFile   func(string) ([]byte, error)
	httpClient *http.Client
}

type setupStatus struct {
	goos               string
	goarch             string
	wsl                string
	ollamaURL          string
	remote             bool
	configurationError string
	executable         string
	api                string
	model              string
	modelPullCommand   string
}

type ollamaTagsResponse struct {
	Models json.RawMessage `json:"models"`
}

type ollamaTag struct {
	Name  string `json:"name"`
	Model string `json:"model"`
}

func defaultSetupProbes() setupProbes {
	return setupProbes{
		goos:       runtime.GOOS,
		goarch:     runtime.GOARCH,
		lookupExec: exec.LookPath,
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
		httpClient: &http.Client{Timeout: setupHTTPTimeout},
	}
}

func runSetup(args []string, output io.Writer, config agent.OllamaConfig, probes setupProbes) error {
	if len(args) != 0 {
		return errors.New("usage: chainrisk-lens setup")
	}
	status := detectSetupStatus(config, probes)
	if _, err := io.WriteString(output, formatSetupStatus(status)); err != nil {
		return fmt.Errorf("write setup status: %w", err)
	}
	return nil
}

func detectSetupStatus(config agent.OllamaConfig, probes setupProbes) setupStatus {
	if probes.goos == "" {
		probes.goos = runtime.GOOS
	}
	if probes.goarch == "" {
		probes.goarch = runtime.GOARCH
	}
	if probes.lookupExec == nil {
		probes.lookupExec = exec.LookPath
	}
	if probes.getenv == nil {
		probes.getenv = os.Getenv
	}
	if probes.readFile == nil {
		probes.readFile = os.ReadFile
	}
	if probes.httpClient == nil {
		probes.httpClient = &http.Client{Timeout: setupHTTPTimeout}
	}

	status := setupStatus{
		goos:   probes.goos,
		goarch: probes.goarch,
	}
	if probes.goos == "linux" {
		status.wsl = detectWSL(probes.getenv, probes.readFile)
	} else {
		status.wsl = "not applicable"
	}

	if config.BaseURL == "" {
		config.BaseURL = defaultOllamaBaseURL
	}
	if strings.TrimSpace(config.Model) == "" {
		status.configurationError = "configured Ollama model is empty"
		status.executable = "not checked (invalid configuration)"
		status.api = "not checked (invalid configuration)"
		status.model = "not checked (invalid configuration)"
		return status
	}

	if _, err := agent.NewOllamaModel(config); err != nil {
		status.configurationError = err.Error()
		status.executable = "not checked (invalid configuration)"
		status.api = "not checked (invalid configuration)"
		status.model = "not checked (invalid configuration)"
		return status
	}

	parsedURL, _ := url.Parse(config.BaseURL)
	status.ollamaURL = config.BaseURL
	status.remote = !isLoopbackHost(parsedURL.Hostname())
	configuredModel := strings.TrimSpace(config.Model)
	status.modelPullCommand = "ollama pull " + configuredModel

	if status.remote {
		status.executable = "not required (remote endpoint)"
	} else if path, err := probes.lookupExec("ollama"); err != nil {
		status.executable = "not found"
	} else {
		status.executable = "available (" + path + ")"
	}

	endpoint := strings.TrimRight(config.BaseURL, "/") + "/api/tags"
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		status.api = "unavailable (invalid request URL)"
		status.model = "unknown (API unavailable)"
		return status
	}
	response, err := probes.httpClient.Do(request)
	if err != nil {
		status.api = "unavailable (" + err.Error() + ")"
		status.model = "unknown (API unavailable)"
		return status
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		status.api = fmt.Sprintf("unavailable (HTTP %d)", response.StatusCode)
		status.model = "unknown (API unavailable)"
		return status
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, setupMaxBody+1))
	if err != nil || len(body) > setupMaxBody {
		status.api = "unavailable (invalid response body)"
		status.model = "unknown (API unavailable)"
		return status
	}
	var tags ollamaTagsResponse
	if err := json.Unmarshal(body, &tags); err != nil {
		status.api = "unavailable (malformed response)"
		status.model = "unknown (API unavailable)"
		return status
	}
	if len(tags.Models) == 0 {
		status.api = "unavailable (response is missing models)"
		status.model = "unknown (API unavailable)"
		return status
	}
	var models []ollamaTag
	if err := json.Unmarshal(tags.Models, &models); err != nil || models == nil {
		status.api = "unavailable (malformed models list)"
		status.model = "unknown (API unavailable)"
		return status
	}

	status.api = "available"
	for _, model := range models {
		if model.Name == configuredModel || model.Model == configuredModel {
			status.model = "available"
			return status
		}
	}
	status.model = "missing"
	return status
}

func detectWSL(getenv func(string) string, readFile func(string) ([]byte, error)) string {
	if getenv("WSL_INTEROP") != "" || getenv("WSL_DISTRO_NAME") != "" {
		return "yes"
	}
	data, err := readFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	kernel := strings.ToLower(string(data))
	if strings.Contains(kernel, "microsoft") || strings.Contains(kernel, "wsl") {
		return "yes"
	}
	return "no"
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func formatSetupStatus(status setupStatus) string {
	var report strings.Builder
	fmt.Fprintln(&report, "ChainRisk Lens Setup Status")
	fmt.Fprintf(&report, "OS: %s\n", status.goos)
	fmt.Fprintf(&report, "CPU architecture: %s\n", status.goarch)
	fmt.Fprintf(&report, "WSL: %s\n", status.wsl)
	fmt.Fprintln(&report, "Core analysis: ready (no Ollama, model, or network required)")
	fmt.Fprintln(&report, "AI investigation: optional")

	if status.configurationError != "" {
		fmt.Fprintf(&report, "Ollama configuration: invalid (%s)\n", status.configurationError)
		fmt.Fprintf(&report, "Ollama executable: %s\n", status.executable)
		fmt.Fprintf(&report, "Ollama API: %s\n", status.api)
		fmt.Fprintf(&report, "Configured model: %s\n", status.model)
		return report.String()
	}

	endpointType := "local"
	if status.remote {
		endpointType = "remote"
	}
	fmt.Fprintf(&report, "Ollama endpoint: %s (%s)\n", status.ollamaURL, endpointType)
	fmt.Fprintf(&report, "Ollama executable: %s\n", status.executable)
	fmt.Fprintf(&report, "Ollama API: %s\n", status.api)
	fmt.Fprintf(&report, "Configured model: %s\n", status.model)
	if status.model == "missing" {
		if status.remote {
			fmt.Fprintf(&report, "To add it on the Ollama host, run manually: %s\n", status.modelPullCommand)
		} else {
			fmt.Fprintf(&report, "To add it, run manually: %s\n", status.modelPullCommand)
		}
	}
	return report.String()
}
