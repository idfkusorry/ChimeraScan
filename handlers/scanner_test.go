package handlers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidURL_ValidCases(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"HTTPS", "https://example.com"},
		{"HTTP", "http://example.com"},
		{"With path", "https://example.com/api/v1"},
		{"With query", "https://example.com?param=value"},
		{"With port", "https://example.com:8080"},
		{"Subdomain", "https://api.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidURL(tt.url)
			assert.True(t, result, "URL should be valid: %s", tt.url)
		})
	}
}

func TestIsValidURL_InvalidCases(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{"Empty", "", false},
		{"No scheme", "example.com", false},
		{"FTP scheme", "ftp://example.com", false},
		{"Localhost", "http://localhost", true},       // Функция возвращает true с warning
		{"Localhost IP", "http://127.0.0.1", true},    // Тоже true
		{"Local network", "http://192.168.1.1", true}, // И это true
		{"Private network", "http://10.0.0.1", true},  // Тоже true
		{"With space", "http://example.com/path with space", false},
		{"With $", "http://example.com/$PATH", false},
		{"Too long", "http://" + strings.Repeat("a", 2000), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidURL(tt.url)
			assert.Equal(t, tt.expected, result, "URL: %s, expected: %v, got: %v", tt.url, tt.expected, result)
		})
	}
}

func TestParseNucleiOutput(t *testing.T) {
	testOutput := `{"template-id":"CVE-2021-12345","info":{"name":"Test Vulnerability","severity":"high"},"host":"example.com"}
{"template-id":"CVE-2021-67890","info":{"name":"Another Vuln","severity":"medium"},"host":"test.com"}`

	results := parseNucleiOutput([]byte(testOutput))

	assert.Len(t, results, 2, "Should parse 2 vulnerabilities")
	assert.Equal(t, "CVE-2021-12345", results[0].TemplateID, "First template ID should match")
	assert.Equal(t, "high", results[0].Info.Severity, "First severity should match")
	assert.Equal(t, "example.com", results[0].Host, "First host should match")
	assert.Equal(t, "CVE-2021-67890", results[1].TemplateID, "Second template ID should match")
}

func TestParseNucleiOutputEmpty(t *testing.T) {
	results := parseNucleiOutput([]byte(""))
	assert.Empty(t, results, "Should return empty slice for empty input")
}

func TestParseNucleiOutputNewlines(t *testing.T) {
	results := parseNucleiOutput([]byte("\n\n\n"))
	assert.Empty(t, results, "Should return empty slice for newlines only")
}

func TestParseNucleiOutputInvalid(t *testing.T) {
	results := parseNucleiOutput([]byte("{invalid json}"))
	assert.Empty(t, results, "Should return empty slice for invalid JSON")
}

func TestParseNucleiOutputMalformed(t *testing.T) {
	input := `{"valid": "json"}
	not json
	{"another": "valid"}`

	results := parseNucleiOutput([]byte(input))
	assert.Len(t, results, 2, "Should parse only valid JSON lines")
}

func TestCalculateSeverityStats(t *testing.T) {
	results := []NucleiResult{
		{SeverityAI: "high"},
		{SeverityAI: "high"},
		{SeverityAI: "medium"},
		{SeverityAI: "low"},
		{SeverityAI: "info"},
		{SeverityAI: "medium"},
		{SeverityAI: "high"},
	}

	stats := calculateSeverityStats(results)

	assert.Equal(t, 3, stats["high"], "Should have 3 high severity")
	assert.Equal(t, 2, stats["medium"], "Should have 2 medium severity")
	assert.Equal(t, 1, stats["low"], "Should have 1 low severity")
	assert.Equal(t, 1, stats["info"], "Should have 1 info severity")
	assert.Equal(t, 7, stats["high"]+stats["medium"]+stats["low"]+stats["info"], "Total should be 7")
}

func TestCalculateSeverityStatsEmpty(t *testing.T) {
	results := []NucleiResult{}
	stats := calculateSeverityStats(results)

	expected := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0}
	assert.Equal(t, expected, stats, "Should return zero stats for empty input")
}

func TestCalculateSeverityStatsOnlyHigh(t *testing.T) {
	results := []NucleiResult{
		{SeverityAI: "high"},
		{SeverityAI: "high"},
		{SeverityAI: "high"},
	}

	stats := calculateSeverityStats(results)

	assert.Equal(t, 3, stats["high"], "Should count 3 high")
	assert.Equal(t, 0, stats["medium"], "Medium should be 0")
	assert.Equal(t, 0, stats["low"], "Low should be 0")
	assert.Equal(t, 0, stats["info"], "Info should be 0")
}

func TestCalculateSeverityStatsMixed(t *testing.T) {
	results := []NucleiResult{
		{SeverityAI: "info"},
		{SeverityAI: "low"},
		{SeverityAI: "medium"},
		{SeverityAI: "high"},
		{SeverityAI: "info"},
	}

	stats := calculateSeverityStats(results)

	assert.Equal(t, 2, stats["info"], "Should have 2 info")
	assert.Equal(t, 1, stats["low"], "Should have 1 low")
	assert.Equal(t, 1, stats["medium"], "Should have 1 medium")
	assert.Equal(t, 1, stats["high"], "Should have 1 high")
}
