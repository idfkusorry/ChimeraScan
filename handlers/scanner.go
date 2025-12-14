package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"chimerascan/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jung-kurt/gofpdf"
)

type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Reference      []string `json:"reference"`
		Tags           []string `json:"tags"`
		Classification struct {
			CveID []string `json:"cve-id"`
			CweID []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	Host             string                 `json:"host"`
	MatchedAt        string                 `json:"matched-at"`
	IP               string                 `json:"ip"`
	Timestamp        string                 `json:"timestamp"`
	CurlCommand      string                 `json:"curl-command"`
	Request          string                 `json:"request"`
	Response         string                 `json:"response"`
	Metadata         map[string]interface{} `json:"metadata"`
	SeverityAI       string                 `json:"severity_ai"`
	DescriptionRU    string                 `json:"description_ru"`
	RecommendationAI string                 `json:"recommendation_ai"`
}

type ScanReport struct {
	TargetURL     string         `json:"target_url"`
	ScanTime      string         `json:"scan_time"`
	Findings      []NucleiResult `json:"findings"`
	TotalCount    int            `json:"total_count"`
	SeverityStats map[string]int `json:"severity_stats"`
}

var (
	activeScans = make(map[uuid.UUID]*exec.Cmd)
)

// Валидация ссылки
func isValidURL(urlStr string) bool {
	if len(urlStr) > 2000 || len(urlStr) == 0 {
		return false
	}

	if !strings.HasPrefix(strings.ToLower(urlStr), "http://") &&
		!strings.HasPrefix(strings.ToLower(urlStr), "https://") {
		return false
	}

	dangerousChars := []string{"`", "$", "(", ")", "{", "}", "[", "]", "|", ";", "&", "<", ">", " "}
	for _, char := range dangerousChars {
		if strings.Contains(urlStr, char) {
			return false
		}
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	if u.Host == "" {
		return false
	}

	if strings.Contains(u.Host, "..") {
		return false
	}

	localHosts := []string{"localhost", "127.0.0.1", "0.0.0.0", "::1", "192.168.", "10.", "172.16."}
	hostLower := strings.ToLower(u.Host)
	for _, localHost := range localHosts {
		if strings.HasPrefix(hostLower, localHost) {
			log.Printf("Warning: Scanning local host %s", u.Host)
			break
		}
	}

	return true
}

// Запуск сканирования
func runNucleiScan(scanID uuid.UUID, targetURL string) {
	if !isValidURL(targetURL) {
		log.Printf("Invalid target URL format: %s", targetURL)
		updateScanStatus(scanID, "Failed")
		return
	}

	log.Printf("Starting Nuclei scan for %s (ID: %s)", targetURL, scanID)

	updateScanStatus(scanID, "In Progress")

	cmd := exec.Command("docker", "run", "--rm",
		"projectdiscovery/nuclei:latest",
		"-u", targetURL,
		"-j",
		"-silent",
		"-no-interactsh",
		"-rate-limit", "50",
		"-timeout", "90")

	activeScans[scanID] = cmd

	output, err := cmd.Output()

	delete(activeScans, scanID)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("Nuclei exited with code: %d", exitErr.ExitCode())
		} else {
			log.Printf("Nuclei scan error: %v", err)
			updateScanStatus(scanID, "Failed")
			return
		}
	}

	results := parseNucleiOutput(output)

	if len(results) > 0 {
		log.Println("AI анализ уязвимостей...")
		for i := range results {
			log.Printf("Анализ %d/%d...\n", i+1, len(results))

			results[i].SeverityAI = getSeverityFromAI(results[i])

			if results[i].Info.Description != "" {
				results[i].DescriptionRU = translateDescriptionFromAI(results[i].Info.Description)
			}

			results[i].RecommendationAI = getRecommendationFromAI(results[i])
		}
	}

	rawOutput, _ := json.Marshal(results)

	saveVulnerabilities(scanID, results)

	reportPaths := generateReports(scanID, targetURL, results)

	updateScanCompletion(scanID, rawOutput, reportPaths)

	log.Printf("Nuclei scan completed for %s. Found %d vulnerabilities", targetURL, len(results))
}

// Парсинг JSON вывода
func parseNucleiOutput(output []byte) []NucleiResult {
	var results []NucleiResult
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			results = append(results, result)
		}
	}

	return results
}

// Оценка уровня риска от ИИ
func getSeverityFromAI(vuln NucleiResult) string {
	prompt := fmt.Sprintf(`Оцени уровень риска уязвимости. Только один из: info, low, medium, high.
Правила:
- info: только если НЕТ необходимости устранять, совершенно нет угрозы
- low: если есть МАЛЕЙШИЙ шанс взлома или минимальный риск
- medium: средний риск, требует внимания
- high: высокий риск, срочное исправление

Уязвимость: %s
Описание: %s
Расположение: %s
Хост: %s
CURL команда: %s
Запрос: %s
Тэги: %s
Классификация CVE: %v
Классификация CWE: %v

Ответ только одним словом:`,
		vuln.Info.Name,
		vuln.Info.Description,
		vuln.MatchedAt,
		vuln.Host,
		vuln.CurlCommand,
		vuln.Request,
		strings.Join(vuln.Info.Tags, ", "),
		strings.Join(vuln.Info.Classification.CveID, ", "),
		strings.Join(vuln.Info.Classification.CweID, ", "))

	result := callOllama(prompt)
	result = strings.TrimSpace(result)
	result = strings.ToLower(result)

	switch result {
	case "info", "low", "medium", "high":
		return result
	default:
		return "medium"
	}
}

// Перевод описания шаблона от ИИ
func translateDescriptionFromAI(description string) string {
	if description == "" {
		return ""
	}
	prompt := fmt.Sprintf(`Переведи на русский язык кратко и технически точно, без вводных слов: "%s"`, description)

	result := callOllama(prompt)
	return strings.TrimSpace(result)
}

// Генерация рекомендаций от ИИ
func getRecommendationFromAI(vuln NucleiResult) string {
	prompt := fmt.Sprintf(`Дай очень краткие рекомендации на русском языке по устранению уязвимости.
Без вводных слов, сразу как устранить. Только практические действия.

Уязвимость: %s
Описание: %s
Уровень риска: %s

Рекомендации:`,
		vuln.Info.Name,
		vuln.Info.Description,
		vuln.SeverityAI)

	result := callOllama(prompt)
	return strings.TrimSpace(result)
}

// Вызов ollama
func callOllama(prompt string) string {
	cmd := exec.Command("ollama", "run", "phi:2.7b", prompt)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Sprintf("Ошибка AI: %v", err)
	}
	return string(output)
}

// Сохранение уязвимостей в БД
func saveVulnerabilities(scanID uuid.UUID, results []NucleiResult) {
	for _, result := range results {
		vulnID := uuid.New()

		referenceJSON, _ := json.Marshal(result.Info.Reference)
		tagsJSON, _ := json.Marshal(result.Info.Tags)
		classificationJSON, _ := json.Marshal(result.Info.Classification)
		metadataJSON, _ := json.Marshal(result.Metadata)

		query := `
			INSERT INTO vulnerabilities (
				id, scan_id, template_id, name, severity, severity_ai, description, 
				description_ru, reference, tags, classification, host, matched_at, ip,
				timestamp, curl_command, request, response, metadata, recommendation_ai
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		`

		var timestamp *time.Time
		if result.Timestamp != "" {
			if ts, err := time.Parse(time.RFC3339, result.Timestamp); err == nil {
				timestamp = &ts
			}
		}

		_, err := database.DB.Exec(query,
			vulnID, scanID, result.TemplateID, result.Info.Name,
			strings.ToLower(result.Info.Severity), result.SeverityAI, result.Info.Description,
			result.DescriptionRU, string(referenceJSON), string(tagsJSON), string(classificationJSON),
			result.Host, result.MatchedAt, result.IP, timestamp,
			result.CurlCommand, result.Request, result.Response, string(metadataJSON), result.RecommendationAI,
		)

		if err != nil {
			log.Printf("Failed to save vulnerability: %v", err)
		}
	}
}

// Генерация отчетов
func generateReports(scanID uuid.UUID, targetURL string, results []NucleiResult) map[string]string {
	timestamp := time.Now().Unix()
	reportsDir := "reports"

	os.MkdirAll(reportsDir, 0755)

	reportPaths := map[string]string{}

	stats := calculateSeverityStats(results)

	report := ScanReport{
		TargetURL:     targetURL,
		ScanTime:      time.Now().Format("2006-01-02 15:04:05"),
		Findings:      results,
		TotalCount:    len(results),
		SeverityStats: stats,
	}

	jsonPath := filepath.Join(reportsDir, fmt.Sprintf("chimerascan_report_%s_%d.json", scanID.String(), timestamp))
	saveJSONReport(report, jsonPath)
	reportPaths["json"] = jsonPath

	pdfPath := filepath.Join(reportsDir, fmt.Sprintf("chimerascan_report_%s_%d.pdf", scanID.String(), timestamp))
	savePDFReport(report, pdfPath)
	reportPaths["pdf"] = pdfPath

	htmlPath := filepath.Join(reportsDir, fmt.Sprintf("chimerascan_report_%s_%d.html", scanID.String(), timestamp))
	saveHTMLReport(report, htmlPath)
	reportPaths["html"] = htmlPath

	return reportPaths
}

// Подсчет уязвимостей по уровням риска для отчетов
func calculateSeverityStats(results []NucleiResult) map[string]int {
	stats := map[string]int{
		"info":   0,
		"low":    0,
		"medium": 0,
		"high":   0,
	}

	for _, result := range results {
		stats[result.SeverityAI]++
	}
	return stats
}

// Сохранения отчета JSON
func saveJSONReport(report ScanReport, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Ошибка создания JSON файла: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(report); err != nil {
		log.Printf("Ошибка кодирования JSON: %v", err)
		return
	}
	log.Printf("JSON отчет сохранен: %s", filename)
}

// Сохранения отчета PDF
func savePDFReport(report ScanReport, filename string) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	logoX := 10.0
	logoY := 10.0
	logoWidth := 20.0
	logoHeight := 20.0

	possibleLogoPaths := []string{
		"static/logo_black.png",
		"logo_black.png",
		"static/images/logo_black.png",
		"reports/logo_black.png",
		"./static/logo_black.png",
		"./logo_black.png",
	}

	var logoPath string
	for _, path := range possibleLogoPaths {
		if _, err := os.Stat(path); err == nil {
			logoPath = path
			break
		}
	}

	if logoPath != "" {
		pdf.Image(logoPath, logoX, logoY, logoWidth, logoHeight, false, "", 0, "")
	}

	textStartX := logoX + logoWidth + 10.0
	textWidth := 190.0 - textStartX

	pdf.SetFont("Arial", "B", 16)
	pdf.SetXY(textStartX, logoY+5)
	pdf.Cell(textWidth, 10, "ChimeraScan: DAST Scanner for Web Applications")

	mainTextX := logoX
	mainTextWidth := 180.0

	pdf.SetY(logoY + logoHeight + 10)

	pdf.SetFont("Arial", "B", 12)
	pdf.SetX(mainTextX)
	pdf.Cell(40, 10, "Scan Information:")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 10)
	pdf.SetX(mainTextX)
	pdf.Cell(40, 8, fmt.Sprintf("Target URL: %s", report.TargetURL))
	pdf.Ln(6)
	pdf.SetX(mainTextX)
	pdf.Cell(40, 8, fmt.Sprintf("Scan Time: %s", report.ScanTime))
	pdf.Ln(6)
	pdf.SetX(mainTextX)
	pdf.Cell(40, 8, fmt.Sprintf("Total Findings: %d", report.TotalCount))
	pdf.Ln(10)

	pdf.SetFont("Arial", "B", 12)
	pdf.SetX(mainTextX)
	pdf.Cell(40, 10, "Severity Statistics:")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 10)
	pdf.SetX(mainTextX)
	pdf.Cell(40, 8, fmt.Sprintf("Info:    %d", report.SeverityStats["info"]))
	pdf.Ln(6)
	pdf.SetX(mainTextX)
	pdf.Cell(40, 8, fmt.Sprintf("Low:     %d", report.SeverityStats["low"]))
	pdf.Ln(6)
	pdf.SetX(mainTextX)
	pdf.Cell(40, 8, fmt.Sprintf("Medium:  %d", report.SeverityStats["medium"]))
	pdf.Ln(6)
	pdf.SetX(mainTextX)
	pdf.Cell(40, 8, fmt.Sprintf("High:    %d", report.SeverityStats["high"]))
	pdf.Ln(15)

	if report.TotalCount > 0 {
		pdf.SetFont("Arial", "B", 14)
		pdf.SetX(mainTextX)
		pdf.Cell(40, 10, "Detailed Findings:")
		pdf.Ln(12)

		for i, finding := range report.Findings {
			if pdf.GetY() > 250 {
				pdf.AddPage()
				if logoPath != "" {
					pdf.Image(logoPath, logoX, logoY, logoWidth, logoHeight, false, "", 0, "")
				}
				pdf.SetY(logoY + logoHeight + 20)
			}

			pdf.SetFont("Arial", "B", 12)
			pdf.SetX(mainTextX)
			pdf.Cell(mainTextWidth, 10, fmt.Sprintf("%d. %s", i+1, finding.Info.Name))
			pdf.Ln(8)

			pdf.SetFont("Arial", "B", 10)
			pdf.SetX(mainTextX)
			pdf.Cell(40, 8, "Template ID:")
			pdf.SetFont("Arial", "", 10)
			pdf.Cell(mainTextWidth-40, 8, finding.TemplateID)
			pdf.Ln(6)

			pdf.SetFont("Arial", "B", 10)
			pdf.SetX(mainTextX)
			pdf.Cell(40, 8, "Severity:")
			pdf.SetFont("Arial", "", 10)
			pdf.Cell(mainTextWidth-40, 8, finding.SeverityAI)
			pdf.Ln(6)

			pdf.SetFont("Arial", "B", 10)
			pdf.SetX(mainTextX)
			pdf.Cell(40, 8, "Host:")
			pdf.SetFont("Arial", "", 10)
			pdf.Cell(mainTextWidth-40, 8, finding.Host)
			pdf.Ln(6)

			pdf.SetFont("Arial", "B", 10)
			pdf.SetX(mainTextX)
			pdf.Cell(40, 8, "Matched At:")
			pdf.SetFont("Arial", "", 10)
			pdf.Cell(mainTextWidth-40, 8, finding.MatchedAt)
			pdf.Ln(6)

			pdf.SetFont("Arial", "B", 10)
			pdf.SetX(mainTextX)
			pdf.Cell(40, 8, "IP:")
			pdf.SetFont("Arial", "", 10)
			pdf.Cell(mainTextWidth-40, 8, finding.IP)
			pdf.Ln(6)

			if finding.Timestamp != "" {
				pdf.SetFont("Arial", "B", 10)
				pdf.SetX(mainTextX)
				pdf.Cell(40, 8, "Timestamp:")
				pdf.SetFont("Arial", "", 10)
				pdf.Cell(mainTextWidth-40, 8, finding.Timestamp)
				pdf.Ln(6)
			}

			if finding.Info.Description != "" {
				pdf.SetFont("Arial", "B", 10)
				pdf.SetX(mainTextX)
				pdf.Cell(40, 8, "Description:")
				pdf.Ln(6)
				pdf.SetFont("Arial", "", 10)
				pdf.SetX(mainTextX)
				pdf.MultiCell(mainTextWidth, 6, finding.Info.Description, "", "", false)
			}

			if len(finding.Info.Reference) > 0 {
				pdf.SetFont("Arial", "B", 10)
				pdf.SetX(mainTextX)
				pdf.Cell(40, 8, "References:")
				pdf.Ln(6)
				pdf.SetFont("Arial", "", 10)
				for _, ref := range finding.Info.Reference {
					pdf.SetX(mainTextX + 5)
					pdf.Cell(mainTextWidth-5, 6, " "+ref)
					pdf.Ln(6)
				}
			}

			if len(finding.Info.Tags) > 0 {
				pdf.SetFont("Arial", "B", 10)
				pdf.SetX(mainTextX)
				pdf.Cell(40, 8, "Tags:")
				pdf.Ln(6)
				pdf.SetFont("Arial", "", 10)
				tagsStr := strings.Join(finding.Info.Tags, ", ")
				pdf.SetX(mainTextX)
				pdf.MultiCell(mainTextWidth, 6, tagsStr, "", "", false)
			}

			if len(finding.Info.Classification.CveID) > 0 || len(finding.Info.Classification.CweID) > 0 {
				pdf.SetFont("Arial", "B", 10)
				pdf.SetX(mainTextX)
				pdf.Cell(40, 8, "Classification:")
				pdf.Ln(6)
				pdf.SetFont("Arial", "", 10)

				if len(finding.Info.Classification.CveID) > 0 {
					pdf.SetX(mainTextX)
					pdf.Cell(10, 6, "CVE:")
					cves := strings.Join(finding.Info.Classification.CveID, ", ")
					pdf.Cell(mainTextWidth-10, 6, " "+cves)
					pdf.Ln(6)
				}

				if len(finding.Info.Classification.CweID) > 0 {
					pdf.SetX(mainTextX)
					pdf.Cell(10, 6, "CWE:")
					cwes := strings.Join(finding.Info.Classification.CweID, ", ")
					pdf.Cell(mainTextWidth-10, 6, " "+cwes)
					pdf.Ln(6)
				}
			}

			if finding.CurlCommand != "" {
				pdf.SetFont("Arial", "B", 10)
				pdf.SetX(mainTextX)
				pdf.Cell(40, 8, "Curl Command:")
				pdf.Ln(6)
				pdf.SetFont("Courier", "", 8)
				pdf.SetX(mainTextX)
				pdf.MultiCell(mainTextWidth, 5, finding.CurlCommand, "", "", false)
				pdf.SetFont("Arial", "", 10)
			}

			if finding.Request != "" {
				pdf.SetFont("Arial", "B", 10)
				pdf.SetX(mainTextX)
				pdf.Cell(40, 8, "Request:")
				pdf.Ln(6)
				pdf.SetFont("Courier", "", 8)
				pdf.SetX(mainTextX)
				pdf.MultiCell(mainTextWidth, 5, finding.Request, "", "", false)
				pdf.SetFont("Arial", "", 10)
			}

			pdf.Ln(5)
			pdf.SetDrawColor(200, 200, 200)
			pdf.SetX(mainTextX)
			pdf.Line(mainTextX, pdf.GetY(), mainTextX+mainTextWidth, pdf.GetY())
			pdf.Ln(10)
		}
	} else {
		pdf.SetFont("Arial", "B", 12)
		pdf.SetX(mainTextX)
		pdf.Cell(40, 10, "No vulnerabilities found.")
		pdf.Ln(10)
	}

	pdf.SetY(-20)
	pdf.SetFont("Arial", "I", 8)
	pdf.CellFormat(0, 10, fmt.Sprintf("Generated by ChimeraScan on %s", time.Now().Format("2006-01-02 15:04:05")), "", 0, "C", false, 0, "")

	err := pdf.OutputFileAndClose(filename)
	if err != nil {
		log.Printf("Error creating PDF: %v", err)
		return
	}
	log.Printf("PDF report saved: %s", filename)
}

// Сохранения отчета HTML
func saveHTMLReport(report ScanReport, filename string) {
	const htmlTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>ChimeraScan: DAST-сканер для веб-приложений</title>
    <style>
        :root {
            --color-bg-primary: #0a0a15;
            --color-bg-secondary: rgba(20, 15, 35, 0.8);
            --color-surface: rgba(255, 255, 255, 0.07);
            --color-surface-hover: rgba(255, 255, 255, 0.12);
            --color-accent: #7c4dff;
            --color-accent-glow: rgba(124, 77, 255, 0.6);
            --color-accent-dark: #5a36cc;
            --color-text-primary: #ffffff;
            --color-text-secondary: #b0b0d0;
            --color-text-muted: #8888aa;
            --color-success: #00e676;
            --color-warning: #ffaa00;
            --color-error: #ff5252;
            --color-info: #00b0ff;
            --border-radius-sm: 8px;
            --border-radius-md: 12px;
            --border-radius-lg: 16px;
        }
        
        body { 
            font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif; 
            margin: 0;
            padding: 0;
            background-color: var(--color-bg-primary);
            color: var(--color-text-primary);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header-container {
            display: flex;
            align-items: center;
            margin: 20px 0 30px 0;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(124, 77, 255, 0.3);
        }
        
        .header-logo {
            flex-shrink: 0;
            margin-right: 20px;
        }
        
        .header-logo img {
            width: 60px;
            height: 60px;
            filter: drop-shadow(0 0 15px var(--color-accent-glow));
        }
        
        .header-title {
            flex-grow: 1;
        }
        
        .header-title h1 {
            color: var(--color-accent);
            margin: 0 0 5px 0;
            font-size: 1.6rem;
        }
        
        .header-title p {
            color: var(--color-text-secondary);
            margin: 0;
            font-size: 0.9rem;
        }
        
        .report-header {
            background: var(--color-surface);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: var(--border-radius-lg);
            margin-bottom: 25px;
            border: 1px solid rgba(124, 77, 255, 0.2);
        }
        
        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .info-item {
            background: rgba(255, 255, 255, 0.03);
            padding: 12px 15px;
            border-radius: var(--border-radius-md);
            border: 1px solid rgba(124, 77, 255, 0.1);
        }
        
        .info-item strong {
            color: var(--color-accent);
            display: block;
            margin-bottom: 5px;
            font-size: 0.9rem;
        }
        
        .stats-section {
            background: var(--color-surface);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: var(--border-radius-lg);
            margin: 25px 0;
            border: 1px solid rgba(124, 77, 255, 0.2);
        }
        
        .stats-section h3 {
            color: var(--color-accent);
            margin: 0 0 20px 0;
            text-align: center;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        .stat-item {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px;
            border-radius: var(--border-radius-md);
            text-align: center;
            border: 1px solid rgba(124, 77, 255, 0.1);
        }
        
        .vulnerability {
            background: var(--color-surface);
            backdrop-filter: blur(10px);
            margin: 20px 0;
            padding: 25px;
            border-radius: var(--border-radius-lg);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
        }
        
        .vulnerability:hover {
            border-color: var(--color-accent);
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        .vulnerability.info { border-left: 4px solid var(--color-info); }
        .vulnerability.low { border-left: 4px solid var(--color-success); }
        .vulnerability.medium { border-left: 4px solid var(--color-warning); }
        .vulnerability.high { border-left: 4px solid var(--color-error); }
        
        .severity {
            font-weight: bold;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            display: inline-block;
            margin: 0 5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .info-sev { background: var(--color-info); color: white; }
        .low-sev { background: var(--color-success); color: black; }
        .medium-sev { background: var(--color-warning); color: white; }
        .high-sev { background: var(--color-error); color: white; }
        
        .section {
            margin: 20px 0;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .section:last-child {
            border-bottom: none;
        }
        
        .vulnerability h3 {
            color: var(--color-text-primary);
            margin: 0 0 20px 0;
            font-size: 1.3rem;
        }
        
        .code {
            background: rgba(0, 0, 0, 0.3);
            padding: 15px;
            border-radius: var(--border-radius-md);
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            margin: 10px 0;
            border: 1px solid rgba(124, 77, 255, 0.2);
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .recommendation {
            background: rgba(255, 168, 0, 0.1);
            padding: 20px;
            border-radius: var(--border-radius-md);
            border-left: 4px solid var(--color-warning);
            margin-top: 20px;
        }
        
        .recommendation strong {
            color: var(--color-warning);
            display: block;
            margin-bottom: 10px;
            font-size: 1.1rem;
        }
        
        h2 {
            color: var(--color-accent);
            margin: 30px 0 20px 0;
            text-align: center;
            font-size: 1.6rem;
        }
        
        ul {
            padding-left: 20px;
            margin: 10px 0;
        }
        
        li {
            margin: 5px 0;
            color: var(--color-text-secondary);
        }
		
		ol {
			padding-left: 20px;
			margin: 10px 0;
		}
        
        p {
            margin: 10px 0;
            color: var(--color-text-secondary);
        }
        
        strong {
            color: var(--color-text-primary);
        }
        
        @media print {
            body {
                background: white;
                color: black;
            }
            
            .vulnerability,
            .report-header,
            .stats-section {
                box-shadow: none;
                border: 1px solid #ddd;
            }
            
            .header-logo img {
                filter: none;
            }
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            
            .header-container {
                flex-direction: column;
                text-align: center;
            }
            
            .header-logo {
                margin-right: 0;
                margin-bottom: 15px;
            }
			
			.header-logo img {
				width: 50px;
				height: 50px;
			}
            
            .report-header,
            .stats-section,
            .vulnerability {
                padding: 20px;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .header-info {
                grid-template-columns: 1fr;
            }
        }
    </style>  
</head>  
<<body>
    <div class="container">
        <div class="header-container">
            <div class="header-logo">
                <img src="/static/images/logo2.png" alt="ChimeraScan">
            </div>
            <div class="header-title">
                <h1>ChimeraScan: DAST-сканер для веб-приложений</h1>
                <p>Dynamic Application Security Testing Scanner</p>
            </div>
        </div>
        
        <div class="report-header">  
            <div class="header-info">
                <div class="info-item">
                    <strong>Целевой URL:</strong> {{.TargetURL}}
                </div>
                <div class="info-item">
                    <strong>Время сканирования:</strong> {{.ScanTime}}
                </div>
                <div class="info-item">
                    <strong>Общее количество найденных уязвимостей:</strong> {{.TotalCount}}
                </div>
            </div>
        </div>  

        <div class="stats-section">  
            <h3>Количество уязвимостей по уровням риска</h3>  
            <div class="stats-grid">
                <div class="stat-item">
                    <strong>Info</strong>
                    <div style="font-size: 1.5rem; color: var(--color-info); margin-top: 5px;">{{.SeverityStats.info}}</div>
                </div>
                <div class="stat-item">
                    <strong>Low</strong>
                    <div style="font-size: 1.5rem; color: var(--color-success); margin-top: 5px;">{{.SeverityStats.low}}</div>
                </div>
                <div class="stat-item">
                    <strong>Medium</strong>
                    <div style="font-size: 1.5rem; color: var(--color-warning); margin-top: 5px;">{{.SeverityStats.medium}}</div>
                </div>
                <div class="stat-item">
                    <strong>High</strong>
                    <div style="font-size: 1.5rem; color: var(--color-error); margin-top: 5px;">{{.SeverityStats.high}}</div>
                </div>
            </div>
        </div>  

        {{if .Findings}}  
        <h2>Найденные уязвимости</h2>  
        {{range $index, $finding := .Findings}}  
        <div class="vulnerability {{$finding.SeverityAI}}">  
            <h3>{{add $index 1}}: {{$finding.Info.Name}}</h3>  
            
            <div class="section">
                <p><strong>ID шаблона:</strong> {{$finding.TemplateID}}</p>  
                <p><strong>Уровень риска:</strong> <span class="severity {{$finding.SeverityAI}}-sev">{{$finding.SeverityAI}}</span></p>  
                <p><strong>Хост:</strong> {{$finding.Host}}</p>  
                <p><strong>Расположение:</strong> {{$finding.MatchedAt}}</p>  
            </div>
            
            <div class="section">
                {{if $finding.IP}}<p><strong>IP:</strong> {{$finding.IP}}</p>{{end}}  
                {{if $finding.Timestamp}}<p><strong>Отметка времени:</strong> {{$finding.Timestamp}}</p>{{end}}  
                {{if $finding.DescriptionRU}}<p><strong>Описание:</strong> {{$finding.DescriptionRU}}</p>{{end}}  
            </div>
            
            {{if $finding.Info.Reference}}
            <div class="section">
                <p><strong>Ссылки:</strong></p>
                <ul>
                    {{range $finding.Info.Reference}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
            </div>
            {{end}}
            
            {{if $finding.Info.Tags}}
            <div class="section">
                <p><strong>Теги:</strong> {{join $finding.Info.Tags ", "}}</p>
            </div>
            {{end}}
            
            {{if or $finding.Info.Classification.CveID $finding.Info.Classification.CweID}}
            <div class="section">
                <p><strong>Классификация:</strong></p>
                {{if $finding.Info.Classification.CveID}}
                <p><strong>CVE:</strong> {{join $finding.Info.Classification.CveID ", "}}</p>
                {{end}}
                {{if $finding.Info.Classification.CweID}}
                <p><strong>CWE:</strong> {{join $finding.Info.Classification.CweID ", "}}</p>
                {{end}}
            </div>
            {{end}}
            
            {{if $finding.CurlCommand}}
            <div class="section">
                <p><strong>CURL команда:</strong></p>
                <div class="code">{{$finding.CurlCommand}}</div>
            </div>
            {{end}}
            
            {{if $finding.Request}}
            <div class="section">
                <p><strong>Запрос:</strong></p>
                <div class="code">{{$finding.Request}}</div>
            </div>
            {{end}}
            
            {{if $finding.RecommendationAI}}
            <div class="recommendation">
                <strong>Рекомендации по устранению:</strong>
                <p>{{$finding.RecommendationAI}}</p>
            </div>
            {{end}}
        </div>  
        {{end}}  
        {{else}}  
        <h2>Уязвимости не найдены.</h2>  
        {{end}}  
    </div>
</body>  
</html>`

	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
		"join": func(items []string, sep string) string {
			return strings.Join(items, sep)
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		log.Printf("Ошибка парсинга HTML шаблона: %v", err)
		return
	}

	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Ошибка создания HTML файла: %v", err)
		return
	}
	defer file.Close()

	if err := tmpl.Execute(file, report); err != nil {
		log.Printf("Ошибка выполнения HTML шаблона: %v", err)
		return
	}
	log.Printf("HTML отчет сохранен: %s", filename)
}

// Обновление статуса
func updateScanStatus(scanID uuid.UUID, status string) {
	var query string
	if status == "In Progress" {
		now := time.Now()
		query = `UPDATE scans SET status = $1, started_at = $2 WHERE id = $3`
		_, err := database.DB.Exec(query, status, now, scanID)
		if err != nil {
			log.Printf("Failed to update scan status: %v", err)
		}
	} else {
		query = `UPDATE scans SET status = $1 WHERE id = $2`
		_, err := database.DB.Exec(query, status, scanID)
		if err != nil {
			log.Printf("Failed to update scan status: %v", err)
		}
	}
}

// Обновление записи сканирования после завершения
func updateScanCompletion(scanID uuid.UUID, rawOutput []byte, reportPaths map[string]string) {
	now := time.Now()

	query := `
		UPDATE scans 
		SET status = $1, finished_at = $2, raw_nuclei_output = $3,
		    report_json_path = $4, report_pdf_path = $5, report_html_path = $6
		WHERE id = $7
	`

	_, err := database.DB.Exec(query,
		"Completed", now, string(rawOutput),
		reportPaths["json"], reportPaths["pdf"], reportPaths["html"],
		scanID,
	)

	if err != nil {
		log.Printf("Failed to update scan completion: %v", err)
	}
}

// Функция остановки сканирования
func StopScan(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	scanIDStr := c.Param("id")

	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	var scanUserID uuid.UUID
	err = database.DB.QueryRow("SELECT user_id FROM scans WHERE id = $1", scanID).Scan(&scanUserID)
	if err != nil || scanUserID != userID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	if cmd, exists := activeScans[scanID]; exists {
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("Failed to kill scan process: %v", err)
		}
		delete(activeScans, scanID)
	}

	updateScanStatus(scanID, "Canceled")

	c.JSON(http.StatusOK, gin.H{"message": "Scan stopped successfully"})
}

// Получение статуса
func GetScanStatus(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	scanID := c.Param("id")

	var scan struct {
		Status    string     `json:"status"`
		StartedAt *time.Time `json:"started_at"`
	}

	err := database.DB.QueryRow(`
		SELECT status, started_at 
		FROM scans 
		WHERE id = $1 AND user_id = $2
	`, scanID, userID).Scan(&scan.Status, &scan.StartedAt)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// Сохранение отчета
func DownloadReport(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	scanID := c.Param("id")
	format := c.Param("format")

	var filePath string
	var query string

	switch format {
	case "json":
		query = "SELECT report_json_path FROM scans WHERE id = $1 AND user_id = $2"
	case "pdf":
		query = "SELECT report_pdf_path FROM scans WHERE id = $1 AND user_id = $2"
	case "html":
		query = "SELECT report_html_path FROM scans WHERE id = $1 AND user_id = $2"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid format"})
		return
	}

	err := database.DB.QueryRow(query, scanID, userID).Scan(&filePath)
	if err != nil || filePath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Report not found"})
		return
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Report file not found"})
		return
	}

	c.File(filePath)
}
