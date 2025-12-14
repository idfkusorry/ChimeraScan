package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID         uuid.UUID `json:"id" db:"id"`
	ProviderID string    `json:"provider_id" db:"provider_id"`
	Email      string    `json:"email" db:"email"`
	Username   string    `json:"username" db:"username"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

type Project struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	UserID      uuid.UUID `json:"user_id" db:"user_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type Scan struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	TargetURL       string     `json:"target_url" db:"target_url"`
	Status          string     `json:"status" db:"status"`
	ProjectID       *uuid.UUID `json:"project_id" db:"project_id"`
	StartedAt       *time.Time `json:"started_at" db:"started_at"`
	FinishedAt      *time.Time `json:"finished_at" db:"finished_at"`
	RawNucleiOutput string     `json:"raw_nuclei_output" db:"raw_nuclei_output"`
	ReportJSONPath  string     `json:"report_json_path" db:"report_json_path"`
	ReportPDFPath   string     `json:"report_pdf_path" db:"report_pdf_path"`
	ReportHTMLPath  string     `json:"report_html_path" db:"report_html_path"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
}

type Vulnerability struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	ScanID           uuid.UUID  `json:"scan_id" db:"scan_id"`
	TemplateID       string     `json:"template_id" db:"template_id"`
	Name             string     `json:"name" db:"name"`
	Severity         string     `json:"severity" db:"severity"`
	SeverityAI       string     `json:"severity_ai" db:"severity_ai"`
	Description      string     `json:"description" db:"description"`
	DescriptionRu    string     `json:"description_ru" db:"description_ru"`
	Reference        []byte     `json:"reference" db:"reference"`           // JSONB stored as []byte
	Tags             []byte     `json:"tags" db:"tags"`                     // JSONB stored as []byte
	Classification   []byte     `json:"classification" db:"classification"` // JSONB stored as []byte
	Host             string     `json:"host" db:"host"`
	MatchedAt        string     `json:"matched_at" db:"matched_at"`
	IP               string     `json:"ip" db:"ip"`
	Timestamp        *time.Time `json:"timestamp" db:"timestamp"`
	CurlCommand      string     `json:"curl_command" db:"curl_command"`
	Request          string     `json:"request" db:"request"`
	Response         string     `json:"response" db:"response"`
	Metadata         []byte     `json:"metadata" db:"metadata"` // JSONB stored as []byte
	RecommendationAI string     `json:"recommendation_ai" db:"recommendation_ai"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
}
