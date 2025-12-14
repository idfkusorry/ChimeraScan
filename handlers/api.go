package handlers

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"chimerascan/database"
	"chimerascan/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CreateProject создает новый проект
func CreateProject(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)

	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	project := models.Project{
		ID:          uuid.New(),
		Name:        req.Name,
		Description: req.Description,
		UserID:      userID,
		CreatedAt:   time.Now(),
	}

	query := `INSERT INTO projects (id, name, description, user_id, created_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := database.DB.Exec(query, project.ID, project.Name, project.Description, project.UserID, project.CreatedAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create project"})
		return
	}

	c.JSON(http.StatusCreated, project)
}

// GetProjects возвращает список проектов пользователя
func GetProjects(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)

	rows, err := database.DB.Query(`
		SELECT id, name, description, created_at 
		FROM projects 
		WHERE user_id = $1 
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
		return
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		var project models.Project
		err := rows.Scan(&project.ID, &project.Name, &project.Description, &project.CreatedAt)
		if err != nil {
			continue
		}
		projects = append(projects, project)
	}

	c.JSON(http.StatusOK, projects)
}

// DeleteProject удаляет проект
func DeleteProject(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	projectID := c.Param("id")

	result, err := database.DB.Exec(`
		DELETE FROM projects 
		WHERE id = $1 AND user_id = $2
	`, projectID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete project"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Project deleted successfully"})
}

// UpdateProject обновляет проект
func UpdateProject(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	projectID := c.Param("id")

	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := database.DB.Exec(`
        UPDATE projects 
        SET name = $1, description = $2 
        WHERE id = $3 AND user_id = $4
    `, req.Name, req.Description, projectID, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update project"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Project updated successfully"})
}

// GetProjectsForScan возвращает проекты для выпадающего списка
func GetProjectsForScan(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	scanID := c.Param("id")

	rows, err := database.DB.Query(`
        SELECT id, name 
        FROM projects 
        WHERE user_id = $1 
        ORDER BY name
    `, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
		return
	}
	defer rows.Close()

	var projects []map[string]interface{}
	for rows.Next() {
		var project struct {
			ID   uuid.UUID `db:"id"`
			Name string    `db:"name"`
		}
		err := rows.Scan(&project.ID, &project.Name)
		if err != nil {
			continue
		}
		projects = append(projects, map[string]interface{}{
			"id":   project.ID.String(),
			"name": project.Name,
		})
	}

	var currentProjectID *string
	err = database.DB.QueryRow(`
        SELECT project_id::text 
        FROM scans 
        WHERE id = $1 AND user_id = $2
    `, scanID, userID).Scan(&currentProjectID)

	if err != nil && err != sql.ErrNoRows {
		log.Printf("Error getting current project: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"projects":           projects,
		"current_project_id": currentProjectID,
	})
}

// StartScan запускает сканирование
func StartScan(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)

	var req struct {
		TargetURL string `json:"target_url" binding:"required,url"`
		ProjectID string `json:"project_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scanID := uuid.New()
	now := time.Now()

	var projectID *uuid.UUID
	if req.ProjectID != "" {
		pid, err := uuid.Parse(req.ProjectID)
		if err == nil {
			projectID = &pid
		}
	}

	scan := models.Scan{
		ID:        scanID,
		TargetURL: req.TargetURL,
		Status:    "Queued",
		ProjectID: projectID,
		StartedAt: &now,
		UserID:    userID,
		CreatedAt: now,
	}

	query := `
		INSERT INTO scans (id, target_url, status, project_id, started_at, user_id, created_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := database.DB.Exec(query,
		scan.ID, scan.TargetURL, scan.Status, scan.ProjectID, scan.StartedAt, scan.UserID, scan.CreatedAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scan"})
		return
	}

	go runNucleiScan(scan.ID, req.TargetURL)

	c.JSON(http.StatusAccepted, gin.H{
		"scan_id": scanID,
		"message": "Scan started successfully",
		"status":  "Queued",
	})
}

// GetScans возвращает список сканирований пользователя
func GetScans(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)

	rows, err := database.DB.Query(`
		SELECT id, target_url, status, project_id, started_at, finished_at, created_at
		FROM scans 
		WHERE user_id = $1 
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scans"})
		return
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		var scan models.Scan
		err := rows.Scan(
			&scan.ID, &scan.TargetURL, &scan.Status, &scan.ProjectID,
			&scan.StartedAt, &scan.FinishedAt, &scan.CreatedAt,
		)
		if err != nil {
			continue
		}
		scans = append(scans, scan)
	}

	c.JSON(http.StatusOK, scans)
}

// AddScanToProject добавляет сканирование в проект
func AddScanToProject(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	scanID := c.Param("id")

	var req struct {
		ProjectID *string `json:"project_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var projectID *uuid.UUID
	if req.ProjectID != nil && *req.ProjectID != "" {
		pid, err := uuid.Parse(*req.ProjectID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
			return
		}

		var projectExists bool
		err = database.DB.QueryRow(`
            SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1 AND user_id = $2)
        `, pid, userID).Scan(&projectExists)

		if err != nil || !projectExists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Project not found"})
			return
		}

		projectID = &pid
	}

	_, err := database.DB.Exec(`
        UPDATE scans 
        SET project_id = $1 
        WHERE id = $2 AND user_id = $3
    `, projectID, scanID, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add scan to project"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Scan updated successfully"})
}

// DeleteScan удаляет сканирование
func DeleteScan(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	scanID := c.Param("id")

	result, err := database.DB.Exec(`
		DELETE FROM scans 
		WHERE id = $1 AND user_id = $2
	`, scanID, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete scan"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Scan deleted successfully"})
}
