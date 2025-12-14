package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"chimerascan/database"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreateProject_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()
	projectName := "Test Project"
	projectDescription := "Test Description"

	mock.ExpectExec(`INSERT INTO projects \(id, name, description, user_id, created_at\) VALUES \(\$1, \$2, \$3, \$4, \$5\)`).
		WithArgs(sqlmock.AnyArg(), projectName, projectDescription, userID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	requestBody := map[string]interface{}{
		"name":        projectName,
		"description": projectDescription,
	}
	jsonBody, _ := json.Marshal(requestBody)

	req, _ := http.NewRequest("POST", "/api/projects", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", userID)

	CreateProject(c)

	assert.Equal(t, http.StatusCreated, w.Code, "Should return 201 status")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.Equal(t, projectName, response["name"], "Project name should match")
	assert.Equal(t, projectDescription, response["description"], "Project description should match")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateProject_InvalidJSON(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	req, _ := http.NewRequest("POST", "/api/projects", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", uuid.New())

	CreateProject(c)

	assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 for invalid JSON")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Contains(t, response, "error", "Response should contain error field")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetProjects_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()
	projectID1 := uuid.New()
	projectID2 := uuid.New()

	rows := sqlmock.NewRows([]string{"id", "name", "description", "created_at"}).
		AddRow(projectID1, "Project 1", "Description 1", time.Now()).
		AddRow(projectID2, "Project 2", "Description 2", time.Now())

	mock.ExpectQuery(`SELECT id, name, description, created_at FROM projects WHERE user_id = \$1 ORDER BY created_at DESC`).
		WithArgs(userID).
		WillReturnRows(rows)

	req, _ := http.NewRequest("GET", "/api/projects", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", userID)

	GetProjects(c)

	if w.Code != 200 {
		t.Logf("Status: %d, Body: %s", w.Code, w.Body.String())
	}

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 status")

	bodyStr := w.Body.String()
	assert.NotEqual(t, "null", bodyStr, "Response should not be null")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteProject_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()
	projectID := uuid.New()

	mock.ExpectExec(`DELETE FROM projects WHERE id = \$1 AND user_id = \$2`).
		WithArgs(projectID, userID).
		WillReturnResult(sqlmock.NewResult(0, 1)) // 1 row affected

	req, _ := http.NewRequest("DELETE", "/api/projects/"+projectID.String(), nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", userID)
	c.Params = gin.Params{{Key: "id", Value: projectID.String()}}

	DeleteProject(c)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 status")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Project deleted successfully", response["message"], "Success message should match")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteProject_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()
	projectID := uuid.New()

	mock.ExpectExec(`DELETE FROM projects WHERE id = \$1 AND user_id = \$2`).
		WithArgs(projectID, userID).
		WillReturnResult(sqlmock.NewResult(0, 0)) // 0 rows affected

	req, _ := http.NewRequest("DELETE", "/api/projects/"+projectID.String(), nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", userID)
	c.Params = gin.Params{{Key: "id", Value: projectID.String()}}

	DeleteProject(c)

	assert.Equal(t, http.StatusNotFound, w.Code, "Should return 404 for non-existent project")

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Contains(t, response, "error", "Response should contain error field")

	assert.NoError(t, mock.ExpectationsWereMet())
}
func TestUpdateProject_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()
	projectID := uuid.New()

	mock.ExpectExec(`UPDATE projects SET name = \$1, description = \$2 WHERE id = \$3 AND user_id = \$4`).
		WithArgs("Updated Name", "Updated Desc", projectID, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	requestBody := map[string]interface{}{
		"name":        "Updated Name",
		"description": "Updated Desc",
	}
	jsonBody, _ := json.Marshal(requestBody)

	req, _ := http.NewRequest("PUT", "/api/projects/"+projectID.String(), bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", userID)
	c.Params = gin.Params{{Key: "id", Value: projectID.String()}}

	UpdateProject(c)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 status")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestStartScan_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()

	mock.ExpectExec(`INSERT INTO scans \(id, target_url, status, project_id, started_at, user_id, created_at\) VALUES \(\$1, \$2, \$3, \$4, \$5, \$6, \$7\)`).
		WithArgs(sqlmock.AnyArg(), "https://example.com", "Queued", nil, sqlmock.AnyArg(), userID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	requestBody := map[string]interface{}{
		"target_url": "https://example.com",
		"project_id": "",
	}
	jsonBody, _ := json.Marshal(requestBody)

	req, _ := http.NewRequest("POST", "/api/scan/start", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", userID)

	StartScan(c)

	assert.Equal(t, http.StatusAccepted, w.Code, "Should return 202 status")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetScans_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()
	scanID := uuid.New()

	rows := sqlmock.NewRows([]string{"id", "target_url", "status", "project_id", "started_at", "finished_at", "created_at"}).
		AddRow(scanID, "https://example.com", "Completed", nil, time.Now(), time.Now(), time.Now())

	mock.ExpectQuery(`SELECT id, target_url, status, project_id, started_at, finished_at, created_at FROM scans WHERE user_id = \$1 ORDER BY created_at DESC`).
		WithArgs(userID).
		WillReturnRows(rows)

	req, _ := http.NewRequest("GET", "/api/scans", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", userID)

	GetScans(c)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 status")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAddScanToProject_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()
	scanID := uuid.New()
	projectID := uuid.New()

	rows := sqlmock.NewRows([]string{"exists"}).AddRow(true)
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM projects WHERE id = \$1 AND user_id = \$2\)`).
		WithArgs(projectID, userID).
		WillReturnRows(rows)

	mock.ExpectExec(`UPDATE scans SET project_id = \$1 WHERE id = \$2 AND user_id = \$3`).
		WithArgs(projectID, scanID, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	requestBody := map[string]interface{}{
		"project_id": projectID.String(),
	}
	jsonBody, _ := json.Marshal(requestBody)

	req, _ := http.NewRequest("POST", "/api/scans/"+scanID.String()+"/add-to-project", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", userID)
	c.Params = gin.Params{{Key: "id", Value: scanID.String()}}

	AddScanToProject(c)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 status")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteScan_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()
	scanID := uuid.New()

	mock.ExpectExec(`DELETE FROM scans WHERE id = \$1 AND user_id = \$2`).
		WithArgs(scanID, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req, _ := http.NewRequest("DELETE", "/api/scans/"+scanID.String(), nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("userID", userID)
	c.Params = gin.Params{{Key: "id", Value: scanID.String()}}

	DeleteScan(c)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 status")
	assert.NoError(t, mock.ExpectationsWereMet())
}
