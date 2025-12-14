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

func TestIntegration_Project_Create_And_Get(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()

	t.Run("Create Project", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO projects`).
			WillReturnResult(sqlmock.NewResult(1, 1))

		projectData := map[string]interface{}{
			"name":        "Test Project",
			"description": "Test Description",
		}
		jsonData, _ := json.Marshal(projectData)

		req, _ := http.NewRequest("POST", "/api/projects", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("userID", userID)

		CreateProject(c)

		assert.Equal(t, 201, w.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Get Projects", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "name", "description", "created_at"}).
			AddRow(uuid.New(), "Project 1", "Desc 1", time.Now())

		mock.ExpectQuery(`SELECT id, name, description, created_at`).
			WithArgs(userID).
			WillReturnRows(rows)

		req, _ := http.NewRequest("GET", "/api/projects", nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("userID", userID)

		GetProjects(c)

		assert.Equal(t, 200, w.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIntegration_API_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		handler    gin.HandlerFunc
		method     string
		path       string
		body       interface{}
		userID     uuid.UUID
		wantStatus int
	}{
		{
			name:       "Create project with empty name",
			handler:    CreateProject,
			method:     "POST",
			path:       "/api/projects",
			body:       map[string]interface{}{"name": "", "description": "test"},
			userID:     uuid.New(),
			wantStatus: 400,
		},
		{
			name:       "Start scan with invalid URL",
			handler:    StartScan,
			method:     "POST",
			path:       "/api/scan/start",
			body:       map[string]interface{}{"target_url": "invalid", "project_id": ""},
			userID:     uuid.New(),
			wantStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Мок БД
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			oldDB := database.DB
			database.DB = db
			defer func() { database.DB = oldDB }()

			if tt.wantStatus == 201 || tt.wantStatus == 202 {
				mock.ExpectExec(`INSERT INTO`).WillReturnResult(sqlmock.NewResult(1, 1))
			}

			var req *http.Request
			if tt.body != nil {
				jsonData, _ := json.Marshal(tt.body)
				req, _ = http.NewRequest(tt.method, tt.path, bytes.NewBuffer(jsonData))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, _ = http.NewRequest(tt.method, tt.path, nil)
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Set("userID", tt.userID)

			tt.handler(c)

			assert.Equal(t, tt.wantStatus, w.Code, "Expected status %d, got %d", tt.wantStatus, w.Code)
		})
	}
}

func TestIntegration_Complete_Workflow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	userID := uuid.New()
	projectID := uuid.New()
	scanID := uuid.New()

	t.Run("1. Create Project", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO projects`).
			WillReturnResult(sqlmock.NewResult(1, 1))

		reqBody := map[string]interface{}{
			"name":        "Workflow Project",
			"description": "For complete workflow test",
		}
		jsonData, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", "/api/projects", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("userID", userID)

		CreateProject(c)

		assert.Equal(t, 201, w.Code)
	})

	t.Run("2. Start Scan", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO scans`).
			WillReturnResult(sqlmock.NewResult(1, 1))

		reqBody := map[string]interface{}{
			"target_url": "https://example.com",
			"project_id": projectID.String(),
		}
		jsonData, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", "/api/scan/start", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("userID", userID)

		StartScan(c)

		assert.Equal(t, 202, w.Code)
	})

	t.Run("3. Get Scans", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "target_url", "status", "project_id", "started_at", "finished_at", "created_at"}).
			AddRow(scanID, "https://example.com", "Queued", projectID, time.Now(), nil, time.Now())

		mock.ExpectQuery(`SELECT id, target_url, status, project_id, started_at, finished_at, created_at`).
			WithArgs(userID).
			WillReturnRows(rows)

		req, _ := http.NewRequest("GET", "/api/scans", nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("userID", userID)

		GetScans(c)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("4. Delete Scan", func(t *testing.T) {
		mock.ExpectExec(`DELETE FROM scans WHERE id = \$1 AND user_id = \$2`).
			WithArgs(scanID, userID).
			WillReturnResult(sqlmock.NewResult(0, 1))

		req, _ := http.NewRequest("DELETE", "/api/scans/"+scanID.String(), nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("userID", userID)
		c.Params = []gin.Param{{Key: "id", Value: scanID.String()}}

		DeleteScan(c)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("5. Delete Project", func(t *testing.T) {
		mock.ExpectExec(`DELETE FROM projects WHERE id = \$1 AND user_id = \$2`).
			WithArgs(projectID, userID).
			WillReturnResult(sqlmock.NewResult(0, 1))

		req, _ := http.NewRequest("DELETE", "/api/projects/"+projectID.String(), nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("userID", userID)
		c.Params = []gin.Param{{Key: "id", Value: projectID.String()}}

		DeleteProject(c)

		assert.Equal(t, 200, w.Code)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}
