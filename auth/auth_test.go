package auth

import (
	"database/sql"
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

func TestGenerateStateOauthCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	state := GenerateStateOauthCookie(c)

	assert.NotEmpty(t, state, "State should not be empty")
	assert.Len(t, state, 24, "Base64 encoded state should be 24 chars") // Исправлено с 22 на 24

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1, "Should set one cookie")
	assert.Equal(t, "oauthstate", cookies[0].Name, "Cookie name should be 'oauthstate'")
}

func TestCreateOrGetUser_NewUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	providerID := "12345"
	email := "test@example.com"
	username := "testuser"

	mock.ExpectQuery(`SELECT id, provider_id, email, username, created_at FROM users WHERE provider_id = \$1`).
		WithArgs(providerID).
		WillReturnError(sql.ErrNoRows)

	mock.ExpectExec(`INSERT INTO users \(id, provider_id, email, username, created_at\)`).
		WithArgs(sqlmock.AnyArg(), providerID, email, username, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	user, err := CreateOrGetUser(providerID, email, username, "github")

	assert.NoError(t, err, "Should not return error")
	assert.NotNil(t, user, "User should not be nil")
	assert.Equal(t, email, user.Email, "Emails should match")
	assert.Equal(t, username, user.Username, "Usernames should match")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateOrGetUser_ExistingUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	providerID := "12345"
	email := "existing@example.com"
	username := "existinguser"
	userID := uuid.New()
	createdAt := time.Now()

	rows := sqlmock.NewRows([]string{"id", "provider_id", "email", "username", "created_at"}).
		AddRow(userID, providerID, email, username, createdAt)

	mock.ExpectQuery(`SELECT id, provider_id, email, username, created_at FROM users WHERE provider_id = \$1`).
		WithArgs(providerID).
		WillReturnRows(rows)

	user, err := CreateOrGetUser(providerID, email, username, "github")

	assert.NoError(t, err, "Should not return error")
	assert.NotNil(t, user, "User should not be nil")
	assert.Equal(t, userID, user.ID, "User IDs should match")
	assert.Equal(t, email, user.Email, "Emails should match")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserFromRequest_Valid(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	oldDB := database.DB
	database.DB = db
	defer func() { database.DB = oldDB }()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	userID := uuid.New()
	cookie := &http.Cookie{
		Name:  "user_id",
		Value: userID.String(),
	}
	c.Request = &http.Request{
		Header: http.Header{"Cookie": []string{cookie.String()}},
	}

	rows := sqlmock.NewRows([]string{"id", "provider_id", "email", "username", "created_at"}).
		AddRow(userID, "github_123", "test@example.com", "testuser", time.Now())

	mock.ExpectQuery(`SELECT id, provider_id, email, username, created_at FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(rows)

	user, err := GetUserFromRequest(c)

	assert.NoError(t, err, "Should not return error")
	assert.NotNil(t, user, "User should not be nil")
	assert.Equal(t, userID, user.ID, "User IDs should match")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUserFromRequest_InvalidUUID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	cookie := &http.Cookie{
		Name:  "user_id",
		Value: "not-a-valid-uuid",
	}
	c.Request = &http.Request{
		Header: http.Header{"Cookie": []string{cookie.String()}},
	}

	user, err := GetUserFromRequest(c)

	assert.Error(t, err, "Should return error for invalid UUID")
	assert.Nil(t, user, "User should be nil on error")
	assert.Contains(t, err.Error(), "invalid UUID", "Error should mention UUID")
}
