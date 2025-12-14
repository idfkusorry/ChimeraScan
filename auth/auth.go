package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"chimerascan/database"
	"chimerascan/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var (
	githubOAuthConfig *oauth2.Config
	gitlabOAuthConfig *oauth2.Config
)

func InitOAuth() {
	githubOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/auth/github/callback",
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}

	gitlabBaseURL := os.Getenv("GITLAB_BASE_URL")
	if gitlabBaseURL == "" {
		gitlabBaseURL = "https://gitlab.com"
	}

	gitlabOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GITLAB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITLAB_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/auth/gitlab/callback",
		Scopes:       []string{"read_user"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  gitlabBaseURL + "/oauth/authorize",
			TokenURL: gitlabBaseURL + "/oauth/token",
		},
	}
}

func GenerateStateOauthCookie(c *gin.Context) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	c.SetCookie("oauthstate", state, 3600, "/", "localhost", false, true)
	return state
}

func GetGitHubOAuthConfig() *oauth2.Config {
	return githubOAuthConfig
}

func GetGitLabOAuthConfig() *oauth2.Config {
	return gitlabOAuthConfig
}

// GitHubUserInfo получает информацию о пользователе из GitHub
func GitHubUserInfo(token string) (map[string]interface{}, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return user, nil
}

// GitLabUserInfo получает информацию о пользователе из GitLab
func GitLabUserInfo(token string) (map[string]interface{}, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", os.Getenv("GITLAB_BASE_URL")+"/api/v4/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return user, nil
}

// CreateOrGetUser создает или получает пользователя из базы данных
func CreateOrGetUser(providerID, email, username, provider string) (*models.User, error) {
	var user models.User
	query := `SELECT id, provider_id, email, username, created_at FROM users WHERE provider_id = $1`

	err := database.DB.QueryRow(query, providerID).Scan(
		&user.ID, &user.ProviderID, &user.Email, &user.Username, &user.CreatedAt,
	)

	if err == sql.ErrNoRows {
		user.ID = uuid.New()
		user.ProviderID = providerID
		user.Email = email
		user.Username = username
		user.CreatedAt = time.Now()

		insertQuery := `INSERT INTO users (id, provider_id, email, username, created_at) 
                       VALUES ($1, $2, $3, $4, $5)`
		_, err := database.DB.Exec(insertQuery, user.ID, user.ProviderID, user.Email, user.Username, user.CreatedAt)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserFromRequest получает пользователя из cookies
func GetUserFromRequest(c *gin.Context) (*models.User, error) {
	userIDStr, err := c.Cookie("user_id")
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, err
	}

	var user models.User
	query := `SELECT id, provider_id, email, username, created_at FROM users WHERE id = $1`
	err = database.DB.QueryRow(query, userID).Scan(
		&user.ID, &user.ProviderID, &user.Email, &user.Username, &user.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}
