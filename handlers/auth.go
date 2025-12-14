package handlers

import (
	"net/http"
	"strconv"

	"chimerascan/auth"

	"github.com/gin-gonic/gin"
)

func LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

func GitHubAuth(c *gin.Context) {
	oauthConfig := auth.GetGitHubOAuthConfig()
	state := auth.GenerateStateOauthCookie(c)
	url := oauthConfig.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func GitHubCallback(c *gin.Context) {
	state := c.Query("state")
	cookieState, err := c.Cookie("oauthstate")

	if err != nil || state != cookieState {
		c.Redirect(http.StatusTemporaryRedirect, "/?error=invalid_state")
		return
	}

	code := c.Query("code")
	oauthConfig := auth.GetGitHubOAuthConfig()

	token, err := oauthConfig.Exchange(c, code)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/?error=token_exchange_failed")
		return
	}

	userInfo, err := auth.GitHubUserInfo(token.AccessToken)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/?error=user_info_failed")
		return
	}

	providerID := strconv.FormatFloat(userInfo["id"].(float64), 'f', 0, 64)
	username := userInfo["login"].(string)

	var email string
	if userInfo["email"] != nil {
		email = userInfo["email"].(string)
	} else {
		email = username + "@users.noreply.github.com"
	}

	user, err := auth.CreateOrGetUser(providerID, email, username, "github")
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/?error=user_creation_failed")
		return
	}

	c.SetCookie("user_id", user.ID.String(), 3600*24, "/", "localhost", false, true)
	c.SetCookie("username", user.Username, 3600*24, "/", "localhost", false, true)

	c.Redirect(http.StatusFound, "/dashboard")
}

func GitLabAuth(c *gin.Context) {
	oauthConfig := auth.GetGitLabOAuthConfig()
	state := auth.GenerateStateOauthCookie(c)
	url := oauthConfig.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func GitLabCallback(c *gin.Context) {
	state := c.Query("state")
	cookieState, err := c.Cookie("oauthstate")

	if err != nil || state != cookieState {
		c.Redirect(http.StatusTemporaryRedirect, "/?error=invalid_state")
		return
	}

	code := c.Query("code")
	oauthConfig := auth.GetGitLabOAuthConfig()

	token, err := oauthConfig.Exchange(c, code)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/?error=token_exchange_failed")
		return
	}

	userInfo, err := auth.GitLabUserInfo(token.AccessToken)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/?error=user_info_failed")
		return
	}

	providerID := strconv.FormatFloat(userInfo["id"].(float64), 'f', 0, 64)
	email := userInfo["email"].(string)
	username := userInfo["username"].(string)

	user, err := auth.CreateOrGetUser(providerID, email, username, "gitlab")
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/?error=user_creation_failed")
		return
	}

	c.SetCookie("user_id", user.ID.String(), 3600*24, "/", "localhost", false, true)
	c.SetCookie("username", user.Username, 3600*24, "/", "localhost", false, true)

	c.Redirect(http.StatusFound, "/dashboard")
}

func Logout(c *gin.Context) {
	c.SetCookie("user_id", "", -1, "/", "localhost", false, true)
	c.SetCookie("username", "", -1, "/", "localhost", false, true)
	c.Redirect(http.StatusFound, "/")
}
