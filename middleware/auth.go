package middleware

import (
	"net/http"

	"chimerascan/auth"

	"github.com/gin-gonic/gin"
)

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := auth.GetUserFromRequest(c)
		if err != nil || user == nil {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Set("userID", user.ID)
		c.Next()
	}
}

func OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := auth.GetUserFromRequest(c)
		if err == nil && user != nil {
			c.Set("user", user)
			c.Set("userID", user.ID)
		}
		c.Next()
	}
}
