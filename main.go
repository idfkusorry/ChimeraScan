package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"chimerascan/auth"
	"chimerascan/database"
	"chimerascan/handlers"
	"chimerascan/middleware"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	if err := database.InitDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer database.CloseDB()

	auth.InitOAuth()

	os.MkdirAll("reports", 0755)
	os.MkdirAll("static/reports", 0755)
	os.MkdirAll("templates", 0755)

	router := gin.Default()

	router.Static("/static", "./static")
	router.Static("/reports", "./reports")

	router.LoadHTMLGlob("templates/*.html")

	public := router.Group("/")
	{
		public.GET("/", handlers.LoginPage)
		public.GET("/auth/github", handlers.GitHubAuth)
		public.GET("/auth/github/callback", handlers.GitHubCallback)
		public.GET("/auth/gitlab", handlers.GitLabAuth)
		public.GET("/auth/gitlab/callback", handlers.GitLabCallback)
		public.GET("/logout", handlers.Logout)
	}

	protected := router.Group("/")
	protected.Use(middleware.AuthRequired())
	{
		protected.GET("/dashboard", handlers.DashboardPage)
		protected.GET("/scan", handlers.ScanPage)
		protected.GET("/projects", handlers.ProjectsPage)
		protected.GET("/scans", handlers.ScansPage)
		protected.GET("/project/:id", handlers.ProjectPage)

		protected.POST("/api/projects", handlers.CreateProject)
		protected.GET("/api/projects", handlers.GetProjects)
		protected.DELETE("/api/projects/:id", handlers.DeleteProject)
		protected.POST("/api/scan/start", handlers.StartScan)
		protected.POST("/api/scan/stop/:id", handlers.StopScan)
		protected.GET("/api/scan/status/:id", handlers.GetScanStatus)
		protected.GET("/api/scans", handlers.GetScans)
		protected.POST("/api/scans/:id/add-to-project", handlers.AddScanToProject)
		protected.DELETE("/api/scans/:id", handlers.DeleteScan)
		protected.GET("/api/report/:id/:format", handlers.DownloadReport)
		protected.PUT("/api/projects/:id", handlers.UpdateProject)
		protected.GET("/api/scans/:id/projects", handlers.GetProjectsForScan)
	}

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on http://localhost:%s", port)
	router.Run(":" + port)
}
