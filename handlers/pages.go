package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func DashboardPage(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Title": "Главная панель",
	})
}

func ScanPage(c *gin.Context) {
	c.HTML(http.StatusOK, "scan.html", gin.H{
		"Title": "Запуск сканирования",
	})
}

func ProjectsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "projects.html", gin.H{
		"Title": "Архив проектов",
	})
}

func ScansPage(c *gin.Context) {
	c.HTML(http.StatusOK, "scans.html", gin.H{
		"Title": "Архив сканирований",
	})
}

func ProjectPage(c *gin.Context) {
	c.HTML(http.StatusOK, "project.html", gin.H{
		"Title": "Проект",
	})
}
