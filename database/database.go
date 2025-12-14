package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

var DB *sql.DB

func InitDB() error {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSLMODE"),
	)

	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	if err = DB.Ping(); err != nil {
		return err
	}

	log.Println("Connected to database successfully")

	// Запуск миграций (автоматически при запуске)
	if err := runMigrations(); err != nil {
		return err
	}

	return nil
}

func runMigrations() error {
	driver, err := postgres.WithInstance(DB, &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	if err != nil {
		return err
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}

	log.Println("Database migrations applied successfully")
	return nil
}

func CloseDB() {
	if DB != nil {
		DB.Close()
	}
}

// Создание таблиц для интеграционного теста
func InitTestDB() error {
	var err error
	DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		return err
	}

	if err = DB.Ping(); err != nil {
		return err
	}

	return createTestTables()
}

func createTestTables() error {
	queries := []string{
		`CREATE TABLE users (
            id TEXT PRIMARY KEY,
            provider_id TEXT NOT NULL,
            email TEXT NOT NULL,
            username TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            user_id TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )`,

		`CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            status TEXT NOT NULL,
            project_id TEXT,
            started_at DATETIME,
            finished_at DATETIME,
            user_id TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )`,
	}

	for _, query := range queries {
		_, err := DB.Exec(query)
		if err != nil {
			return err
		}
	}

	return nil
}
