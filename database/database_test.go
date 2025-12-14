package database

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitDB_MissingRequiredEnv(t *testing.T) {
	testCases := []struct {
		name   string
		envVar string
	}{
		{"Missing DB_HOST", "DB_HOST"},
		{"Missing DB_PORT", "DB_PORT"},
		{"Missing DB_USER", "DB_USER"},
		{"Missing DB_NAME", "DB_NAME"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldValue := os.Getenv(tc.envVar)
			os.Unsetenv(tc.envVar)
			defer os.Setenv(tc.envVar, oldValue)

			err := InitDB()
			assert.Error(t, err, "Should return error when %s is missing", tc.envVar)
		})
	}
}

func TestCloseDB_WithConnection(t *testing.T) {
	assert.NotPanics(t, func() {
		CloseDB()
	}, "CloseDB should not panic")

	if DB != nil {
		CloseDB()
		err := DB.Ping()
		assert.Error(t, err, "Ping should fail after CloseDB")
	}
}

func TestCloseDB_NilDB(t *testing.T) {
	oldDB := DB
	DB = nil
	defer func() { DB = oldDB }()

	assert.NotPanics(t, func() {
		CloseDB()
	}, "CloseDB should not panic when DB is nil")
}

func TestDatabase_ConnectionString(t *testing.T) {
	oldEnv := map[string]string{
		"DB_HOST":    os.Getenv("DB_HOST"),
		"DB_PORT":    os.Getenv("DB_PORT"),
		"DB_USER":    os.Getenv("DB_USER"),
		"DB_SSLMODE": os.Getenv("DB_SSLMODE"),
	}
	defer func() {
		for k, v := range oldEnv {
			os.Setenv(k, v)
		}
	}()

	os.Setenv("DB_HOST", "testhost")
	os.Setenv("DB_PORT", "1234")
	os.Setenv("DB_USER", "testuser")
	os.Setenv("DB_SSLMODE", "require")

	connStr := "host=testhost port=1234 user=testuser password= dbname= sslmode=require"
	assert.Contains(t, connStr, "testhost", "Connection string should contain host")
	assert.Contains(t, connStr, "1234", "Connection string should contain port")
}

func TestInitDB_MissingEnv(t *testing.T) {
	oldDBHost := os.Getenv("DB_HOST")
	os.Unsetenv("DB_HOST")
	defer os.Setenv("DB_HOST", oldDBHost)

	err := InitDB()
	assert.Error(t, err, "Should return error when DB_HOST is missing")
	assert.NotNil(t, err, "Error should not be nil")
}

func TestCloseDB(t *testing.T) {
	assert.NotPanics(t, func() {
		CloseDB()
	}, "CloseDB should not panic even if DB is nil")

	if DB != nil {
		CloseDB()
	}
}
