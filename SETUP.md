# Установка и настройка ChimeraScan

ChimeraScan - это DAST-сканер для веб-приложений с AI-анализом, написанный на Go. Приложение использует PostgreSQL, OAuth-аутентификацию через GitHub/GitLab, сканер Nuclei через Docker и AI-модуль на основе Ollama.

## 📋 Предварительные требования

### Обязательные зависимости:
- **Go 1.24+** (указано в Dockerfile)
- **Docker 20.10+** (для работы Nuclei сканера)
- **PostgreSQL 14+** (или запуск через Docker)
- **Git**

### Опциональные (для AI-анализа):
- **Ollama** (для AI-анализа уязвимостей)

## 🚀 Варианты запуска

### Вариант 1: Быстрый запуск (рекомендуется для разработки)

#### Шаг 1: Получение исходного кода
```bash
git clone https://github.com/idfkusorry/ChimeraScan.git
cd ChimeraScan

Шаг 2: Настройка переменных окружения
bash
cp .env.example .env
Отредактируйте файл .env, указав необходимые значения:

env
# Сервер
SERVER_PORT=8080

# База данных PostgreSQL
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=chimerascan
DB_SSLMODE=disable

# OAuth GitHub
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# OAuth GitLab
GITLAB_CLIENT_ID=your_gitlab_client_id
GITLAB_CLIENT_SECRET=your_gitlab_client_secret
GITLAB_BASE_URL=https://gitlab.com
Шаг 3: Настройка базы данных
Вариант A: Локальный PostgreSQL

bash
# Создание базы данных
createdb chimerascan
# Или через psql
psql -c "CREATE DATABASE chimerascan;"
Вариант B: PostgreSQL через Docker

bash
# Запуск PostgreSQL в Docker
docker run --name chimerascan-postgres \
  -e POSTGRES_PASSWORD=your_password \
  -e POSTGRES_DB=chimerascan \
  -p 5432:5432 \
  -d postgres:15-alpine
Шаг 4: Настройка OAuth-приложений
GitHub:

Перейдите на https://github.com/settings/developers

Нажмите "New OAuth App"

Заполните:

Application name: ChimeraScan

Homepage URL: http://localhost:8080

Authorization callback URL: http://localhost:8080/auth/github/callback

Скопируйте Client ID и Client Secret в .env

GitLab:

Перейдите на https://gitlab.com/-/profile/applications

Нажмите "New application"

Заполните:

Name: ChimeraScan

Redirect URI: http://localhost:8080/auth/gitlab/callback

Scopes: read_user

Скопируйте Application ID и Secret в .env

Шаг 5: Установка зависимостей
bash
# Загрузка зависимостей Go
go mod download
go mod tidy
Шаг 6: Запуск приложения
bash
# Запуск приложения (миграции выполнятся автоматически)
go run main.go
Приложение будет доступно по адресу: http://localhost:8080

Вариант 2: Сборка и запуск исполняемого файла
Шаг 1-5: Выполните шаги 1-5 из Варианта 1
Шаг 6: Сборка приложения
bash
# Сборка исполняемого файла
go build -o chimerascan main.go
Шаг 7: Выполнение миграций (если не сработали автоматически)
bash
# Установка инструмента миграций
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Выполнение миграций
migrate -path migrations -database "postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=$DB_SSLMODE" up
Шаг 8: Запуск
bash
# Запуск собранного приложения
./chimerascan
Вариант 3: Запуск с AI-анализом (Ollama)
Шаг 1-5: Выполните шаги 1-5 из Варианта 1
Шаг 6: Настройка Ollama
bash
# Установка Ollama (если еще не установлен)
# Следуйте инструкциям на https://ollama.com/download

# Запуск сервиса Ollama
ollama serve

# В отдельном терминале загрузите модель
ollama pull phi:2.7b  # Или используйте llama3:8b из кода
Шаг 7: Проверка Ollama
bash
# Проверьте, что Ollama работает
curl http://localhost:11434/api/tags
Шаг 8: Запуск приложения
bash
go run main.go
Вариант 4: Полный Docker-запуск (только база данных)
bash
# Создание сети Docker
docker network create chimerascan-network

# Запуск PostgreSQL
docker run -d --name chimerascan-db \
  --network chimerascan-network \
  -e POSTGRES_PASSWORD=your_password \
  -e POSTGRES_DB=chimerascan \
  -p 5432:5432 \
  postgres:15-alpine

# Ожидаем запуск базы данных
sleep 5

# Запуск приложения (измените DB_HOST на chimerascan-db в .env)
go run main.go
🔧 Проверка работоспособности
После запуска приложения:

Откройте браузер и перейдите по адресу: http://localhost:8080

Войдите в систему, используя кнопки аутентификации через GitHub или GitLab

Проверьте Docker:

bash
# Убедитесь, что Docker запущен
docker ps

# Pull Nuclei образ (при первом сканировании загрузится автоматически)
docker pull projectdiscovery/nuclei:latest
Проверьте AI-модуль (если используется):

bash
# Проверьте работу Ollama
ollama list