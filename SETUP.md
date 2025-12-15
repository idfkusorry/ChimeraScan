# Установка и настройка ChimeraScan

ChimeraScan - это DAST-сканер для веб-приложений с AI-анализом, написанный на Go. Приложение использует PostgreSQL, OAuth-аутентификацию через GitHub/GitLab, сканер Nuclei через Docker и AI-модуль на основе Ollama.

## Предварительные требования

### Обязательные зависимости:
- **Go 1.24+** (указано в Dockerfile)
- **Docker 20.10+** (для работы Nuclei сканера)
- **PostgreSQL 14+** (или запуск через Docker)
- **Git**

### Опциональные (для AI-анализа):
- **Ollama** (для AI-анализа уязвимостей)

## Действия по запуску

### Шаг 1: Получение исходного кода
```bash
git clone https://github.com/idfkusorry/ChimeraScan.git
cd ChimeraScan
```

### Шаг 2: Настройка переменных окружения
Отредактируйте файл .env.example, указав необходимые значения

### Шаг 3: Настройка базы данных
#### Создание базы данных
```bash
createdb chimerascan
```
#### Или через psql
```bash
psql -c "CREATE DATABASE chimerascan;"
```

### Шаг 4: Настройка OAuth-приложений
#### GitHub:
Перейдите на https://github.com/settings/developers
Нажмите "New OAuth App"
Заполните:
- Application name: ChimeraScan
- Homepage URL: http://localhost:8080
- Authorization callback URL: http://localhost:8080/auth/github/callback
- Скопируйте Client ID и Client Secret в .env.example

#### GitLab:
Перейдите на https://gitlab.com/-/profile/applications
Нажмите "New application"
Заполните:
- Name: ChimeraScan
- Redirect URI: http://localhost:8080/auth/gitlab/callback
- Scopes: read_user
- Скопируйте Application ID и Secret в .env.example

### Шаг 5: Установка зависимостей
#### Загрузка зависимостей Go
```bash
go mod download
go mod tidy
```

### Шаг 6: Запуск приложения (Вариант 1)
#### Запуск приложения (миграции выполнятся автоматически)
```bash
go run main.go
```
Приложение будет доступно по адресу: http://localhost:8080

### Шаг 6: Сборка приложения (Вариант 2)
#### Сборка исполняемого файла
```bash
go build -o chimerascan main.go
```

### Шаг 7: Выполнение миграций (если не сработали автоматически)
#### Установка инструмента миграций
```bash
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
```

#### Выполнение миграций
```bash
migrate -path migrations -database "postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=$DB_SSLMODE" up
```

### Шаг 8: Запуск
#### Запуск собранного приложения
```bash
./chimerascan
```

## Запуск с AI-анализом (Ollama)
Шаг 1-5: Выполните шаги 1-5
### Шаг 6: Настройка Ollama
#### Установка Ollama (если еще не установлен)
#### Следуйте инструкциям на https://ollama.com/download

#### Запуск сервиса Ollama
```bash
ollama serve
```

#### В отдельном терминале загрузите модель
```bash
ollama pull phi:2.7b
```

### Шаг 7: Проверка Ollama
#### Проверьте, что Ollama работает
```bash
curl http://localhost:11434/api/tags
```

### Шаг 8: Запуск приложения
```bash
go run main.go
```

### После запуска приложения:

- Откройте браузер и перейдите по адресу: http://localhost:8080

- Войдите в систему, используя кнопки аутентификации через GitHub или GitLab

### При возникновении проблем необходимо:

#### Убедится, что Docker запущен
```bash
docker ps
```

Проверьте AI-модуль (если используется):
#### Проверить работу Ollama
```bash
ollama list
```
