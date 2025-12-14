-- Создание типов для статуса сканирования
CREATE TYPE scan_status AS ENUM ('Queued', 'In Progress', 'Completed', 'Failed', 'Canceled');
CREATE TYPE severity_level AS ENUM ('Info', 'Low', 'Medium', 'High');

-- Таблица пользователей
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider_id)
);

-- Таблица проектов
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Таблица сканирований
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_url TEXT NOT NULL,
    status scan_status NOT NULL DEFAULT 'Queued',
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    raw_nuclei_output JSONB,
    report_json_path TEXT,
    report_pdf_path TEXT,
    report_html_path TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

-- Таблица уязвимостей 
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    template_id TEXT NOT NULL,
    name TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    severity_ai VARCHAR(20) NOT NULL,
    description TEXT,
    description_ru TEXT,
    reference JSONB,
    tags JSONB,
    classification JSONB,
    host TEXT NOT NULL,
    matched_at TEXT,
    ip TEXT,
    timestamp TIMESTAMP WITH TIME ZONE,
    curl_command TEXT,
    request TEXT,
    response TEXT,
    metadata JSONB,
    recommendation_ai TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Индексы для быстрого поиска
CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_severity_ai ON vulnerabilities(severity_ai);
-- Индексы для таблицы scans
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_created_at ON scans(created_at);
CREATE INDEX idx_scans_user_id_created_at ON scans(user_id, created_at);
CREATE INDEX idx_scans_project_id ON scans(project_id);

-- Индексы для таблицы projects
CREATE INDEX idx_projects_user_id ON projects(user_id);
CREATE INDEX idx_projects_created_at ON projects(created_at);
CREATE INDEX idx_projects_user_id_created_at ON projects(user_id, created_at);

-- Индекс для таблицы users
CREATE INDEX idx_users_provider_id ON users(provider_id);

-- Индекс для таблицы vulnerabilities
CREATE INDEX idx_vulnerabilities_severity_ai_scan_id ON vulnerabilities(severity_ai, scan_id);