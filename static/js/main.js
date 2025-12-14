document.addEventListener('DOMContentLoaded', function() {
    console.log('ChimeraScan UI initialized');
    
    initAsciiMatrix();
    
    initModals();
    
    initTooltips();
    
    setUserInfo();
});

function initAsciiMatrix() {
    const asciiSymbols = ['{', '}', '/', '*', '<', '>', '[', ']', '&', '#', '@', '%', '$'];
    const matrixContainer = document.getElementById('ascii-matrix');
    
    if (!matrixContainer) return;
    
    for (let i = 0; i < 50; i++) {
        const symbol = document.createElement('div');
        symbol.className = 'ascii-symbol';
        symbol.textContent = asciiSymbols[Math.floor(Math.random() * asciiSymbols.length)];
        symbol.style.left = `${Math.random() * 100}%`;
        symbol.style.fontSize = `${Math.random() * 12 + 10}px`;
        symbol.style.opacity = Math.random() * 0.1 + 0.05;
        symbol.style.setProperty('--delay', Math.random() * 20);
        
        matrixContainer.appendChild(symbol);
    }
    
    setInterval(() => {
        const symbols = document.querySelectorAll('.ascii-symbol');
        const randomSymbol = symbols[Math.floor(Math.random() * symbols.length)];
        
        if (randomSymbol) {
            randomSymbol.style.opacity = Math.random() * 0.3 + 0.1;
            setTimeout(() => {
                randomSymbol.style.opacity = Math.random() * 0.1 + 0.05;
            }, 100);
        }
    }, 2000);
}

function setUserInfo() {
    const username = getCookie('username') || 'Пользователь';
    const usernameElements = document.querySelectorAll('#username, .username');
    
    usernameElements.forEach(el => {
        if (el.id === 'username' || el.classList.contains('username')) {
            el.textContent = username;
        }
    });
    
    const avatarElements = document.querySelectorAll('.user-avatar, .avatar');
    avatarElements.forEach(el => {
        if (!el.getAttribute('src')) {
            if (username && !el.textContent) {
                el.textContent = username.charAt(0).toUpperCase();
            }
        }
    });
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function initModals() {
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal-overlay')) {
            closeAllModals();
        }
    });
    
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeAllModals();
        }
    });
    
    document.querySelectorAll('.modal-close, [data-modal-close]').forEach(btn => {
        btn.addEventListener('click', closeAllModals);
    });
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

function closeAllModals() {
    document.querySelectorAll('.modal-overlay.active').forEach(modal => {
        modal.classList.remove('active');
    });
    document.body.style.overflow = '';
}

function initTooltips() {
    const tooltipElements = document.querySelectorAll('[title]');
    
    tooltipElements.forEach(el => {
        el.addEventListener('mouseenter', showTooltip);
        el.addEventListener('mouseleave', hideTooltip);
    });
}

function showTooltip(e) {
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = e.target.getAttribute('title');
    tooltip.style.cssText = `
        position: fixed;
        background: rgba(20, 15, 35, 0.95);
        backdrop-filter: blur(10px);
        color: white;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 0.9rem;
        z-index: 10000;
        border: 1px solid rgba(124, 77, 255, 0.3);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        pointer-events: none;
        max-width: 300px;
        white-space: nowrap;
    `;
    
    document.body.appendChild(tooltip);
    
    const x = e.pageX + 10;
    const y = e.pageY + 10;
    
    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${y}px`;
    
    e.target.dataset.tooltipId = 'tooltip-' + Date.now();
    tooltip.id = e.target.dataset.tooltipId;
}

function hideTooltip(e) {
    const tooltipId = e.target.dataset.tooltipId;
    if (tooltipId) {
        const tooltip = document.getElementById(tooltipId);
        if (tooltip) {
            tooltip.remove();
        }
    }
}

function validateForm(form) {
    const requiredInputs = form.querySelectorAll('[required]');
    let isValid = true;
    
    requiredInputs.forEach(input => {
        if (!input.value.trim()) {
            showInputError(input, 'Это поле обязательно для заполнения');
            isValid = false;
        } else {
            clearInputError(input);
        }
    });
    
    return isValid;
}

function showInputError(input, message) {
    clearInputError(input);
    
    const error = document.createElement('div');
    error.className = 'form-error';
    error.textContent = message;
    error.style.cssText = `
        color: var(--color-error);
        font-size: 0.85rem;
        margin-top: 4px;
    `;
    
    input.parentNode.appendChild(error);
    input.style.borderColor = 'var(--color-error)';
}

function clearInputError(input) {
    const error = input.parentNode.querySelector('.form-error');
    if (error) {
        error.remove();
    }
    input.style.borderColor = '';
}

class ScanManager {
    constructor() {
        this.currentScanId = null;
        this.statusInterval = null;
        this.isScanning = false;
    }
    
    startScan(targetUrl, projectId = null) {
        if (!targetUrl) {
            alert('Пожалуйста, введите URL для сканирования');
            return false;
        }
        
        console.log('Starting scan:', { targetUrl, projectId });
        
        this.showScanningUI();
        this.isScanning = true;
        
        this.simulateScanProgress();
        
        return true;
    }
    
    stopScan() {
        if (!this.isScanning) return;
        
        clearInterval(this.statusInterval);
        this.isScanning = false;
        
        const statusElement = document.getElementById('scanStatus');
        const sphere = document.querySelector('.pulsing-sphere');
        
        if (statusElement) {
            statusElement.textContent = 'Сканирование остановлено';
            statusElement.style.color = 'var(--color-warning)';
        }
        
        if (sphere) {
            sphere.style.animation = 'none';
            sphere.style.opacity = '0.5';
        }
        
        console.log('Scan stopped');
    }
    
    showScanningUI() {
        const startBtn = document.getElementById('startScanBtn');
        const scanningSection = document.getElementById('scanningSection');
        
        if (startBtn) startBtn.style.display = 'none';
        if (scanningSection) scanningSection.style.display = 'block';
    }
    
    hideScanningUI() {
        const startBtn = document.getElementById('startScanBtn');
        const scanningSection = document.getElementById('scanningSection');
        const reportSection = document.getElementById('reportSection');
        
        if (startBtn) startBtn.style.display = 'block';
        if (scanningSection) scanningSection.style.display = 'none';
        if (reportSection) reportSection.style.display = 'block';
    }
    
    simulateScanProgress() {
        const statusElement = document.getElementById('scanStatus');
        const statuses = [
            'Подготовка к сканированию',
            'Анализ цели',
            'Проверка уязвимостей',
            'Сканирование параметров',
            'Формирование отчета',
            'Завершение'
        ];
        
        let progress = 0;
        
        this.statusInterval = setInterval(() => {
            if (progress < statuses.length) {
                if (statusElement) {
                    statusElement.textContent = statuses[progress];
                }
                progress++;
            } else {
                clearInterval(this.statusInterval);
                this.completeScan();
            }
        }, 2000);
    }
    
    completeScan() {
        this.isScanning = false;
        this.hideScanningUI();
        console.log('Scan completed');
    }
    
    downloadReport(scanId, format) {
        window.open(`/api/report/${scanId}/${format}`, '_blank');
    }
}

if (document.querySelector('.scan-form')) {
    window.scanManager = new ScanManager();
}

function loadProjects() {
    return fetch('/api/projects')
        .then(response => response.json())
        .catch(error => {
            console.error('Error loading projects:', error);
            return [];
        });
}

function loadProjectScans(projectId) {
    return fetch(`/api/projects/${projectId}/scans`)
        .then(response => response.json())
        .catch(error => {
            console.error('Error loading project scans:', error);
            return [];
        });
}

function createProject(name, description = '') {
    return fetch('/api/projects', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, description })
    })
    .then(response => response.json());
}

function updateProject(projectId, data) {
    return fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json());
}

function deleteProject(projectId) {
    return fetch(`/api/projects/${projectId}`, {
        method: 'DELETE'
    });
}

function loadScans() {
    return fetch('/api/scans')
        .then(response => response.json())
        .catch(error => {
            console.error('Error loading scans:', error);
            return [];
        });
}

function deleteScan(scanId) {
    return fetch(`/api/scans/${scanId}`, {
        method: 'DELETE'
    });
}

function addScanToProject(scanId, projectId) {
    return fetch(`/api/scans/${scanId}/add-to-project`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ project_id: projectId })
    });
}

function truncateText(text, maxLength = 50) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('ru-RU', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function setupSearch(inputId, itemsSelector, searchCallback) {
    const searchInput = document.getElementById(inputId);
    if (!searchInput) return;
    
    const debouncedSearch = debounce(function() {
        const searchTerm = this.value.toLowerCase();
        searchCallback(searchTerm);
    }, 300);
    
    searchInput.addEventListener('input', debouncedSearch);
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: rgba(20, 15, 35, 0.95);
        backdrop-filter: blur(10px);
        color: white;
        padding: 16px 24px;
        border-radius: var(--border-radius-md);
        border-left: 4px solid var(--color-${type});
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

window.ChimeraUI = {
    openModal,
    closeModal,
    closeAllModals,
    validateForm,
    truncateText,
    formatDate,
    showToast,
    setupSearch,
    
    startScan: function() {
        const targetUrl = document.getElementById('targetUrl')?.value;
        const projectId = document.getElementById('projectSelect')?.value || null;
        
        if (window.scanManager) {
            return window.scanManager.startScan(targetUrl, projectId);
        }
        return false;
    },
    
    stopScan: function() {
        if (window.scanManager) {
            window.scanManager.stopScan();
        }
    },
    
    downloadReport: function(scanId, format) {
        if (window.scanManager) {
            window.scanManager.downloadReport(scanId, format);
        }
    },
    
    createProject: function() {
        const name = document.getElementById('projectName')?.value;
        const description = document.getElementById('projectDescription')?.value || '';
        
        if (!name) {
            alert('Пожалуйста, введите название проекта');
            return;
        }
        
        createProject(name, description)
            .then(() => {
                closeAllModals();
                showToast('Проект успешно создан', 'success');
                // Reload projects list
                if (typeof loadProjects === 'function') {
                    loadProjects();
                }
            })
            .catch(error => {
                showToast('Ошибка при создании проекта: ' + error.message, 'error');
            });
    }
};