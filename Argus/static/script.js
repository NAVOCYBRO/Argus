// Global variables
let currentScanId = null;
let chatHistory = [];
let aiAssistantAvailable = false;

// Toast notification system
function showToast(type, message) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        info: 'info-circle',
        warning: 'exclamation-triangle'
    };
    
    toast.innerHTML = `
        <div class="toast-header">
            <span class="toast-title">
                <i class="fas fa-${icons[type]}"></i>
                ${type.charAt(0).toUpperCase() + type.slice(1)}
            </span>
            <button class="toast-close" onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="toast-message">${message}</div>
    `;
    
    container.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.remove();
        }
    }, 5000);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    checkAIAssistantStatus();
    updateStats();
});

async function checkAIAssistantStatus() {
    try {
        const response = await fetch('/ai/status');
        const data = await response.json();
        
        aiAssistantAvailable = data.available;
        const statusElement = document.getElementById('aiStatus');
        
        if (aiAssistantAvailable) {
            statusElement.textContent = 'Online';
            statusElement.style.color = 'var(--low)';
            showToast('success', 'AI Assistant connected successfully');
        } else {
            statusElement.textContent = 'Offline';
            statusElement.style.color = 'var(--critical)';
            showToast('info', 'AI Assistant is offline. Set GROQ_API_KEY for AI features.');
        }
    } catch (error) {
        console.error('Failed to check AI status:', error);
        document.getElementById('aiStatus').textContent = 'Error';
        document.getElementById('aiStatus').style.color = 'var(--critical)';
    }
}

async function updateStats() {
    // Update stats from localStorage or API
    const totalScans = localStorage.getItem('totalScans') || 0;
    const criticalFindings = localStorage.getItem('criticalFindings') || 0;
    const avgScanTime = localStorage.getItem('avgScanTime') || '0s';
    
    document.getElementById('totalScans').textContent = totalScans;
    document.getElementById('criticalFindings').textContent = criticalFindings;
    document.getElementById('avgScanTime').textContent = avgScanTime;
}

// Scan functionality
document.getElementById('scanForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const target = document.getElementById('target').value;
    if (!target) {
        showToast('error', 'Please enter a target to scan');
        return;
    }
    
    const scanButton = document.getElementById('scanButton');
    const progressSection = document.getElementById('progressSection');
    const progressFill = document.getElementById('progressFill');
    const progressPercent = document.getElementById('progressPercent');
    const scanDuration = document.getElementById('scanDuration');
    
    // Show progress section
    progressSection.style.display = 'block';
    progressSection.scrollIntoView({ behavior: 'smooth' });
    scanButton.disabled = true;
    scanButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>Scanning...</span>';
    
    // Reset progress
    progressFill.style.width = '0%';
    progressPercent.textContent = '0%';
    scanDuration.textContent = '0s';
    
    const startTime = Date.now();
    
    // Update duration timer
    const durationInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        scanDuration.textContent = `${elapsed}s`;
    }, 1000);
    
    try {
        // Get form data
        const formData = new FormData(this);
        const scanOptions = {
            full_scan: formData.get('full_scan') === 'on',
            service_detect: formData.get('service_detect') === 'on',
            cve_check: formData.get('cve_check') === 'on',
            web_scan: formData.get('web_scan') === 'on',
            ai_analysis: formData.get('ai_analysis') === 'on'
        };
        
        // Start scan
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                'target': target,
                'full_scan': scanOptions.full_scan ? 'on' : 'off',
                'service_detect': scanOptions.service_detect ? 'on' : 'off',
                'cve_check': scanOptions.cve_check ? 'on' : 'off',
                'web_scan': scanOptions.web_scan ? 'on' : 'off',
                'ai_analysis': scanOptions.ai_analysis ? 'on' : 'off'
            })
        });
        
        const data = await response.json();
        
        if (data.status === 'scan_started') {
            currentScanId = data.scan_id;
            showToast('success', `Scan started for ${target}`);
            addProgressStep('Scan queued and started', 'pending');
            pollScanProgress(data.scan_id, durationInterval);
        } else {
            throw new Error(data.error || 'Failed to start scan');
        }
        
    } catch (error) {
        console.error('Scan error:', error);
        showToast('error', `Scan failed: ${error.message}`);
        scanButton.disabled = false;
        scanButton.innerHTML = '<i class="fas fa-play-circle"></i><span>Start Security Scan</span>';
        clearInterval(durationInterval);
    }
});

async function pollScanProgress(scanId, durationInterval) {
    const progressFill = document.getElementById('progressFill');
    const progressPercent = document.getElementById('progressPercent');
    const progressSteps = document.getElementById('progressSteps');
    const scanButton = document.getElementById('scanButton');
    
    const pollInterval = setInterval(async () => {
        try {
            const response = await fetch(`/scan/status/${scanId}`);
            const data = await response.json();
            
            if (data.status === 'running') {
                const progress = data.progress || 0;
                progressFill.style.width = `${progress}%`;
                progressPercent.textContent = `${progress}%`;
                
                if (data.current_step) {
                    addProgressStep(data.current_step, 'active');
                }
                
            } else if (data.status === 'completed') {
                clearInterval(pollInterval);
                clearInterval(durationInterval);
                progressFill.style.width = '100%';
                progressPercent.textContent = '100%';
                addProgressStep('Analysis complete', 'completed');
                
                scanButton.disabled = false;
                scanButton.innerHTML = '<i class="fas fa-play-circle"></i><span>Start Security Scan</span>';
                
                // Update stats
                updateLocalStats();
                
                // Get results
                setTimeout(() => getScanResults(scanId), 1000);
                
            } else if (data.status === 'error') {
                clearInterval(pollInterval);
                clearInterval(durationInterval);
                showToast('error', `Scan failed: ${data.error}`);
                addProgressStep(`Error: ${data.error}`, 'error');
                scanButton.disabled = false;
                scanButton.innerHTML = '<i class="fas fa-play-circle"></i><span>Start Security Scan</span>';
            }
            
        } catch (error) {
            console.error('Polling error:', error);
        }
    }, 1000);
}

function addProgressStep(stepText, status) {
    const progressSteps = document.getElementById('progressSteps');
    const existingSteps = progressSteps.querySelectorAll('.progress-step');
    
    // Update existing active step to completed
    existingSteps.forEach(step => {
        if (step.classList.contains('active')) {
            step.classList.remove('active');
            step.classList.add('completed');
        }
    });
    
    // Add new step
    const stepDiv = document.createElement('div');
    stepDiv.className = `progress-step ${status}`;
    
    const icon = status === 'completed' ? 'check' : 
                 status === 'error' ? 'times' : 
                 'sync-alt';
    
    stepDiv.innerHTML = `
        <div class="step-icon">
            <i class="fas fa-${icon} ${status === 'active' ? 'fa-spin' : ''}"></i>
        </div>
        <div class="step-text">${stepText}</div>
        <div class="step-time">${new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</div>
    `;
    
    progressSteps.appendChild(stepDiv);
    progressSteps.scrollTop = progressSteps.scrollHeight;
}

async function getScanResults(scanId) {
    try {
        const response = await fetch(`/scan/results/${scanId}`);
        const data = await response.json();
        
        if (data.status === 'completed') {
            displayResults(data);
            showToast('success', 'Scan completed successfully');
        } else {
            setTimeout(() => getScanResults(scanId), 2000);
        }
    } catch (error) {
        console.error('Error getting results:', error);
        showToast('error', 'Failed to get scan results');
    }
}

// Display results
function displayResults(data) {
    const resultsContainer = document.getElementById('resultsContainer');
    const resultsSummary = document.getElementById('resultsSummary');
    const resultsTarget = document.getElementById('resultsTarget');
    const resultsTime = document.getElementById('resultsTime');
    
    // Update header
    resultsTarget.textContent = data.target;
    resultsTime.textContent = new Date(data.timestamp).toLocaleString();
    
    // Show results container
    resultsContainer.style.display = 'block';
    resultsContainer.scrollIntoView({ behavior: 'smooth' });
    
    // Build summary
    const summary = data.summary || {};
    resultsSummary.innerHTML = `
        <div class="summary-card critical">
            <div class="summary-header">
                <h4>Critical</h4>
                <span class="severity-badge critical">CRITICAL</span>
            </div>
            <div class="summary-count">${summary.critical || 0}</div>
            <div class="summary-label">Immediate attention required</div>
        </div>
        <div class="summary-card high">
            <div class="summary-header">
                <h4>High</h4>
                <span class="severity-badge high">HIGH</span>
            </div>
            <div class="summary-count">${summary.high || 0}</div>
            <div class="summary-label">Address within 48 hours</div>
        </div>
        <div class="summary-card medium">
            <div class="summary-header">
                <h4>Medium</h4>
                <span class="severity-badge medium">MEDIUM</span>
            </div>
            <div class="summary-count">${summary.medium || 0}</div>
            <div class="summary-label">Schedule for patching</div>
        </div>
        <div class="summary-card low">
            <div class="summary-header">
                <h4>Low</h4>
                <span class="severity-badge low">LOW</span>
            </div>
            <div class="summary-count">${summary.low || 0}</div>
            <div class="summary-label">Consider in maintenance</div>
        </div>
        <div class="summary-card risk-score-card">
            <div class="risk-score">
                <div class="score-circle">
                    <svg>
                        <circle class="score-bg" cx="60" cy="60" r="50"></circle>
                        <circle class="score-progress" cx="60" cy="60" r="50" 
                                stroke-dashoffset="${314 - (314 * (summary.risk_score || 0)) / 100}"></circle>
                    </svg>
                    <div class="score-value">${summary.risk_score || 0}</div>
                </div>
                <div class="score-label">Risk Score</div>
                <div class="score-desc">${summary.risk_level || 'LOW'} risk level</div>
            </div>
        </div>
    `;
    
    // Update tabs content
    updateOverviewTab(data);
    updateNetworkTab(data);
    updateVulnerabilitiesTab(data);
    updateRecommendationsTab(data);
    updateAIAnalysisTab(data);
    
    // Show overview tab by default
    showResultsTab('overview');
}

function updateOverviewTab(data) {
    const tab = document.getElementById('overviewTab');
    const summary = data.summary || {};
    
    tab.innerHTML = `
        <div class="section">
            <h4><i class="fas fa-info-circle"></i> Executive Summary</h4>
            <p>Security assessment of <strong>${data.target}</strong> completed on ${new Date(data.timestamp).toLocaleString()}.</p>
            
            <div class="stats-grid" style="margin-top: 20px;">
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon">
                            <i class="fas fa-door-open"></i>
                        </div>
                    </div>
                    <span class="stat-value">${data.open_ports?.length || 0}</span>
                    <span class="stat-label">Open Ports</span>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon">
                            <i class="fas fa-server"></i>
                        </div>
                    </div>
                    <span class="stat-value">${data.services?.length || 0}</span>
                    <span class="stat-label">Services</span>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon">
                            <i class="fas fa-bug"></i>
                        </div>
                    </div>
                    <span class="stat-value">${summary.total_findings || 0}</span>
                    <span class="stat-label">Total Findings</span>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <div class="stat-icon">
                            <i class="fas fa-database"></i>
                        </div>
                    </div>
                    <span class="stat-value">${summary.cves_found || 0}</span>
                    <span class="stat-label">CVEs Found</span>
                </div>
            </div>
        </div>
    `;
}

function updateNetworkTab(data) {
    const tab = document.getElementById('networkTab');
    
    let portsHTML = '';
    if (data.open_ports && data.open_ports.length > 0) {
        portsHTML = `
            <div class="section">
                <h4><i class="fas fa-door-open"></i> Open Ports (${data.open_ports.length})</h4>
                <div class="ports-display">
                    ${data.open_ports.map(port => `<span class="port-badge">${port}</span>`).join('')}
                </div>
            </div>
        `;
    }
    
    let servicesHTML = '';
    if (data.services && data.services.length > 0) {
        servicesHTML = `
            <div class="section">
                <h4><i class="fas fa-server"></i> Detected Services (${data.services.length})</h4>
                <div class="services-table">
                    <div class="table-header">
                        <div class="table-header-cell">Port</div>
                        <div class="table-header-cell">Service</div>
                        <div class="table-header-cell">Version</div>
                        <div class="table-header-cell">Product</div>
                        <div class="table-header-cell">Protocol</div>
                    </div>
                    <div id="servicesContainer">
                        ${data.services.map(service => `
                            <div class="table-row">
                                <div class="table-cell">${service.port}</div>
                                <div class="table-cell">
                                    <span class="service-badge">${service.name}</span>
                                </div>
                                <div class="table-cell">${service.version || 'Unknown'}</div>
                                <div class="table-cell">${service.product || '-'}</div>
                                <div class="table-cell">
                                    <span class="protocol-badge">${service.protocol || 'TCP'}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    }
    
    tab.innerHTML = portsHTML + servicesHTML;
}

function updateVulnerabilitiesTab(data) {
    const tab = document.getElementById('vulnerabilitiesTab');
    const vulns = data.vulnerabilities || {};
    const cves = data.cves || {};
    
    let vulnHTML = '<div class="vulnerabilities-grid">';
    
    // Critical vulnerabilities
    if (vulns.critical_findings && vulns.critical_findings.length > 0) {
        vulns.critical_findings.forEach(finding => {
            vulnHTML += `
                <div class="vulnerability-card critical">
                    <div class="vulnerability-header">
                        <span class="vulnerability-id">Critical Vulnerability</span>
                        <span class="vulnerability-severity critical">CRITICAL</span>
                    </div>
                    <p class="vulnerability-description">
                        ${finding.issue || 'Critical security issue detected'}
                    </p>
                    <div class="vulnerability-meta">
                        <span class="meta-item">
                            <i class="fas fa-server"></i>
                            ${finding.service || 'Unknown'}
                        </span>
                        <span class="meta-item">
                            <i class="fas fa-door-open"></i>
                            Port ${finding.port || 'N/A'}
                        </span>
                    </div>
                </div>
            `;
        });
    }
    
    // CVE vulnerabilities
    Object.entries(cves).forEach(([service, cveList]) => {
        if (cveList && cveList.length > 0) {
            cveList.forEach(cve => {
                if (cve.severity === 'CRITICAL' || cve.severity === 'HIGH') {
                    vulnHTML += `
                        <div class="vulnerability-card ${cve.severity.toLowerCase()}">
                            <div class="vulnerability-header">
                                <span class="vulnerability-id">${cve.id}</span>
                                <span class="vulnerability-severity ${cve.severity.toLowerCase()}">
                                    ${cve.severity}
                                </span>
                            </div>
                            <p class="vulnerability-description">
                                ${cve.description || 'No description available'}
                            </p>
                            <div class="vulnerability-meta">
                                <span class="meta-item">
                                    <i class="fas fa-server"></i>
                                    ${service}
                                </span>
                                ${cve.cvss_score ? `
                                    <span class="meta-item">
                                        <i class="fas fa-chart-bar"></i>
                                        CVSS ${cve.cvss_score}
                                    </span>
                                ` : ''}
                            </div>
                        </div>
                    `;
                }
            });
        }
    });
    
    vulnHTML += '</div>';
    
    if (vulnHTML === '<div class="vulnerabilities-grid"></div>') {
        vulnHTML = '<p>No critical or high vulnerabilities found.</p>';
    }
    
    tab.innerHTML = vulnHTML;
}

function updateRecommendationsTab(data) {
    const tab = document.getElementById('recommendationsTab');
    
    if (data.recommendations && data.recommendations.length > 0) {
        let recommendationsHTML = '<div class="vulnerabilities-grid">';
        
        data.recommendations.forEach(rec => {
            recommendationsHTML += `
                <div class="vulnerability-card ${rec.severity}">
                    <div class="vulnerability-header">
                        <span class="vulnerability-id">${rec.title}</span>
                        <span class="vulnerability-severity ${rec.severity}">
                            ${rec.severity.toUpperCase()}
                        </span>
                    </div>
                    <p class="vulnerability-description">
                        ${rec.description}
                    </p>
                    ${rec.steps && rec.steps.length > 0 ? `
                        <div class="vulnerability-meta" style="flex-direction: column; align-items: start; gap: 8px;">
                            <strong>Steps:</strong>
                            <ul style="margin: 0; padding-left: 20px;">
                                ${rec.steps.map(step => `<li>${step}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            `;
        });
        
        recommendationsHTML += '</div>';
        tab.innerHTML = recommendationsHTML;
    } else {
        tab.innerHTML = '<p>No recommendations available.</p>';
    }
}

function updateAIAnalysisTab(data) {
    const tab = document.getElementById('aiTab');
    
    if (data.ai_analysis) {
        tab.innerHTML = `
            <div class="ai-response">
                ${marked.parse(data.ai_analysis)}
            </div>
        `;
    } else {
        tab.innerHTML = `
            <p>No AI analysis available.</p>
            <button class="scan-button" style="margin-top: 20px;" onclick="generateAIAnalysis()">
                <i class="fas fa-robot"></i>
                <span>Generate AI Analysis</span>
            </button>
        `;
    }
}

function showResultsTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(`${tabName}Tab`).classList.add('active');
    document.querySelector(`.tab-btn[onclick="showResultsTab('${tabName}')"]`).classList.add('active');
}

// AI Chat functionality
async function sendChatMessage() {
    if (!aiAssistantAvailable) {
        showToast('error', 'AI Assistant is offline. Please check your API key configuration.');
        return;
    }
    
    const chatInput = document.getElementById('chatInput');
    const message = chatInput.value.trim();
    
    if (!message) return;
    
    // Add user message
    addChatMessage('user', message);
    chatInput.value = '';
    
    // Show typing indicator
    const chatMessages = document.getElementById('chatMessages');
    const typingIndicator = document.createElement('div');
    typingIndicator.className = 'message ai';
    typingIndicator.innerHTML = `
        <div class="message-content">
            <strong>Security Assistant:</strong> <i class="fas fa-spinner fa-spin"></i> Analyzing...
        </div>
    `;
    chatMessages.appendChild(typingIndicator);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    
    try {
        const response = await fetch('/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: message,
                history: chatHistory,
                scan_id: currentScanId
            })
        });
        
        const data = await response.json();
        chatMessages.removeChild(typingIndicator);
        
        if (data.status === 'success') {
            addChatMessage('ai', data.response);
            chatHistory.push({ role: 'user', content: message });
            chatHistory.push({ role: 'assistant', content: data.response });
            if (chatHistory.length > 10) chatHistory = chatHistory.slice(-10);
        } else {
            addChatMessage('ai', `Error: ${data.error || 'Unknown error'}`);
        }
        
    } catch (error) {
        chatMessages.removeChild(typingIndicator);
        addChatMessage('ai', `Connection error: ${error.message}`);
        showToast('error', 'Failed to get AI response');
    }
}

function addChatMessage(role, content) {
    const chatMessages = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${role}`;
    
    const name = role === 'user' ? 'You' : 'Security Assistant';
    
    messageDiv.innerHTML = `
        <div class="message-content">
            <strong>${name}:</strong> ${role === 'user' ? content : marked.parse(content)}
        </div>
    `;
    
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

async function generateAIAnalysis() {
    if (!aiAssistantAvailable) {
        showToast('error', 'AI Assistant is offline');
        return;
    }
    
    if (!currentScanId) {
        showToast('error', 'Please run a scan first');
        return;
    }
    
    try {
        const response = await fetch('/ai/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_id: currentScanId })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            updateAIAnalysisTab({ ai_analysis: data.analysis });
            showResultsTab('ai');
            showToast('success', 'AI analysis generated successfully');
        } else {
            showToast('error', `Failed to generate analysis: ${data.error}`);
        }
    } catch (error) {
        showToast('error', `Failed to generate analysis: ${error.message}`);
    }
}

function updateLocalStats() {
    // Update localStorage with new stats
    const totalScans = parseInt(localStorage.getItem('totalScans') || 0) + 1;
    localStorage.setItem('totalScans', totalScans);
    
    // Update UI
    document.getElementById('totalScans').textContent = totalScans;
    
    // You would update other stats based on scan results
    // This is a simplified example
}
