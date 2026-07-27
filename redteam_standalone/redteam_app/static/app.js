// RedTeam Dashboard JavaScript

const API_BASE = '/api';

// DOM Elements
let currentOperationId = null;

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    loadDashboard();
    loadOperations();
    
    // Event listeners
    const createOpBtn = document.getElementById('createOpBtn');
    if (createOpBtn) {
        createOpBtn.addEventListener('click', showCreateOperationForm);
    }
});

// Load dashboard data
async function loadDashboard() {
    try {
        const response = await fetch(`${API_BASE}/dashboard`);
        const data = await response.json();
        updateDashboardStats(data);
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

// Update dashboard statistics
function updateDashboardStats(data) {
    const summary = data.summary || {};
    
    document.getElementById('totalOps')?.innerText = summary.total_operations || 0;
    document.getElementById('totalFindings')?.innerText = summary.total_findings || 0;
    document.getElementById('totalTargets')?.innerText = summary.total_targets || 0;
}

// Load all operations
async function loadOperations() {
    try {
        const response = await fetch(`${API_BASE}/operations`);
        const data = await response.json();
        displayOperations(data.operations || []);
    } catch (error) {
        console.error('Error loading operations:', error);
        showAlert('Failed to load operations', 'error');
    }
}

// Display operations in table
function displayOperations(operations) {
    const tbody = document.querySelector('table tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (operations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No operations yet</td></tr>';
        return;
    }
    
    operations.forEach(op => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><code>${op.operation_id}</code></td>
            <td>${op.operation_name}</td>
            <td><span class="status ${op.status}">${op.status}</span></td>
            <td>${op.phase || 'N/A'}</td>
            <td>${op.findings_count || 0}</td>
            <td>
                <button class="btn small" onclick="viewOperation('${op.operation_id}')">View</button>
                <button class="btn small secondary" onclick="manageOperation('${op.operation_id}')">Manage</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Show create operation form
function showCreateOperationForm() {
    const opName = prompt('Enter operation name:');
    if (!opName) return;
    
    const targets = prompt('Enter target(s) (comma-separated):');
    if (!targets) return;
    
    createOperation(opName, targets.split(',').map(t => t.trim()));
}

// Create new operation
async function createOperation(name, targets) {
    try {
        const response = await fetch(`${API_BASE}/operations`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                operation_name: name,
                target_scope: { targets: targets },
                rules_of_engagement: {
                    allowed_methods: ['reconnaissance', 'scanning', 'exploitation'],
                    authorized_for_destructive: false
                }
            })
        });
        
        const data = await response.json();
        if (response.ok) {
            showAlert(`Operation ${data.operation_id} created successfully`, 'success');
            loadOperations();
            loadDashboard();
        } else {
            showAlert('Failed to create operation', 'error');
        }
    } catch (error) {
        console.error('Error creating operation:', error);
        showAlert('Error creating operation', 'error');
    }
}

// View operation details
async function viewOperation(operationId) {
    currentOperationId = operationId;
    
    try {
        const response = await fetch(`${API_BASE}/operations/${operationId}`);
        const op = await response.json();
        
        // Update operation details panel
        displayOperationDetails(op);
        
        // Load findings
        const findingsResponse = await fetch(`${API_BASE}/operations/${operationId}/findings`);
        const findingsData = await findingsResponse.json();
        displayFindings(findingsData.findings || []);
        
    } catch (error) {
        console.error('Error viewing operation:', error);
        showAlert('Failed to load operation details', 'error');
    }
}

// Display operation details
function displayOperationDetails(op) {
    const detailsPanel = document.getElementById('operationDetails');
    if (!detailsPanel) return;
    
    detailsPanel.innerHTML = `
        <h3>${op.operation_name}</h3>
        <p><strong>Operation ID:</strong> <code>${op.attack_id}</code></p>
        <p><strong>Status:</strong> <span class="status ${op.status}">${op.status}</span></p>
        <p><strong>Phase:</strong> ${op.phase || 'N/A'}</p>
        <p><strong>Targets:</strong> ${(op.target_scope?.targets || []).join(', ')}</p>
        <p><strong>Created:</strong> ${op.created_at || 'N/A'}</p>
        <div class="mt-20 gap-10 flex">
            <button class="btn success" onclick="approveOperation('${op.attack_id}')" 
                    ${op.status === 'approved' || op.status === 'running' ? 'disabled' : ''}>
                Approve
            </button>
            <button class="btn" onclick="startOperation('${op.attack_id}')" 
                    ${op.status !== 'approved' ? 'disabled' : ''}>
                Start
            </button>
            <button class="btn success small" onclick="addFinding('${op.attack_id}')">
                Add Finding
            </button>
        </div>
    `;
}

// Display findings
function displayFindings(findings) {
    const findingsPanel = document.getElementById('findingsPanel');
    if (!findingsPanel) return;
    
    if (findings.length === 0) {
        findingsPanel.innerHTML = '<p class="text-center">No findings yet</p>';
        return;
    }
    
    let html = '<table><thead><tr><th>Title</th><th>Severity</th><th>Evidence</th><th>Date</th></tr></thead><tbody>';
    findings.forEach(finding => {
        html += `
            <tr>
                <td>${finding.title}</td>
                <td><span class="severity ${finding.severity}">${finding.severity}</span></td>
                <td>${finding.evidence}</td>
                <td>${new Date(finding.timestamp).toLocaleString()}</td>
            </tr>
        `;
    });
    html += '</tbody></table>';
    findingsPanel.innerHTML = html;
}

// Approve operation
async function approveOperation(operationId) {
    const analystId = prompt('Enter analyst ID (optional):') || 'analyst-001';
    const justification = prompt('Enter justification:') || 'Security assessment';
    
    try {
        const response = await fetch(`${API_BASE}/operations/${operationId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                analyst_id: analystId,
                justification: justification
            })
        });
        
        const data = await response.json();
        if (response.ok && data.approved) {
            showAlert('Operation approved successfully', 'success');
            loadOperations();
            viewOperation(operationId);
        } else {
            showAlert('Approval failed', 'error');
        }
    } catch (error) {
        console.error('Error approving operation:', error);
        showAlert('Error approving operation', 'error');
    }
}

// Start operation
async function startOperation(operationId) {
    const analystId = prompt('Enter analyst ID (optional):') || 'analyst-001';
    
    try {
        const response = await fetch(`${API_BASE}/operations/${operationId}/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ analyst_id: analystId })
        });
        
        const data = await response.json();
        if (response.ok && data.started) {
            showAlert('Operation started successfully', 'success');
            loadOperations();
            viewOperation(operationId);
        } else {
            showAlert('Failed to start operation', 'error');
        }
    } catch (error) {
        console.error('Error starting operation:', error);
        showAlert('Error starting operation', 'error');
    }
}

// Add finding
async function addFinding(operationId) {
    const title = prompt('Finding title:');
    if (!title) return;
    
    const severity = prompt('Severity (critical/high/medium/low/info):', 'medium');
    const evidence = prompt('Evidence/Description:') || '';
    
    try {
        const response = await fetch(`${API_BASE}/operations/${operationId}/findings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                title: title,
                severity: severity,
                evidence: evidence
            })
        });
        
        if (response.ok) {
            showAlert('Finding added successfully', 'success');
            viewOperation(operationId);
            loadDashboard();
        } else {
            showAlert('Failed to add finding', 'error');
        }
    } catch (error) {
        console.error('Error adding finding:', error);
        showAlert('Error adding finding', 'error');
    }
}

// Manage operation (phase/status changes)
async function manageOperation(operationId) {
    const action = prompt('Enter action (phase/view/report):', 'view');
    
    if (action === 'phase') {
        const newPhase = prompt('Enter new phase (RECONNAISSANCE/SCANNING/EXPLOITATION/POST_EXPLOITATION/PERSISTENCE/EXFILTRATION/CLEANUP):');
        if (!newPhase) return;
        
        const analystId = prompt('Enter analyst ID (optional):') || 'analyst-001';
        
        try {
            const response = await fetch(`${API_BASE}/operations/${operationId}/phase`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    phase: newPhase.toUpperCase(),
                    analyst_id: analystId
                })
            });
            
            if (response.ok) {
                showAlert('Phase changed successfully', 'success');
                viewOperation(operationId);
            } else {
                showAlert('Failed to change phase', 'error');
            }
        } catch (error) {
            showAlert('Error changing phase', 'error');
        }
    } else if (action === 'report') {
        generateReport(operationId);
    } else {
        viewOperation(operationId);
    }
}

// Generate report
async function generateReport(operationId) {
    try {
        const response = await fetch(`${API_BASE}/operations/${operationId}/report`);
        const report = await response.json();
        
        const reportWindow = window.open();
        reportWindow.document.write(`
            <html>
            <head>
                <title>RedTeam Report - ${report.operation_name}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                    .report { background: white; padding: 20px; border-radius: 8px; }
                    h1 { color: #0f2f5a; }
                    h2 { color: #1a5fb4; margin-top: 20px; border-bottom: 2px solid #1a5fb4; padding-bottom: 10px; }
                    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background: #f0f0f0; }
                    .severity-critical { color: #d13438; }
                    .severity-high { color: #ffb900; }
                </style>
            </head>
            <body>
                <div class="report">
                    <h1>Red Team Assessment Report</h1>
                    <p><strong>Operation:</strong> ${report.operation_name}</p>
                    <p><strong>Operation ID:</strong> ${report.operation_id}</p>
                    <p><strong>Status:</strong> ${report.status}</p>
                    <p><strong>Phase:</strong> ${report.phase || 'N/A'}</p>
                    <p><strong>Created:</strong> ${report.created_at || 'N/A'}</p>
                    
                    <h2>Targets</h2>
                    <p>${(report.target_scope?.targets || []).join(', ')}</p>
                    
                    <h2>Findings (${report.findings.length})</h2>
                    ${report.findings.length > 0 ? `
                        <table>
                            <thead>
                                <tr><th>Title</th><th>Severity</th><th>Evidence</th></tr>
                            </thead>
                            <tbody>
                                ${report.findings.map(f => `
                                    <tr>
                                        <td>${f.title}</td>
                                        <td class="severity-${f.severity}">${f.severity}</td>
                                        <td>${f.evidence}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    ` : '<p>No findings</p>'}
                </div>
            </body>
            </html>
        `);
        reportWindow.document.close();
    } catch (error) {
        showAlert('Failed to generate report', 'error');
    }
}

// Show alert message
function showAlert(message, type = 'info') {
    const alertsContainer = document.getElementById('alerts');
    if (!alertsContainer) {
        // Create alerts container if it doesn't exist
        const container = document.body;
        const div = document.createElement('div');
        div.id = 'alerts';
        div.style.position = 'fixed';
        div.style.top = '20px';
        div.style.right = '20px';
        div.style.zIndex = '9999';
        container.appendChild(div);
        alertsContainer = div;
    }
    
    const alert = document.createElement('div');
    alert.className = `alert ${type}`;
    alert.textContent = message;
    alert.style.animation = 'slideIn 0.3s ease';
    
    alertsContainer.appendChild(alert);
    
    // Auto-remove after 5 seconds
    setTimeout(() => alert.remove(), 5000);
}

// Add slideIn animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style);

// Refresh operations every 10 seconds
setInterval(() => {
    loadOperations();
    loadDashboard();
}, 10000);
