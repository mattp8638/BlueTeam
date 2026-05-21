document.addEventListener('DOMContentLoaded', () => {
    
    // --- Navigation Logic ---
    const navItems = document.querySelectorAll('.nav-links li');
    const sections = document.querySelectorAll('.view-section');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            // Update active nav
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            // Show target section
            const targetId = item.getAttribute('data-target');
            sections.forEach(s => s.classList.remove('active'));
            document.getElementById(targetId).classList.add('active');

            // Trigger data load if needed
            if(targetId === 'settings') loadSettings();
            if(targetId === 'quarantine') loadQuarantine();
        });
    });

    // --- Data Fetching ---
    function fetchStatus() {
        fetch('/api/status')
            .then(res => res.json())
            .then(data => {
                document.getElementById('stat-scanned').textContent = data.hashes_scanned.toLocaleString();
                document.getElementById('stat-blocked').textContent = data.malicious_found.toLocaleString();
            })
            .catch(err => console.error("Agent offline", err));
    }

    function loadSettings() {
        fetch('/api/config')
            .then(res => res.json())
            .then(data => {
                document.getElementById('agent-id').value = data.agent_id || '';
                document.getElementById('api-url').value = data.nerve_center_url || '';
            });
    }

    function loadQuarantine() {
        fetch('/api/quarantine')
            .then(res => res.json())
            .then(data => {
                const tbody = document.getElementById('quarantine-tbody');
                tbody.innerHTML = '';
                
                if(!data.files || data.files.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">Vault is empty</td></tr>';
                    return;
                }

                data.files.forEach(file => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${new Date(file.timestamp * 1000).toLocaleString()}</td>
                        <td>${file.original_path}</td>
                        <td style="color: var(--accent-red);">${file.reason}</td>
                        <td><button class="btn btn-secondary" style="padding: 6px 12px; font-size: 0.8rem;">Restore</button></td>
                    `;
                    tbody.appendChild(tr);
                });
            });
    }

    // --- Actions ---
    window.triggerScan = function(type) {
        const feedback = document.getElementById('scan-feedback');
        
        fetch('/api/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ type: type })
        })
        .then(res => res.json())
        .then(data => {
            feedback.textContent = data.message;
            feedback.className = `feedback-msg ${data.success ? 'success' : 'error'}`;
        });
    };

    document.getElementById('config-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const payload = {
            agent_id: document.getElementById('agent-id').value,
            nerve_center_url: document.getElementById('api-url').value
        };

        const feedback = document.getElementById('settings-feedback');
        feedback.className = 'feedback-msg hidden';

        fetch('/api/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        })
        .then(res => res.json())
        .then(data => {
            feedback.textContent = data.message || data.error;
            feedback.className = `feedback-msg ${data.success ? 'success' : 'error'}`;
        });
    });

    // Init
    fetchStatus();
    setInterval(fetchStatus, 5000); // Poll status every 5s
});
