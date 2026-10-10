let breakdownChart = null;

function initChart() {
    const ctx = document.getElementById('threatBreakdownChart').getContext('2d');
    breakdownChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['SQL Injection', 'Cross-Site Scripting (XSS)', 'Command / Traversal', 'BOLA / IDOR Violation', 'CSIC Anomalous'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#eab308', '#3b82f6'],
                borderWidth: 2,
                borderColor: '#111827'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#9ca3af', font: { size: 10 } } }
            }
        }
    });
}

async function loadStats() {
    try {
        const res = await fetch('/api/threats/stats');
        const data = await res.json();

        const totalEl = document.getElementById('metric-total');
        if (totalEl) totalEl.innerText = data.total_inspected || 0;

        const blockedEl = document.getElementById('metric-blocked');
        if (blockedEl) blockedEl.innerText = data.total_blocked || 0;

        const allowedEl = document.getElementById('metric-allowed');
        if (allowedEl) allowedEl.innerText = data.total_allowed || 0;

        if (breakdownChart) {
            breakdownChart.data.datasets[0].data = [
                data.breakdown.SQLi || 0,
                data.breakdown.XSS || 0,
                data.breakdown.Command_Traversal || 0,
                data.breakdown.BOLA_IDOR || 0,
                data.breakdown.Anomalous_Attack || 0
            ];
            breakdownChart.update();
        }

        const tbody = document.getElementById('incident-tbody');
        if (data.recent_incidents && data.recent_incidents.length > 0) {
            tbody.innerHTML = '';
            data.recent_incidents.forEach(inc => prependIncidentRow(inc, false));
        }
    } catch (e) {
        console.error("Failed to load stats:", e);
    }
}

function prependIncidentRow(inc, isNew = true) {
    const tbody = document.getElementById('incident-tbody');
    if (tbody.querySelector('.empty-state')) {
        tbody.innerHTML = '';
    }

    const actionText = inc.action || inc.action_taken || 'ALLOWED';
    const isBlocked = (actionText === 'BLOCKED');

    const badgeClass = isBlocked ? 'badge-blocked' : 'badge-allowed';
    const rowClass = isNew ? (isBlocked ? 'new-incident-row' : 'new-incident-allowed') : '';

    const row = document.createElement('tr');
    if (rowClass) row.classList.add(rowClass);

    row.innerHTML = `
        <td>${inc.timestamp || new Date().toLocaleTimeString()}</td>
        <td><code>${inc.ip || inc.client_ip}</code></td>
        <td><code>${inc.path}</code></td>
        <td><span class="badge badge-type">${inc.type || inc.attack_type}</span></td>
        <td><strong>${inc.confidence}</strong></td>
        <td><span class="code-snippet">${escapeHtml(inc.payload || inc.payload_sample || '')}</span></td>
        <td><span class="badge ${badgeClass}">${actionText}</span></td>
    `;

    tbody.insertBefore(row, tbody.firstChild);

    while (tbody.children.length > 35) {
        tbody.removeChild(tbody.lastChild);
    }
}

function escapeHtml(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/threats`);
    const statusEl = document.getElementById('connection-status');

    ws.onopen = () => {
        statusEl.innerText = "Gateway Online (Live)";
    };

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.event === 'TRAFFIC_EVENT') {
            const totalEl = document.getElementById('metric-total');
            if (totalEl) totalEl.innerText = parseInt(totalEl.innerText || '0') + 1;

            if (msg.action_taken === 'BLOCKED') {
                const blockedEl = document.getElementById('metric-blocked');
                if (blockedEl) blockedEl.innerText = parseInt(blockedEl.innerText || '0') + 1;
            } else {
                const allowedEl = document.getElementById('metric-allowed');
                allowedEl.innerText = parseInt(allowedEl.innerText || '0') + 1;
            }

            if (msg.latency_ms) {
                const latEl = document.getElementById('metric-latency');
                if (latEl) latEl.innerText = `${msg.latency_ms} ms`;
            }

            prependIncidentRow(msg, true);
            loadStats();
        }
    };

    ws.onclose = () => {
        statusEl.innerText = "Reconnecting...";
        setTimeout(connectWebSocket, 3000);
    };
}

// Interactive Attack Simulator
async function sendSimulatedRequest(isAttack) {
    const resultBox = document.getElementById('sim-result-box');
    const input = document.getElementById('sim-payload');
    let payload = input.value;

    if (!isAttack) {
        payload = "laptop_stand_aluminum";
        input.value = payload;
    }

    resultBox.innerText = `Sending: /api/products?search=${payload} ...`;

    try {
        const response = await fetch(`/api/products?search=${encodeURIComponent(payload)}`);
        const data = await response.json();

        if (response.status === 403) {
            resultBox.innerHTML = `<span style="color: #ef4444;">🚨 <strong>HTTP 403 BLOCKED!</strong> ${data.threat_type} (${data.confidence}) in ${data.inspection_latency}</span>`;
        } else {
            resultBox.innerHTML = `<span style="color: #10b981;">✅ <strong>HTTP 200 ALLOWED!</strong> Benign request passed through.</span>`;
        }
    } catch (err) {
        resultBox.innerText = `Error: ${err}`;
    }
}

// BOLA / IDOR Specific Simulator
async function sendBolaRequest(isAttack) {
    const resultBox = document.getElementById('sim-result-box');
    
    // Alice's Token trying to access:
    // If attack: Bob's order (201) -> BOLA!
    // If clean: Alice's own order (101) -> ALLOWED!
    const orderId = isAttack ? "201" : "101";
    const headers = { "Authorization": "Bearer token_alice" };

    resultBox.innerText = `[Alice] Requesting: GET /api/orders/${orderId} ...`;

    try {
        const response = await fetch(`/api/orders/${orderId}`, { headers: headers });
        const data = await response.json();

        if (response.status === 403) {
            resultBox.innerHTML = `<span style="color: #eab308;">🚨 <strong>HTTP 403 BOLA BLOCKED!</strong> ${data.threat_type} (${data.confidence})</span>`;
        } else {
            resultBox.innerHTML = `<span style="color: #10b981;">✅ <strong>HTTP 200 ALLOWED!</strong> Alice authorized to access Order ${orderId}.</span>`;
        }
    } catch (err) {
        resultBox.innerText = `Error: ${err}`;
    }
}

window.addEventListener('DOMContentLoaded', () => {
    initChart();
    loadStats();
    connectWebSocket();
});