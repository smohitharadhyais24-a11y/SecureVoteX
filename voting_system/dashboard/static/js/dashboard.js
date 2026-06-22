/* SecureVoteX™ - Dashboard Client JavaScript Engine */

// Global fetch interceptor to append CSRF token automatically
const originalFetch = window.fetch;
window.fetch = function (url, options) {
    options = options || {};
    const method = options.method ? options.method.toUpperCase() : 'GET';
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
        const csrfTokenMeta = document.querySelector('meta[name="csrf-token"]');
        if (csrfTokenMeta) {
            options.headers = options.headers || {};
            if (options.headers instanceof Headers) {
                options.headers.set('X-CSRFToken', csrfTokenMeta.getAttribute('content'));
            } else {
                options.headers['X-CSRFToken'] = csrfTokenMeta.getAttribute('content');
            }
        }
    }
    return originalFetch(url, options);
};

// Global XSS escape helper
function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>'"]/g, tag => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
    }[tag] || tag));
}

let currentChart = null;
let currentChartType = 'donut'; // 'donut', 'race', 'timeline'
let threatChart = null;

// Local Caches
let statsCache = {};
let currentCandidateData = {};
let timelineDataPoints = []; // rolling history of { time: HH:MM:SS, count: N }
let securityMetricsHistory = []; // history of { time: HH:MM:SS, replay: R, tamper: T, double: D }
let booths = {};
let serverUptime = 0;
let userRole = 'VIEWER';
let username = 'guest';

// Voter Registry tab controls
let votersList = [];
let voterFilterStatus = 'ALL';
let voterSearchQuery = '';
let voterCurrentPage = 1;
const voterPageSize = 10;
let voterSortField = 'name';
let voterSortAsc = true;

// Candidates Management tab controls
let candidatesList = [];
let candidateSearchQuery = '';
let candidateCurrentPage = 1;
const candidatePageSize = 6;

// Admin Management tab controls
let adminsList = [];

// Presentation mode interval
let presentationInterval = null;
const chartTypes = ['donut', 'race', 'timeline'];

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    init().catch(err => console.error('SecureVoteX init failed:', err));
});

// Setup document-wide listeners
document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
        if (document.body.classList.contains('presentation-active')) {
            exitPresentationMode();
        }
    }
});

async function init() {
    // 1. Fetch User Identity & Role
    try {
        const meResponse = await fetch('/api/auth/me');
        if (!meResponse.ok) {
            window.location.href = '/login';
            return;
        }
        const data = await meResponse.json();
        username = data.username;
        userRole = data.role;
        
        // Update welcome tags
        document.getElementById('session-username').textContent = username;
        document.getElementById('session-role-badge').textContent = userRole;
        document.getElementById('welcome-username').textContent = username;
        document.getElementById('welcome-role').textContent = userRole.replace('_', ' ');
        
        applyRBAC();
    } catch (err) {
        console.error(err);
        window.location.href = '/login';
        return;
    }

    // 1b. Fetch Initial Candidates list
    try {
        const candResponse = await fetch('/api/candidates');
        const data = await candResponse.json();
        candidatesList = data.candidates || [];
    } catch (err) {
        console.error('Failed to load initial candidates:', err);
    }

    // 2. Fetch Initial Statistics
    try {
        const statsResponse = await fetch('/api/dashboard/stats');
        const stats = await statsResponse.json();
        statsCache = stats;
        updateDashboardUI(stats);
    } catch (err) {
        console.error('Failed to load initial stats:', err);
    }

    // 3. Fetch Initial Audit Logs
    try {
        const auditResponse = await fetch('/api/audit');
        const data = await auditResponse.json();
        const logs = data.audit_log || [];
        logs.reverse().forEach(appendAuditLog);
    } catch (err) {
        console.error('Failed to load audit logs:', err);
    }

    // 4. Fetch Initial Health & Booths
    try {
        const healthResponse = await fetch('/api/health');
        const data = await healthResponse.json();
        const health = data.health || [];
        health.forEach(item => {
            if (item.component.startsWith('booth:')) {
                let free_heap = 0;
                let buffered_votes = 0;
                let firmware_version = 'v1.0.0';
                if (item.message) {
                    const parts = item.message.split(' | ');
                    parts.forEach(part => {
                        if (part.startsWith('FW:')) firmware_version = part.replace('FW:', '').trim();
                        if (part.startsWith('Heap:')) free_heap = parseInt(part.replace('Heap:', '').replace('B', '').trim()) || 0;
                        if (part.startsWith('Buffered:')) buffered_votes = parseInt(part.replace('Buffered:', '').trim()) || 0;
                    });
                }
                booths[item.component] = {
                    component: item.component,
                    status: item.status,
                    firmware_version,
                    free_heap,
                    buffered_votes,
                    fsm_state: item.status === 'ONLINE' ? 'IDLE' : 'OFFLINE',
                    current_voter: '',
                    rfid_status: 'IDLE',
                    fingerprint_status: 'IDLE',
                    lcd_status: item.status === 'ONLINE' ? 'Scan RFID' : 'Offline'
                };
            }
        });
        renderBoothCards();
    } catch (err) {
        console.error('Failed to load health status:', err);
    }

    // 5. Load Certificate Details
    if (userRole === 'SUPER_ADMIN' || userRole === 'AUDITOR') {
        loadCertificates();
    }

    // 6. Initialize default charts
    initChart();
    initSecurityChart();
    initCCChart();

    // 7. Connect Socket.IO
    initSocket();

    // 8. Start Timers
    startTimers();
}

function applyRBAC() {
    const roleTabs = {
        'SUPER_ADMIN': ['command_center', 'evaluator', 'dashboard', 'demo_workflow', 'election', 'voters', 'booths', 'security', 'audit', 'reports', 'health', 'certificates', 'architecture', 'settings'],
        'ELECTION_OFFICER': ['command_center', 'evaluator', 'dashboard', 'demo_workflow', 'election', 'voters', 'booths', 'reports', 'health', 'settings'],
        'AUDITOR': ['command_center', 'evaluator', 'dashboard', 'demo_workflow', 'security', 'audit', 'reports', 'health', 'certificates', 'architecture', 'settings'],
        'VIEWER': ['command_center', 'evaluator', 'dashboard', 'demo_workflow', 'booths', 'health', 'architecture', 'settings']
    };

    const allowed = roleTabs[userRole] || roleTabs['VIEWER'];
    
    // Hide/show links in sidebar
    document.querySelectorAll('.nav-link').forEach(link => {
        const tabName = link.getAttribute('data-tab');
        if (allowed.includes(tabName)) {
            link.classList.remove('hidden');
        } else {
            link.classList.add('hidden');
        }
    });

    // Check action button access rules
    if (userRole === 'SUPER_ADMIN' || userRole === 'ELECTION_OFFICER') {
        document.querySelectorAll('.admin-only').forEach(el => el.classList.remove('hidden'));
    } else {
        document.querySelectorAll('.admin-only').forEach(el => el.classList.add('hidden'));
    }

    if (userRole === 'SUPER_ADMIN' || userRole === 'AUDITOR') {
        document.querySelectorAll('.auditor-only').forEach(el => el.classList.remove('hidden'));
    } else {
        document.querySelectorAll('.auditor-only').forEach(el => el.classList.add('hidden'));
    }
    
    // Profile details in settings
    const settingsUser = document.getElementById('settings-profile-username');
    if (settingsUser) {
        document.getElementById('settings-profile-username').textContent = username;
        document.getElementById('settings-profile-role').textContent = userRole.replace('_', ' ');
    }
}

function startTimers() {
    // 1-second ticks
    setInterval(() => {
        const now = new Date();
        document.getElementById('live-clock').textContent = now.toLocaleTimeString();
        
        serverUptime++;
        const h = Math.floor(serverUptime / 3600);
        const m = Math.floor((serverUptime % 3600) / 60);
        const s = serverUptime % 60;
        
        const uptimeStr = `${h}h ${m}m ${s}s`;
        const el1 = document.getElementById('uptime-display');
        if (el1) el1.textContent = uptimeStr;
        const el2 = document.getElementById('uptime-display-banner');
        if (el2) el2.textContent = uptimeStr;
    }, 1000);

    // Poll system resources and certificate status every 5 seconds
    loadSystemStatus();
    setInterval(loadSystemStatus, 5000);
}

async function loadSystemStatus() {
    try {
        const response = await fetch('/api/system/status');
        if (!response.ok) return;
        const status = await response.json();
        
        // Update resources
        const elCpu = document.getElementById('health-cpu-display');
        if (elCpu) {
            elCpu.textContent = `${status.cpu_usage.toFixed(1)}%`;
            document.getElementById('health-ram-display').textContent = `${status.ram_usage.toFixed(1)}%`;
            document.getElementById('health-disk-display').textContent = `${status.disk_usage.toFixed(1)}%`;
            document.getElementById('health-db-rows-display').textContent = status.database_rows.toLocaleString();
            document.getElementById('health-db-size-display').textContent = `${status.database_size_kb.toFixed(1)} KB`;
            
            updateResourceIndicator('health-cpu-indicator', status.cpu_usage);
            updateResourceIndicator('health-ram-indicator', status.ram_usage);
            updateResourceIndicator('health-disk-indicator', status.disk_usage);
        }
        
        // Update general badges
        updateSystemHealthBadge('database', 'ONLINE');
        updateSystemHealthBadge('mqtt_broker', status.mqtt_connected ? 'ONLINE' : 'OFFLINE');
        updateSystemHealthBadge('flask_server', 'ONLINE');
        updateSystemHealthBadge('socketio', 'ONLINE');
        
        // Settings panel status values
        const dbText = document.getElementById('settings-db-path');
        if (dbText) {
            dbText.textContent = 'voting_system/database/voting.db';
            document.getElementById('settings-mqtt-broker').textContent = 'localhost:1883';
            document.getElementById('settings-tls-mode').textContent = status.tls_enabled ? 'TRUE (TLS Certificates Active)' : 'FALSE (Insecure Mode)';
            document.getElementById('settings-tls-mode').className = status.tls_enabled ? 'text-successgreen font-bold' : 'text-warningyellow font-bold';
        }
        
        // Sync reports metrics
        const rptTurnout = document.getElementById('reports-turnout-pct');
        if (rptTurnout) {
            const pct = statsCache.turnout ?? 0.0;
            rptTurnout.textContent = `${pct.toFixed(2)}%`;
            document.getElementById('reports-turnout-bar').style.width = `${pct.toFixed(2)}%`;
            if (statsCache.candidate_counts) {
                const countA = (statsCache.candidate_counts['A'] || 0) + (statsCache.candidate_counts['1'] || 0);
                const countB = (statsCache.candidate_counts['B'] || 0) + (statsCache.candidate_counts['2'] || 0);
                const countC = (statsCache.candidate_counts['C'] || 0) + (statsCache.candidate_counts['3'] || 0);
                document.getElementById('reports-votes-a').textContent = countA;
                document.getElementById('reports-votes-b').textContent = countB;
                document.getElementById('reports-votes-c').textContent = countC;
            }
        }
        
    } catch (err) {
        console.error('Failed to load system diagnostics:', err);
    }
}

function updateResourceIndicator(id, val) {
    const el = document.getElementById(id);
    if (!el) return;
    if (val > 85) {
        el.className = 'h-2.5 w-2.5 rounded-full bg-dangered pulse';
    } else if (val > 60) {
        el.className = 'h-2.5 w-2.5 rounded-full bg-warningyellow pulse';
    } else {
        el.className = 'h-2.5 w-2.5 rounded-full bg-successgreen pulse';
    }
}

async function loadCertificates() {
    try {
        const response = await fetch('/api/certificates');
        if (!response.ok) return;
        const data = await response.json();
        
        document.getElementById('cert-ca-subject').textContent = data.ca_cert.subject;
        document.getElementById('cert-ca-issuer').textContent = data.ca_cert.issuer;
        document.getElementById('cert-ca-issued').textContent = data.ca_cert.issue_date;
        document.getElementById('cert-ca-expired').textContent = data.ca_cert.expiry_date;
        
        document.getElementById('cert-server-subject').textContent = data.server_cert.subject;
        document.getElementById('cert-server-issuer').textContent = data.server_cert.issuer;
        document.getElementById('cert-server-issued').textContent = data.server_cert.issue_date;
        document.getElementById('cert-server-expired').textContent = data.server_cert.expiry_date;
        
        const healthTls = document.getElementById('health-tls-status-badge');
        if (healthTls) {
            healthTls.textContent = data.tls_enabled ? 'ENABLED' : 'DISABLED';
            healthTls.className = data.tls_enabled ? 'font-bold text-successgreen font-mono' : 'font-bold text-warningyellow font-mono';
        }
    } catch (err) {
        console.error(err);
    }
}

function initSocket() {
    const socket = io();
    
    socket.on('active_clients', (data) => {
        const summary = document.getElementById('clients-count-summary');
        if (summary) summary.textContent = data.count;
    });
    
    socket.on('dashboard_update', (data) => {
        statsCache = data;
        updateDashboardUI(data);
    });
    
    socket.on('new_audit_log', (data) => {
        appendAuditLog(data);
    });
    
    socket.on('auth_event', (data) => {
        appendLiveAuthEvent(data);
    });
    
    socket.on('system_health_update', (data) => {
        if (data.component.startsWith('booth:')) {
            if (!booths[data.component]) {
                booths[data.component] = {};
            }
            Object.assign(booths[data.component], data);
            renderBoothCards();
            updateHardwareStatusPanel(data);
            
            // Query stats to syncconnected booths
            fetch('/api/dashboard/stats')
                .then(res => res.json())
                .then(updateDashboardUI)
                .catch(err => console.error(err));
        } else {
            updateSystemHealthBadge(data.component, data.status);
        }
    });
}

function updateSystemHealthBadge(component, status) {
    let id = null;
    if (component === 'database') id = 'health-db';
    if (component === 'mqtt_broker') id = 'health-mqtt';
    if (component === 'flask_server') id = 'health-server';
    if (component === 'socketio') id = 'health-socket';
    
    if (!id) return;
    const el = document.getElementById(id);
    if (!el) return;
    
    const dot = el.querySelector('span:last-child');
    if (!dot) return;
    
    if (status === 'ONLINE' || status === 'CONNECTED') {
        dot.className = 'h-2.5 w-2.5 rounded-full bg-successgreen pulse';
    } else {
        dot.className = 'h-2.5 w-2.5 rounded-full bg-dangered';
    }
}

function appendAuditLog(entry) {
    // Command Center Last Audit Event sync
    const ccLastAudit = document.getElementById('cc-last-audit');
    if (ccLastAudit) {
        ccLastAudit.textContent = entry.details || entry.event_type;
        const ts = entry.timestamp ? entry.timestamp.split('T')[1] || entry.timestamp : '--:--:--';
        const cleanTs = ts.includes('+') ? ts.split('+')[0] : ts;
        document.getElementById('cc-last-audit-ts').textContent = cleanTs;
    }

    // 1. Audit Terminal Viewer
    const viewer = document.getElementById('terminal-log-viewer');
    if (viewer) {
        const line = document.createElement('div');
        line.className = 'terminal-line';
        
        let colorClass = 'text-successgreen';
        if (entry.severity === 'WARNING') {
            colorClass = 'text-warningyellow';
        } else if (entry.severity === 'CRITICAL') {
            colorClass = 'text-dangered animate-pulse font-bold';
        } else if (entry.event_type === 'SYSTEM_RESTART') {
            colorClass = 'text-accentblue font-bold';
        }
        
        const ts = entry.timestamp ? entry.timestamp.split('T')[1] || entry.timestamp : '--:--:--';
        const cleanTs = ts.includes('+') ? ts.split('+')[0] : ts;
        const voterStr = entry.rfid_id ? ` [RFID: ${escapeHTML(entry.rfid_id)}]` : '';
        const ipStr = entry.ip_address ? ` [IP: ${escapeHTML(entry.ip_address)}]` : '';
        
        line.innerHTML = `<span class="text-textmuted">[${escapeHTML(cleanTs)}]</span> <span class="${colorClass}">${escapeHTML(entry.event_type)}</span>${voterStr}${ipStr}: ${escapeHTML(entry.details)}`;
        
        viewer.appendChild(line);
        viewer.scrollTop = viewer.scrollHeight;
        
        while (viewer.children.length > 100) {
            viewer.removeChild(viewer.firstChild);
        }
    }
    
    // 2. Dashboard Alerts Feed
    if (entry.severity === 'CRITICAL' || entry.severity === 'WARNING') {
        const dbAlerts = document.getElementById('dashboard-recent-alerts');
        if (dbAlerts) {
            // Remove empty placeholder
            const placeholder = document.getElementById('dashboard-alerts-empty');
            if (placeholder) placeholder.remove();
            if (dbAlerts.textContent.includes('No security threats')) dbAlerts.innerHTML = '';
            
            const card = document.createElement('div');
            const alertColor = entry.severity === 'CRITICAL' ? 'border-dangered bg-dangered/5 text-dangered' : 'border-warningyellow bg-warningyellow/5 text-warningyellow';
            card.className = `p-3 rounded-xl border ${alertColor} flex flex-col gap-1`;
            
            const ts = entry.timestamp ? entry.timestamp.split('T')[1] || entry.timestamp : '--:--:--';
            const cleanTs = ts.split('+')[0];
            card.innerHTML = `<div class="flex justify-between font-bold"><span>${escapeHTML(entry.event_type)}</span><span class="font-mono text-[10px]">[${escapeHTML(cleanTs)}]</span></div><p class="text-[10px] text-textlight/90">${escapeHTML(entry.details)}</p>`;
            
            dbAlerts.insertBefore(card, dbAlerts.firstChild);
            
            // Limit to 4 items in Dashboard view
            while (dbAlerts.children.length > 4) {
                dbAlerts.removeChild(dbAlerts.lastChild);
            }
        }
    }
}

function renderBoothCards() {
    const grid = document.getElementById('booth-monitoring-grid');
    if (!grid) return;
    
    const keys = Object.keys(booths);
    if (keys.length === 0) {
        grid.innerHTML = `
            <div class="col-span-2 text-center text-sm py-8 text-textmuted" id="booths-empty-message">
                <i class="fa-solid fa-spinner animate-spin text-accentblue mb-2 text-xl block"></i>
                Awaiting network status updates from ESP32 booths...
            </div>`;
        return;
    }
    
    let html = '';
    
    // Location tracker totals
    let locationCounts = { 'Building A': 0, 'Building B': 0, 'Library': 0, 'Auditorium': 0 };
    
    keys.sort().forEach((key, index) => {
        const b = booths[key];
        const boothId = key.replace('booth:', 'Booth #');
        const isOnline = b.status === 'ONLINE';
        const statusDotColor = isOnline ? 'bg-successgreen animate-pulse' : 'bg-dangered';
        
        const fsmState = escapeHTML(b.fsm_state || 'OFFLINE');
        const voter = escapeHTML(b.current_voter || 'None');
        const rfid = escapeHTML(b.rfid_status || 'IDLE');
        const finger = escapeHTML(b.fingerprint_status || 'IDLE');
        const mqtt = escapeHTML(b.mqtt_status || (isOnline ? 'CONNECTED' : 'DISCONNECTED'));
        const lcd = escapeHTML(b.lcd_status || 'Offline');
        const heap = b.free_heap || 0;
        const buffered = b.buffered_votes || 0;
        const version = escapeHTML(b.firmware_version || 'v1.0.0');
        
        // Mock physical locations for UI display mapping
        const locations = ['Building A', 'Library', 'Auditorium', 'Building B'];
        const mockLocation = locations[index % locations.length];
        
        if (isOnline) {
            locationCounts[mockLocation]++;
        }
        
        html += `
        <div class="glass-panel p-4 flex flex-col gap-3 border-accentblue/15 hover:border-accentblue/40">
            <div class="flex items-center justify-between border-b border-darkborder pb-2">
                <div class="flex items-center gap-2">
                    <span class="h-2.5 w-2.5 rounded-full ${statusDotColor}"></span>
                    <strong class="text-sm text-white">${boothId}</strong>
                    <span class="text-[9px] text-accentblue bg-accentblue/10 border border-accentblue/25 px-1.5 py-0.25 rounded font-bold uppercase font-mono">${mockLocation}</span>
                </div>
                <span class="text-[10px] text-textmuted bg-darkbg px-2 py-0.5 rounded border border-darkborder font-mono">${version}</span>
            </div>
            
            <div class="grid grid-cols-2 gap-2 text-xs">
                <div>
                    <span class="text-textmuted block text-[10px]">FSM State</span>
                    <span class="font-mono font-bold text-accentblue">${fsmState}</span>
                </div>
                <div>
                    <span class="text-textmuted block text-[10px]">Current Voter</span>
                    <span class="font-mono font-semibold text-white truncate block max-w-[100px]">${voter}</span>
                </div>
            </div>
            
            <div class="h-px bg-darkborder"></div>
            
            <div class="grid grid-cols-3 gap-1.5 text-[10px]">
                <div class="bg-darkbg/40 p-1.5 rounded border border-darkborder text-center">
                    <span class="text-textmuted block">RFID</span>
                    <span class="font-bold ${rfid === 'VALIDATING' ? 'text-warningyellow' : rfid === 'SCANNED' ? 'text-successgreen' : 'text-textmuted'}">${rfid}</span>
                </div>
                <div class="bg-darkbg/40 p-1.5 rounded border border-darkborder text-center">
                    <span class="text-textmuted block">Finger</span>
                    <span class="font-bold ${finger === 'SCANNING' ? 'text-warningyellow' : finger === 'VERIFIED' ? 'text-successgreen' : 'text-textmuted'}">${finger}</span>
                </div>
                <div class="bg-darkbg/40 p-1.5 rounded border border-darkborder text-center">
                    <span class="text-textmuted block">MQTT</span>
                    <span class="font-bold ${mqtt === 'CONNECTED' ? 'text-successgreen' : 'text-dangered'}">${mqtt}</span>
                </div>
            </div>
            
            <div class="bg-[#050913] border border-darkborder p-2 rounded font-mono text-[10px] text-successgreen mt-1 flex items-center gap-1.5">
                <i class="fa-solid fa-desktop text-accentblue"></i>
                <span class="truncate">LCD: "${lcd}"</span>
            </div>
            
            <div class="flex justify-between items-center text-[9px] text-textmuted mt-1">
                <span>Heap: ${heap.toLocaleString()} B</span>
                <span>Buffered: ${buffered}</span>
            </div>
        </div>`;
    });
    
    grid.innerHTML = html;
    
    // Sync Location maps
    document.getElementById('map-booth-count-building-a').textContent = `${locationCounts['Building A']} active devices`;
    document.getElementById('map-booth-count-building-b').textContent = `${locationCounts['Building B']} active devices`;
    document.getElementById('map-booth-count-library').textContent = `${locationCounts['Library']} active devices`;
    document.getElementById('map-booth-count-auditorium').textContent = `${locationCounts['Auditorium']} active devices`;
    
    // Pulse indicator dot color based on totals
    updateMapDotIndicator('map-booth-count-building-a', locationCounts['Building A']);
    updateMapDotIndicator('map-booth-count-building-b', locationCounts['Building B']);
    updateMapDotIndicator('map-booth-count-library', locationCounts['Library']);
    updateMapDotIndicator('map-booth-count-auditorium', locationCounts['Auditorium']);
}

function updateMapDotIndicator(labelId, count) {
    const label = document.getElementById(labelId);
    if (!label) return;
    const dot = label.parentNode.querySelector('span');
    if (!dot) return;
    if (count > 0) {
        dot.className = 'h-2 w-2 rounded-full bg-successgreen pulse';
    } else {
        dot.className = 'h-2 w-2 rounded-full bg-gray-600';
    }
}

function updateDashboardUI(stats) {
    if (!stats) return;
    
    // Command Center Overview sync
    const welcomeElectionStatus = document.getElementById('welcome-election-status');
    if (welcomeElectionStatus) welcomeElectionStatus.textContent = stats.election_status ?? 'INACTIVE';
    const welcomeTurnout = document.getElementById('welcome-turnout');
    if (welcomeTurnout) welcomeTurnout.textContent = `${(stats.turnout ?? 0.0).toFixed(2)}%`;
    const welcomeBooths = document.getElementById('welcome-booths');
    if (welcomeBooths) welcomeBooths.textContent = stats.connected_booths ?? 0;
    
    // Executive Command Center Dynamic Card Sync
    const ccStatus = document.getElementById('cc-status');
    if (ccStatus) ccStatus.textContent = stats.election_status ?? 'INACTIVE';
    const ccRegistered = document.getElementById('cc-registered');
    if (ccRegistered) ccRegistered.textContent = (stats.total_voters ?? 0).toLocaleString();
    const ccCast = document.getElementById('cc-cast');
    if (ccCast) ccCast.textContent = (stats.total_votes ?? stats.total_votes_cast ?? 0).toLocaleString();
    const ccTurnout = document.getElementById('cc-turnout');
    if (ccTurnout) ccTurnout.textContent = `${(stats.turnout ?? 0.0).toFixed(2)}%`;
    
    // Leading Candidate calculation
    const ccWinner = document.getElementById('cc-winner');
    if (ccWinner) {
        let maxVotes = -1;
        let leadingCandidate = 'Tie / None';
        
        // Build resolved candidates counts map
        const resolvedCounts = {};
        const getCandidateName = (key) => {
            const legacyMap = { 'A': 1, 'B': 2, 'C': 3 };
            const id = legacyMap[key] || parseInt(key);
            const found = candidatesList.find(c => c.candidate_id === id);
            return found ? found.candidate_name : `Candidate ${key}`;
        };
        
        if (stats.candidate_counts) {
            Object.entries(stats.candidate_counts).forEach(([key, count]) => {
                const name = getCandidateName(key);
                resolvedCounts[name] = (resolvedCounts[name] || 0) + count;
            });
            
            Object.entries(resolvedCounts).forEach(([name, count]) => {
                if (count > maxVotes) {
                    maxVotes = count;
                    leadingCandidate = name;
                } else if (count === maxVotes && maxVotes > 0) {
                    leadingCandidate = 'Tie';
                }
            });
        }
        ccWinner.textContent = leadingCandidate;
    }
    
    const ccBooths = document.getElementById('cc-booths');
    if (ccBooths) ccBooths.textContent = stats.connected_booths ?? 0;
    
    const replay = stats.replay_attacks ?? 0;
    const tamper = stats.tampered_packets ?? 0;
    const double = stats.double_votes ?? 0;
    const totalRejected = stats.rejected_votes ?? 0;
    const authFailures = Math.max(0, totalRejected - replay - tamper - double);
    
    // Command Center Threat Card
    const ccThreat = document.getElementById('cc-threat');
    const ccThreatDesc = document.getElementById('cc-threat-desc');
    if (ccThreat && ccThreatDesc) {
        if (replay > 0 || tamper > 0) {
            ccThreat.textContent = 'RED';
            ccThreat.className = 'text-2xl font-extrabold text-dangered font-mono animate-pulse';
            ccThreatDesc.textContent = 'Critical threat: replay/tamper event logged';
        } else if (double > 0) {
            ccThreat.textContent = 'YELLOW';
            ccThreat.className = 'text-2xl font-extrabold text-warningyellow font-mono';
            ccThreatDesc.textContent = 'Warning: duplicate vote attempt logged';
        } else {
            ccThreat.textContent = 'GREEN';
            ccThreat.className = 'text-2xl font-extrabold text-successgreen font-mono';
            ccThreatDesc.textContent = 'No active threat detected';
        }
    }
    
    // Command Center Health Card
    const ccHealth = document.getElementById('cc-health');
    const ccHealthDesc = document.getElementById('cc-health-desc');
    if (ccHealth && ccHealthDesc) {
        if (replay > 0 || tamper > 0) {
            ccHealth.textContent = 'DEGRADED';
            ccHealth.className = 'text-2xl font-extrabold text-warningyellow font-mono';
            ccHealthDesc.textContent = 'Incident alerts active';
        } else {
            ccHealth.textContent = 'HEALTHY';
            ccHealth.className = 'text-2xl font-extrabold text-successgreen font-mono';
            ccHealthDesc.textContent = 'All services active';
        }
    }
    
    // Update Heatmap Cell values in SOC
    updateHeatmapCell('heatmap-val-admin', tamper);
    updateHeatmapCell('heatmap-val-science', double);
    updateHeatmapCell('heatmap-val-library', replay);
    updateHeatmapCell('heatmap-val-auditorium', authFailures);
    
    // Update Security progress score breakdown
    const tlsEnabled = stats.security_details?.tls_enabled ?? false;
    const tlsScore = tlsEnabled ? 100 : 0;
    const hmacScore = Math.max(50, 100 - tamper * 10);
    const replayScore = Math.max(50, 100 - replay * 10);
    const auditScore = 100;
    
    updateSecurityBar('score-val-tls', 'score-bar-tls', tlsScore);
    updateSecurityBar('score-val-hmac', 'score-bar-hmac', hmacScore);
    updateSecurityBar('score-val-replay', 'score-bar-replay', replayScore);
    updateSecurityBar('score-val-audit', 'score-bar-audit', auditScore);
    
    // Update Evaluator tab diagnostic items
    const mqtth = document.getElementById('cc-health-mqtt');
    if (mqtth) {
        const mqttOnline = stats.security_details?.tls_enabled || stats.mqtt_rate > 0 || stats.connected_booths > 0 || (typeof demoSafetyModeActive !== 'undefined' && demoSafetyModeActive);
        if (mqttOnline) {
            mqtth.className = 'text-successgreen font-bold block mt-1';
            mqtth.innerHTML = '<i class="fa-solid fa-circle-check"></i> ONLINE';
        } else {
            mqtth.className = 'text-warningyellow font-bold block mt-1';
            mqtth.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> OFFLINE';
        }
    }
    
    const tlsh = document.getElementById('cc-health-tls');
    if (tlsh) {
        if (tlsEnabled) {
            tlsh.className = 'text-successgreen font-bold block mt-1';
            tlsh.innerHTML = '<i class="fa-solid fa-lock"></i> SECURED';
        } else {
            tlsh.className = 'text-warningyellow font-bold block mt-1';
            tlsh.innerHTML = '<i class="fa-solid fa-lock-open"></i> INSECURE';
        }
    }
    
    const threatBadge = document.getElementById('welcome-threat');
    if (threatBadge) {
        if (replay > 0 || tamper > 0) {
            threatBadge.textContent = 'CRITICAL';
            threatBadge.className = 'text-dangered font-bold font-mono animate-pulse';
        } else if (double > 0 || totalRejected > 0) {
            threatBadge.textContent = 'WARNING';
            threatBadge.className = 'text-warningyellow font-bold font-mono';
        } else {
            threatBadge.textContent = 'GREEN';
            threatBadge.className = 'text-successgreen font-bold font-mono';
        }
    }

    // General counters
    document.getElementById('total-voters').textContent = (stats.total_voters ?? 0).toLocaleString();
    document.getElementById('total-votes').textContent = (stats.total_votes ?? stats.total_votes_cast ?? 0).toLocaleString();
    
    const turnout = stats.turnout ?? 0.0;
    document.getElementById('turnout-display').textContent = `${turnout.toFixed(2)}%`;
    document.getElementById('total-rejected').textContent = totalRejected.toLocaleString();
    
    // Header UI Sync
    const hdrBooths = document.getElementById('header-connected-booths');
    if (hdrBooths) {
        hdrBooths.textContent = stats.connected_booths ?? 0;
        document.getElementById('header-votes-min').textContent = stats.votes_per_minute ?? 0;
        document.getElementById('header-security-rating').textContent = stats.security_rating ?? 'A+';
    }
    
    // Status Badge UI Sync
    const statusText = stats.election_status ?? 'INACTIVE';
    const badge = document.getElementById('election-status-badge');
    if (badge) {
        badge.textContent = statusText;
        if (statusText === 'ACTIVE') {
            badge.className = 'font-bold text-successgreen font-mono';
            badge.previousElementSibling.className = 'h-2.5 w-2.5 rounded-full bg-successgreen animate-ping';
        } else if (statusText === 'PAUSED') {
            badge.className = 'font-bold text-warningyellow font-mono';
            badge.previousElementSibling.className = 'h-2.5 w-2.5 rounded-full bg-warningyellow animate-pulse';
        } else {
            badge.className = 'font-bold text-dangered font-mono';
            badge.previousElementSibling.className = 'h-2.5 w-2.5 rounded-full bg-dangered';
        }
    }
    
    // Election Management text details
    const mgmtStatus = document.getElementById('mgmt-status');
    if (mgmtStatus) {
        mgmtStatus.textContent = statusText;
        mgmtStatus.className = 'font-bold font-mono ' + (statusText === 'ACTIVE' ? 'text-successgreen' : (statusText === 'PAUSED' ? 'text-warningyellow' : 'text-dangered'));
    }
    
    // TLS Checklist status items
    const tlsItem = document.getElementById('tls-checklist-item');
    if (tlsItem) {
        const tlsEnabled = stats.security_details?.tls_enabled ?? false;
        if (tlsEnabled) {
            tlsItem.className = 'flex items-center justify-between text-successgreen font-bold';
            document.getElementById('tls-checklist-badge').textContent = 'ACTIVE';
            
            const badgeTls = document.getElementById('tls-status-badge');
            if (badgeTls) {
                badgeTls.className = 'flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-successgreen/10 border border-successgreen/20 text-successgreen font-bold';
                badgeTls.innerHTML = '<i class="fa-solid fa-lock text-xs"></i> TLS SECURE';
            }
        } else {
            tlsItem.className = 'flex items-center justify-between text-warningyellow font-bold';
            document.getElementById('tls-checklist-badge').textContent = 'INACTIVE';
            
            const badgeTls = document.getElementById('tls-status-badge');
            if (badgeTls) {
                badgeTls.className = 'flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-warningyellow/10 border border-warningyellow/20 text-warningyellow font-bold';
                badgeTls.innerHTML = '<i class="fa-solid fa-lock-open text-xs"></i> TLS INSECURE';
            }
        }
    }

    // Sync SOC Metrics Tab
    const socReplay = document.getElementById('soc-replay');
    if (socReplay) {
        document.getElementById('soc-replay').textContent = replay.toLocaleString();
        document.getElementById('soc-tamper').textContent = tamper.toLocaleString();
        document.getElementById('soc-double').textContent = double.toLocaleString();
        
        const authFailures = Math.max(0, totalRejected - replay - tamper - double);
        document.getElementById('soc-auth').textContent = authFailures.toLocaleString();
    }

    // Dynamic timeline process nodes checklist
    updateTimelineDot('timeline-dot-started', statusText === 'ACTIVE' || statusText === 'PAUSED');
    updateTimelineDot('timeline-dot-firstvote', (stats.total_votes ?? stats.total_votes_cast ?? 0) > 0);
    updateTimelineDot('timeline-dot-50votes', (stats.total_votes ?? stats.total_votes_cast ?? 0) >= 50);
    updateTimelineDot('timeline-dot-100votes', (stats.total_votes ?? stats.total_votes_cast ?? 0) >= 100);
    updateTimelineDot('timeline-dot-closed', statusText === 'INACTIVE' && (stats.total_votes ?? stats.total_votes_cast ?? 0) > 0);

    // Sync charts data
    if (stats.candidate_counts) {
        updateChartData(stats.candidate_counts, stats.total_votes ?? stats.total_votes_cast ?? 0);
        updateSecurityChart(stats);
    }
}

function updateTimelineDot(dotId, active) {
    const dot = document.getElementById(dotId);
    if (!dot) return;
    const title = document.getElementById(dotId.replace('dot', 'title'));
    const desc = document.getElementById(dotId.replace('dot', 'desc'));
    
    if (active) {
        dot.className = 'absolute -left-[30px] top-0 h-4.5 w-4.5 rounded-full bg-successgreen border-4 border-gray-950 flex items-center justify-center';
        dot.innerHTML = '<i class="fa-solid fa-check text-[7px] text-white"></i>';
        if (title) {
            title.className = 'font-bold text-white';
            desc.className = 'text-textmuted text-[11px] mt-0.5';
        }
    } else {
        dot.className = 'absolute -left-[30px] top-0 h-4.5 w-4.5 rounded-full bg-darkbg border-4 border-darkborder flex items-center justify-center';
        dot.innerHTML = '';
        if (title) {
            title.className = 'font-bold text-textmuted';
            desc.className = 'text-textmuted/50 text-[11px] mt-0.5';
        }
    }
}

function updateChartData(candidateCounts, totalVotes) {
    currentCandidateData = candidateCounts;
    
    const timeStr = new Date().toLocaleTimeString();
    if (timelineDataPoints.length === 0 || timelineDataPoints[timelineDataPoints.length - 1].count !== totalVotes) {
        timelineDataPoints.push({ time: timeStr, count: totalVotes });
        if (timelineDataPoints.length > 10) {
            timelineDataPoints.shift();
        }
    }
    
    initChart();
}

function initChart() {
    const canvas = document.getElementById('main-results-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (currentChart) {
        currentChart.destroy();
    }
    
    const activeCandidates = candidatesList.filter(c => c.status === 'ACTIVE');
    const labels = activeCandidates.length > 0 
        ? activeCandidates.map(c => c.candidate_name) 
        : ['Candidate A', 'Candidate B', 'Candidate C'];
    
    const getCandidateVoteCount = (candId, candName, counts) => {
        let count = 0;
        const legacyMap = { 1: 'A', 2: 'B', 3: 'C' };
        if (counts[candId] !== undefined) count += counts[candId];
        if (counts[candName] !== undefined) count += counts[candName];
        const legKey = legacyMap[candId];
        if (legKey && counts[legKey] !== undefined) count += counts[legKey];
        return count;
    };
    
    const voteCounts = activeCandidates.length > 0
        ? activeCandidates.map(c => getCandidateVoteCount(c.candidate_id, c.candidate_name, currentCandidateData))
        : [currentCandidateData['A'] || 0, currentCandidateData['B'] || 0, currentCandidateData['C'] || 0];
    
    const chartColors = [
        'rgba(59, 130, 246, 0.85)',
        'rgba(16, 185, 129, 0.85)',
        'rgba(245, 158, 11, 0.85)',
        'rgba(168, 85, 247, 0.85)',
        'rgba(236, 72, 153, 0.85)',
        'rgba(20, 184, 166, 0.85)'
    ];
    const hoverColors = [
        '#3B82F6',
        '#10B981',
        '#F59E0B',
        '#A855F7',
        '#EC4899',
        '#14B8A6'
    ];
    
    const finalColors = labels.map((_, i) => chartColors[i % chartColors.length]);
    const finalHoverColors = labels.map((_, i) => hoverColors[i % hoverColors.length]);

    if (currentChartType === 'donut') {
        currentChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: voteCounts,
                    backgroundColor: finalColors,
                    borderColor: 'rgba(255, 255, 255, 0.08)',
                    borderWidth: 1.5,
                    hoverBackgroundColor: finalHoverColors
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#F9FAFB',
                            font: { family: 'Inter', size: 11 }
                        }
                    }
                },
                cutout: '70%'
            }
        });
    } else if (currentChartType === 'race') {
        currentChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Votes Tally',
                    data: voteCounts,
                    backgroundColor: finalColors,
                    borderColor: 'rgba(255, 255, 255, 0.08)',
                    borderWidth: 1.5,
                    hoverBackgroundColor: finalHoverColors,
                    barThickness: 24
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#9CA3AF', font: { family: 'JetBrains Mono', size: 10 }, stepSize: 1 }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#F9FAFB', font: { family: 'Inter', weight: 'bold', size: 11 } }
                    }
                }
            }
        });
    } else if (currentChartType === 'timeline') {
        const lineLabels = timelineDataPoints.map(pt => pt.time);
        const lineValues = timelineDataPoints.map(pt => pt.count);
        currentChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: lineLabels.length > 0 ? lineLabels : ['Start'],
                datasets: [{
                    label: 'Cumulative Trend',
                    data: lineValues.length > 0 ? lineValues : [0],
                    borderColor: '#3B82F6',
                    backgroundColor: 'rgba(59, 130, 246, 0.05)',
                    borderWidth: 2.5,
                    fill: true,
                    tension: 0.35,
                    pointBackgroundColor: '#10B981',
                    pointBorderColor: '#080E1A',
                    pointRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#9CA3AF', font: { family: 'JetBrains Mono', size: 9 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#9CA3AF', font: { family: 'JetBrains Mono', size: 9 }, stepSize: 1 }
                    }
                }
            }
        });
    }
}

function switchChartType(type) {
    currentChartType = type;
    
    ['donut', 'race', 'timeline'].forEach(t => {
        const btn = document.getElementById(`btn-chart-${t}`);
        if (btn) {
            if (t === type) {
                btn.className = 'px-3 py-1.5 rounded-lg bg-accentblue text-white font-semibold transition-all';
            } else {
                btn.className = 'px-3 py-1.5 rounded-lg hover:bg-darkborder text-textmuted font-semibold transition-all';
            }
        }
    });
    
    initChart();
}

function switchTab(tabId) {
    // 1. Hide all tab panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.add('hidden');
    });
    
    // 2. Show requested panel
    const target = document.getElementById(`tab-panel-${tabId}`);
    if (target) target.classList.remove('hidden');
    
    // 3. Update nav active link design state
    document.querySelectorAll('.nav-link').forEach(link => {
        link.className = 'nav-link w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-xs font-bold text-left transition-all text-textmuted hover:text-white hover:bg-white/5';
    });
    
    const activeLink = document.querySelector(`.nav-link[data-tab="${tabId}"]`);
    if (activeLink) {
        activeLink.className = 'nav-link w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-xs font-bold text-left transition-all active-link';
    }
    
    // 4. Update page ribbon title
    const titles = {
        'command_center': 'Executive Command Center',
        'evaluator': 'Project Evaluation Console',
        'dashboard': 'System Dashboard',
        'candidates': 'Candidate Registry & Symbol Setup',
        'election': 'Election Configuration & Control',
        'voters': 'Voter Registry & Auth Status',
        'booths': 'Booth Operations Monitor',
        'security': 'Security Operations Center (SOC)',
        'audit': 'Live Audit Log Streams',
        'reports': 'Official Report Download Center',
        'health': 'System Health Diagnostics',
        'certificates': 'TLS Certificate Configuration',
        'architecture': 'SecureVoteX Cryptographic Flow',
        'admins': 'System Administrator Registry',
        'settings': 'Administrative Account Settings'
    };
    
    document.getElementById('active-tab-title').textContent = titles[tabId] || 'SecureVoteX Console';
    
    // 5. Hide command center welcome card on specific detailed pages for cleaner looks
    const welcome = document.getElementById('command-center-welcome');
    if (welcome) {
        if (tabId === 'dashboard' || tabId === 'command_center') {
            welcome.classList.remove('hidden');
        } else {
            welcome.classList.add('hidden');
        }
    }
    
    // 6. Trigger specific dynamic data reloads
    if (tabId === 'voters') {
        loadVoters();
    } else if (tabId === 'candidates') {
        loadCandidates();
    } else if (tabId === 'admins') {
        loadAdmins();
    }
    
    // Redraw charts
    setTimeout(() => {
        initChart();
        initCCChart();
        if (tabId === 'security') {
            drawSecurityChart();
        }
    }, 100);
}

// Voter registry pagination methods
async function loadVoters() {
    try {
        const response = await fetch('/api/voters');
        const data = await response.json();
        votersList = data.voters || [];
        renderVotersTable();
    } catch (err) {
        console.error('Failed to load voter directory:', err);
    }
}

function handleVoterFilter() {
    voterSearchQuery = document.getElementById('voter-search-input').value.toLowerCase();
    voterFilterStatus = document.getElementById('voter-status-filter').value;
    voterCurrentPage = 1;
    renderVotersTable();
}

function sortVoters(field) {
    if (voterSortField === field) {
        voterSortAsc = !voterSortAsc;
    } else {
        voterSortField = field;
        voterSortAsc = true;
    }
    renderVotersTable();
}

function renderVotersTable() {
    let filtered = [...votersList];
    
    if (voterFilterStatus === 'VOTED') {
        filtered = filtered.filter(v => v.has_voted === 1 || v.has_voted === true);
    } else if (voterFilterStatus === 'NOT_VOTED') {
        filtered = filtered.filter(v => v.has_voted === 0 || v.has_voted === false);
    }
    
    if (voterSearchQuery) {
        filtered = filtered.filter(v => 
            v.name.toLowerCase().includes(voterSearchQuery) || 
            v.rfid_id.toLowerCase().includes(voterSearchQuery)
        );
    }
    
    filtered.sort((a, b) => {
        let valA = a[voterSortField];
        let valB = b[voterSortField];
        
        if (typeof valA === 'string') valA = valA.toLowerCase();
        if (typeof valB === 'string') valB = valB.toLowerCase();
        
        if (valA < valB) return voterSortAsc ? -1 : 1;
        if (valA > valB) return voterSortAsc ? 1 : -1;
        return 0;
    });
    
    const totalEntries = filtered.length;
    const totalPages = Math.ceil(totalEntries / voterPageSize);
    voterCurrentPage = Math.max(1, Math.min(voterCurrentPage, totalPages));
    
    const startIdx = (voterCurrentPage - 1) * voterPageSize;
    const endIdx = Math.min(startIdx + voterPageSize, totalEntries);
    const paginated = filtered.slice(startIdx, endIdx);
    
    const tbody = document.getElementById('voter-table-body');
    if (!tbody) return;
    
    if (paginated.length === 0) {
        const colSpan = (userRole === 'SUPER_ADMIN' || userRole === 'ELECTION_OFFICER') ? 8 : 7;
        tbody.innerHTML = `<tr><td colspan="${colSpan}" class="p-8 text-center text-textmuted">No matching voter records found.</td></tr>`;
        document.getElementById('voter-pagination-indicator').textContent = 'Showing 0 to 0 of 0 entries';
        document.getElementById('btn-voter-prev').disabled = true;
        document.getElementById('btn-voter-next').disabled = true;
        return;
    }
    
    let html = '';
    paginated.forEach(v => {
        const hasVoted = v.has_voted === 1 || v.has_voted === true;
        const statusBadge = hasVoted 
            ? '<span class="inline-block text-[10px] bg-successgreen/10 border border-successgreen/20 text-successgreen font-bold px-2 py-0.5 rounded font-sans uppercase">VOTED</span>' 
            : '<span class="inline-block text-[10px] bg-gray-700/20 border border-gray-700/30 text-textmuted font-semibold px-2 py-0.5 rounded font-sans uppercase text-gray-500">NOT VOTED</span>';
            
        const registeredStatus = '<span class="inline-block text-[10px] bg-successgreen/10 border border-successgreen/20 text-successgreen font-bold px-2 py-0.5 rounded font-sans uppercase">REGISTERED</span>';
            
        const regDateStr = v.registered_at ? v.registered_at.replace('T', ' ').split('.')[0] : '--';
        const voteDateStr = v.voted_at ? v.voted_at.replace('T', ' ').split('.')[0] : '--';
        
        // Hide RFID characters for production look
        const maskedRfid = v.rfid_id.length > 7
            ? v.rfid_id.substring(0, 5) + '***' + v.rfid_id.substring(v.rfid_id.length - 2)
            : v.rfid_id;
            
        let actionsHtml = '';
        if (userRole === 'SUPER_ADMIN' || userRole === 'ELECTION_OFFICER') {
            actionsHtml = `
            <td class="p-4 text-center font-sans">
                <div class="flex items-center justify-center gap-2">
                    <button onclick="editVoter('${escapeHTML(v.rfid_id)}')" title="Edit Voter" class="h-7 w-7 rounded-lg bg-accentblue/10 hover:bg-accentblue hover:text-white text-accentblue flex items-center justify-center transition-all">
                        <i class="fa-solid fa-pen text-[10px]"></i>
                    </button>
                    <button onclick="deleteVoter('${escapeHTML(v.rfid_id)}')" title="Delete Voter" class="h-7 w-7 rounded-lg bg-dangered/10 hover:bg-dangered hover:text-white text-dangered flex items-center justify-center transition-all">
                        <i class="fa-solid fa-trash-can text-[10px]"></i>
                    </button>
                </div>
            </td>`;
        }
        
        html += `
        <tr class="hover:bg-white/5 transition-all">
            <td class="p-4 font-bold text-accentblue font-mono">${escapeHTML(maskedRfid)}</td>
            <td class="p-4 font-bold text-white font-sans">${escapeHTML(v.name)}</td>
            <td class="p-4 text-center text-white font-mono">${escapeHTML(v.fingerprint_id)}</td>
            <td class="p-4 text-center">${registeredStatus}</td>
            <td class="p-4 text-center">${statusBadge}</td>
            <td class="p-4 text-right text-textmuted">${escapeHTML(regDateStr)}</td>
            <td class="p-4 text-right text-textmuted">${escapeHTML(voteDateStr)}</td>
            ${actionsHtml}
        </tr>`;
    });
    
    tbody.innerHTML = html;
    
    document.getElementById('voter-pagination-indicator').textContent = `Showing ${totalEntries === 0 ? 0 : startIdx + 1} to ${endIdx} of ${totalEntries} entries`;
    document.getElementById('btn-voter-prev').disabled = voterCurrentPage === 1;
    document.getElementById('btn-voter-next').disabled = voterCurrentPage === totalPages || totalPages === 0;
}

function changeVoterPage(dir) {
    voterCurrentPage += dir;
    renderVotersTable();
}

// Audit Logs Tab search and filter
function handleAuditFilter() {
    const q = document.getElementById('audit-search-input').value.toLowerCase();
    const severity = document.getElementById('audit-severity-filter').value;
    
    document.querySelectorAll('#terminal-log-viewer .terminal-line').forEach(line => {
        const text = line.textContent.toLowerCase();
        const hasQuery = text.includes(q);
        const hasSeverity = severity === 'ALL' || text.includes(` ${severity} `) || text.includes(`[${severity}]`);
        
        if (hasQuery && hasSeverity) {
            line.classList.remove('hidden');
        } else {
            line.classList.add('hidden');
        }
    });
}

function clearTerminalLogs() {
    const viewer = document.getElementById('terminal-log-viewer');
    if (viewer) {
        viewer.innerHTML = '<div class="terminal-line text-textmuted">Terminal history cleared by administrator. Log stream active...</div>';
    }
}

// Fullscreen Presentation Mode logic
function toggleFullscreenPresentation() {
    const isPresentation = !document.body.classList.contains('presentation-active');
    
    if (isPresentation) {
        document.body.classList.add('presentation-active');
        document.body.classList.add('fullscreen-mode');
        
        const elem = document.documentElement;
        if (elem.requestFullscreen) {
            elem.requestFullscreen().catch(err => console.log(err));
        } else if (elem.webkitRequestFullscreen) {
            elem.webkitRequestFullscreen();
        }
        
        let idx = chartTypes.indexOf(currentChartType);
        presentationInterval = setInterval(() => {
            idx = (idx + 1) % chartTypes.length;
            switchChartType(chartTypes[idx]);
        }, 6000);
        
        const btnDash = document.getElementById('btn-presentation-dashboard');
        if (btnDash) btnDash.innerHTML = '<i class="fa-solid fa-compress"></i> Exit Presentation';
    } else {
        exitPresentationMode();
    }
}

function exitPresentationMode() {
    document.body.classList.remove('presentation-active');
    document.body.classList.remove('fullscreen-mode');
    
    if (document.exitFullscreen) {
        document.exitFullscreen().catch(err => console.log(err));
    }
    
    if (presentationInterval) {
        clearInterval(presentationInterval);
        presentationInterval = null;
    }
    
    const btnDash = document.getElementById('btn-presentation-dashboard');
    if (btnDash) btnDash.innerHTML = '<i class="fa-solid fa-expand"></i> Presentation Mode';
}

async function controlElection(status) {
    if (!confirm(`Are you sure you want to transition election status to: ${status}?`)) {
        return;
    }
    try {
        const response = await fetch('/api/election/control', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
        const result = await response.json();
        if (result.status === 'success') {
            console.log(`Election status updated to ${status}`);
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (err) {
        console.error('Failed to update election status:', err);
    }
}

async function resetDemoData() {
    if (!confirm('Are you sure you want to reset the election database?\nThis will clear all votes and restore the default demo seed records.')) {
        return;
    }
    try {
        const response = await fetch('/api/election/reset', { method: 'POST' });
        const result = await response.json();
        if (result.status === 'success') {
            timelineDataPoints = [];
            document.getElementById('terminal-log-viewer').innerHTML = '<div class="terminal-line text-accentblue font-bold">System restarted. Database reseeded to default demographic records.</div>';
            alert('Database successfully reset to default seeds!');
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (err) {
        console.error('Failed to reset demo data:', err);
    }
}

async function handleChangePassword(e) {
    e.preventDefault();
    const feedback = document.getElementById('password-feedback');
    const btn = document.getElementById('btn-change-password');
    
    feedback.className = 'hidden';
    
    const oldPassword = document.getElementById('old-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    
    if (newPassword !== confirmPassword) {
        feedback.className = 'p-3 rounded-lg mb-4 text-xs font-semibold bg-dangered/15 border border-dangered/30 text-dangered block';
        feedback.textContent = 'New passwords do not match.';
        return;
    }
    
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Saving...';
    
    try {
        const response = await fetch('/api/admin/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
        });
        const result = await response.json();
        
        if (response.ok && result.status === 'success') {
            feedback.className = 'p-3 rounded-lg mb-4 text-xs font-semibold bg-successgreen/15 border border-successgreen/30 text-successgreen block';
            feedback.textContent = 'Password successfully updated in SQLite database.';
            document.getElementById('change-password-form').reset();
        } else {
            feedback.className = 'p-3 rounded-lg mb-4 text-xs font-semibold bg-dangered/15 border border-dangered/30 text-dangered block';
            feedback.textContent = result.message || 'Verification failed. Incorrect old password.';
        }
    } catch (err) {
        console.error(err);
        feedback.className = 'p-3 rounded-lg mb-4 text-xs font-semibold bg-dangered/15 border border-dangered/30 text-dangered block';
            feedback.textContent = 'Failed to submit form. Check broker connectivity.';
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-lock-open"></i> Save New Credentials';
    }
}

function initSecurityChart() {
    drawSecurityChart();
}

function updateSecurityChart(stats) {
    const timeStr = new Date().toLocaleTimeString();
    const replay = stats.replay_attacks ?? 0;
    const tamper = stats.tampered_packets ?? 0;
    const double = stats.double_votes ?? 0;
    const totalRejected = stats.rejected_votes ?? 0;
    const authFailures = Math.max(0, totalRejected - replay - tamper - double);

    securityMetricsHistory.push({
        time: timeStr,
        replay: replay,
        tamper: tamper,
        double: double,
        auth: authFailures
    });

    if (securityMetricsHistory.length > 10) {
        securityMetricsHistory.shift();
    }

    drawSecurityChart();
}

function drawSecurityChart() {
    const canvas = document.getElementById('threat-timeline-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (threatChart) {
        threatChart.destroy();
    }

    const labels = securityMetricsHistory.map(pt => pt.time);
    const replays = securityMetricsHistory.map(pt => pt.replay);
    const tampers = securityMetricsHistory.map(pt => pt.tamper);
    const doubles = securityMetricsHistory.map(pt => pt.double);
    const auths = securityMetricsHistory.map(pt => pt.auth);

    threatChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels.length > 0 ? labels : ['Start'],
            datasets: [
                {
                    label: 'Replay Attacks',
                    data: replays.length > 0 ? replays : [0],
                    borderColor: 'rgba(239, 68, 68, 0.85)',
                    backgroundColor: 'rgba(239, 68, 68, 0.05)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: false
                },
                {
                    label: 'Tampered Packets',
                    data: tampers.length > 0 ? tampers : [0],
                    borderColor: 'rgba(244, 63, 94, 0.85)',
                    backgroundColor: 'rgba(244, 63, 94, 0.05)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: false
                },
                {
                    label: 'Double Votes',
                    data: doubles.length > 0 ? doubles : [0],
                    borderColor: 'rgba(245, 158, 11, 0.85)',
                    backgroundColor: 'rgba(245, 158, 11, 0.05)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: false
                },
                {
                    label: 'Auth Failures',
                    data: auths.length > 0 ? auths : [0],
                    borderColor: 'rgba(168, 85, 247, 0.85)',
                    backgroundColor: 'rgba(168, 85, 247, 0.05)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#F9FAFB',
                        font: { family: 'Inter', size: 10 }
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#9CA3AF', font: { family: 'JetBrains Mono', size: 9 } }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#9CA3AF', font: { family: 'JetBrains Mono', size: 9 }, stepSize: 1 }
                }
            }
        }
    });
}

// ========================================================
// DEMO CENTER & SIMULATION MANAGEMENT ENGINES
// ========================================================

let demoSafetyModeInterval = null;
let demoSafetyModeActive = false;
let demoSafetyState = {
    booths: {
        'BOOTH001': { step: 0, voter: '' },
        'BOOTH002': { step: 0, voter: '' },
        'BOOTH003': { step: 0, voter: '' },
        'BOOTH004': { step: 0, voter: '' }
    },
    tick: 0
};

const fsmSteps = [
    { state: 'IDLE', lcd: 'Scan RFID', rfid: 'IDLE', finger: 'IDLE' },
    { state: 'WAITING_RFID', lcd: 'Checking Voter', rfid: 'VALIDATING', finger: 'IDLE' },
    { state: 'RFID_VERIFIED', lcd: 'Scan Finger', rfid: 'SCANNED', finger: 'IDLE' },
    { state: 'FINGERPRINT_SCAN', lcd: 'Checking Finger', rfid: 'SCANNED', finger: 'SCANNING' },
    { state: 'FINGERPRINT_VERIFIED', lcd: 'Select Candidate', rfid: 'SCANNED', finger: 'VERIFIED' },
    { state: 'CANDIDATE_SELECTION', lcd: 'Sending Vote', rfid: 'SCANNED', finger: 'VERIFIED' },
    { state: 'VOTE_SUBMITTED', lcd: 'Vote Recorded', rfid: 'SCANNED', finger: 'VERIFIED' }
];

const mockVoters = ['Ravi Kumar', 'Priya Sharma', 'Arjun Rao', 'Sneha Patil', 'Kiran Nair', 'Deepa Menon', 'Vikram Singh'];

function openDemoModal() {
    const modal = document.getElementById('demo-center-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeDemoModal() {
    const modal = document.getElementById('demo-center-modal');
    if (modal) modal.classList.add('hidden');
}

async function setElectionStatus(status) {
    try {
        await fetch('/api/election/control', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });
    } catch (err) {
        console.error(err);
    }
}

function toggleDemoSafetyMode(checked) {
    demoSafetyModeActive = checked;
    const cb = document.getElementById('demo-safety-mode-toggle');
    if (cb) cb.checked = checked;

    if (checked) {
        console.log('Demo Safety Mode ENABLED');
        setElectionStatus('ACTIVE');
        demoSafetyState.tick = 0;
        demoSafetyModeInterval = setInterval(() => {
            runDemoSafetyTick();
        }, 3000);
        runDemoSafetyTick();
    } else {
        console.log('Demo Safety Mode DISABLED');
        if (demoSafetyModeInterval) {
            clearInterval(demoSafetyModeInterval);
            demoSafetyModeInterval = null;
        }
    }
}

async function runDemoSafetyTick() {
    demoSafetyState.tick++;
    const tick = demoSafetyState.tick;
    const boothKeys = Object.keys(demoSafetyState.booths);
    
    for (const bId of boothKeys) {
        const boothState = demoSafetyState.booths[bId];
        
        if (Math.random() > 0.4) {
            boothState.step = (boothState.step + 1) % fsmSteps.length;
        }
        
        if (boothState.step === 1 && !boothState.voter) {
            boothState.voter = mockVoters[Math.floor(Math.random() * mockVoters.length)];
        }
        
        const currentFSM = fsmSteps[boothState.step];
        const isSubmitted = currentFSM.state === 'VOTE_SUBMITTED';
        
        await fetch('/api/demo/booth-heartbeat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                booth_id: bId,
                fsm_state: currentFSM.state,
                lcd_status: currentFSM.lcd,
                rfid_status: currentFSM.rfid,
                fingerprint_status: currentFSM.finger,
                current_voter: boothState.voter,
                wifi_status: 'CONNECTED',
                mqtt_status: 'CONNECTED',
                free_heap: 45000 + Math.floor(Math.random() * 5000),
                buffered_votes: 0,
                firmware_version: 'v1.2.0'
            })
        });
        
        if (isSubmitted && boothState.voter) {
            await fetch('/api/demo/simulate-vote', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ booth_id: bId })
            });
            boothState.voter = '';
        }
    }
    
    if (tick % 10 === 0) {
        const threatTypes = ['AUTH_FAIL', 'DOUBLE_VOTE', 'REPLAY', 'TAMPER'];
        const randomThreat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
        await fetch('/api/demo/simulate-threat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: randomThreat })
        });
    }
}

let electionSimInterval = null;
let boothSimInterval = null;

function toggleElectionSimulation(action) {
    const btnStart = document.getElementById('btn-sim-vote-start');
    const btnStop = document.getElementById('btn-sim-vote-stop');
    
    if (action === 'start') {
        if (btnStart) btnStart.classList.add('hidden');
        if (btnStop) btnStop.classList.remove('hidden');
        setElectionStatus('ACTIVE');
        
        electionSimInterval = setInterval(async () => {
            await fetch('/api/demo/simulate-vote', { method: 'POST' });
        }, 2000);
    } else {
        if (btnStart) btnStart.classList.remove('hidden');
        if (btnStop) btnStop.classList.add('hidden');
        if (electionSimInterval) {
            clearInterval(electionSimInterval);
            electionSimInterval = null;
        }
    }
}

function toggleBoothSimulation(action) {
    const btnStart = document.getElementById('btn-sim-booth-start');
    const btnStop = document.getElementById('btn-sim-booth-stop');
    
    if (action === 'start') {
        if (btnStart) btnStart.classList.add('hidden');
        if (btnStop) btnStop.classList.remove('hidden');
        
        let step = 0;
        boothSimInterval = setInterval(async () => {
            step = (step + 1) % fsmSteps.length;
            const current = fsmSteps[step];
            await fetch('/api/demo/booth-heartbeat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    booth_id: 'BOOTH001',
                    fsm_state: current.state,
                    lcd_status: current.lcd,
                    rfid_status: current.rfid,
                    fingerprint_status: current.finger,
                    wifi_status: 'CONNECTED',
                    mqtt_status: 'CONNECTED'
                })
            });
        }, 2500);
    } else {
        if (btnStart) btnStart.classList.remove('hidden');
        if (btnStop) btnStop.classList.add('hidden');
        if (boothSimInterval) {
            clearInterval(boothSimInterval);
            boothSimInterval = null;
        }
    }
}

async function triggerSimulatedThreat(type) {
    if (!type) return;
    await fetch('/api/demo/simulate-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type })
    });
}

async function runScenario(type) {
    closeDemoModal();
    console.log(`Running scenario ${type}...`);
    
    if (type === 'A') {
        await setElectionStatus('ACTIVE');
        const booths = ['BOOTH001', 'BOOTH002', 'BOOTH003', 'BOOTH004'];
        for (const b of booths) {
            await fetch('/api/demo/booth-heartbeat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    booth_id: b,
                    wifi_status: 'CONNECTED',
                    mqtt_status: 'CONNECTED',
                    fsm_state: 'IDLE',
                    lcd_status: 'Scan RFID'
                })
            });
        }
        for (let i = 0; i < 3; i++) {
            setTimeout(async () => {
                const randomBooth = booths[Math.floor(Math.random() * booths.length)];
                await fetch('/api/demo/simulate-vote', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ booth_id: randomBooth })
                });
            }, i * 1500);
        }
    } else if (type === 'B') {
        await fetch('/api/demo/simulate-threat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'DOUBLE_VOTE' })
        });
    } else if (type === 'C') {
        await fetch('/api/demo/simulate-threat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'REPLAY' })
        });
    } else if (type === 'D') {
        await fetch('/api/demo/booth-heartbeat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                booth_id: 'BOOTH002',
                wifi_status: 'DISCONNECTED',
                mqtt_status: 'DISCONNECTED',
                buffered_votes: 3,
                fsm_state: 'OFFLINE',
                lcd_status: 'Offline (Buffered)'
            })
        });
        setTimeout(async () => {
            await fetch('/api/demo/booth-heartbeat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    booth_id: 'BOOTH002',
                    wifi_status: 'CONNECTED',
                    mqtt_status: 'CONNECTED',
                    buffered_votes: 0,
                    fsm_state: 'IDLE',
                    lcd_status: 'Scan RFID'
                })
            });
            for (let i = 0; i < 3; i++) {
                setTimeout(async () => {
                    await fetch('/api/demo/simulate-vote', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ booth_id: 'BOOTH002' })
                    });
                }, i * 1000);
            }
        }, 3000);
    } else if (type === 'E') {
        await setElectionStatus('INACTIVE');
    }
}

let quickDemoTimer = null;
let qdTimeLeft = 180;
let qdCurrentStep = 0;

const quickDemoSteps = [
    { time: 180, desc: 'Election Activation: Triggering backend activation sequence...', action: async () => {
        await setElectionStatus('ACTIVE');
    }},
    { time: 165, desc: 'Simulated Voter Authentication: RFID card detected at Booth #BOOTH001...', action: async () => {
        await fetch('/api/demo/booth-heartbeat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                booth_id: 'BOOTH001',
                fsm_state: 'WAITING_RFID',
                lcd_status: 'Checking Voter',
                rfid_status: 'VALIDATING',
                wifi_status: 'CONNECTED',
                mqtt_status: 'CONNECTED'
            })
        });
    }},
    { time: 150, desc: 'Fingerprint Verification: Scanning voter biometrics credentials...', action: async () => {
        await fetch('/api/demo/booth-heartbeat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                booth_id: 'BOOTH001',
                fsm_state: 'RFID_VERIFIED',
                lcd_status: 'Scan Finger',
                rfid_status: 'SCANNED',
                fingerprint_status: 'SCANNING',
                wifi_status: 'CONNECTED',
                mqtt_status: 'CONNECTED'
            })
        });
    }},
    { time: 135, desc: 'Vote Submission: HMAC payload signed and pushed to backend database...', action: async () => {
        await fetch('/api/demo/simulate-vote', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ booth_id: 'BOOTH001' })
        });
    }},
    { time: 120, desc: 'Dashboard Update: Socket.IO update broadcast and metrics sync...', action: async () => {
        // System updates automatically via Socket.IO
    }},
    { time: 105, desc: 'Security Event: Generating unauthorized double vote attempt...', action: async () => {
        await fetch('/api/demo/simulate-threat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'DOUBLE_VOTE' })
        });
    }},
    { time: 90, desc: 'Replay Attack Blocked: Cryptographic replay exploit rejected by database key checks...', action: async () => {
        await fetch('/api/demo/simulate-threat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'REPLAY' })
        });
    }},
    { time: 75, desc: 'Audit Log Update: Integrity verification entries added to Secure Audit stream...', action: async () => {
        // Handled automatically on the backend
    }},
    { time: 60, desc: 'Booth Health Update: Compiling status telemetry from Building A/B/Library...', action: async () => {
        const booths = ['BOOTH001', 'BOOTH002', 'BOOTH003', 'BOOTH004'];
        for (const b of booths) {
            await fetch('/api/demo/booth-heartbeat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    booth_id: b,
                    wifi_status: 'CONNECTED',
                    mqtt_status: 'CONNECTED',
                    fsm_state: 'IDLE',
                    lcd_status: 'Scan RFID'
                })
            });
        }
    }},
    { time: 45, desc: 'Election Results Update: Launching election results simulation surge...', action: async () => {
        for (let i = 0; i < 4; i++) {
            setTimeout(async () => {
                await fetch('/api/demo/simulate-vote', { method: 'POST' });
            }, i * 1000);
        }
    }},
    { time: 30, desc: 'PDF Report Generation: Exporting official cryptographic results report...', action: async () => {
        window.open('/api/election/export/pdf', '_blank');
    }},
    { time: 15, desc: 'Showcase Mode Launch: Starting 10-second Showcase kiosk rotation loop...', action: async () => {
        startProjectShowcase();
    }}
];

function startEvaluatorQuickDemo() {
    const statusContainer = document.getElementById('quick-demo-status');
    const btn = document.getElementById('btn-quick-demo');
    
    if (statusContainer) statusContainer.classList.remove('hidden');
    if (btn) {
        btn.disabled = true;
        btn.className = 'w-full bg-gray-700 text-gray-400 font-extrabold py-3 rounded-xl cursor-not-allowed text-xs uppercase tracking-wider';
        btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Demo In Progress...';
    }
    
    qdTimeLeft = 180;
    qdCurrentStep = 0;
    
    if (quickDemoTimer) clearInterval(quickDemoTimer);
    
    executeQuickDemoStep();
    
    quickDemoTimer = setInterval(() => {
        qdTimeLeft--;
        
        const timerEl = document.getElementById('qd-timer');
        if (timerEl) timerEl.textContent = `${qdTimeLeft}s left`;
        
        const nextStep = quickDemoSteps[qdCurrentStep + 1];
        if (nextStep && qdTimeLeft <= nextStep.time) {
            qdCurrentStep++;
            executeQuickDemoStep();
        }
        
        if (qdTimeLeft <= 0) {
            clearInterval(quickDemoTimer);
            quickDemoTimer = null;
            
            if (btn) {
                btn.disabled = false;
                btn.className = 'w-full bg-gradient-to-r from-warningyellow to-amber-600 hover:from-amber-600 hover:to-warningyellow text-white font-extrabold py-3 rounded-xl transition-all shadow-lg shadow-warningyellow/10 flex items-center justify-center gap-2 text-xs uppercase tracking-wider';
                btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Run 3-Minute Demonstration';
            }
            
            const descEl = document.getElementById('qd-desc');
            if (descEl) descEl.textContent = 'Demonstration sequence complete!';
        }
    }, 1000);
}

function executeQuickDemoStep() {
    const step = quickDemoSteps[qdCurrentStep];
    if (!step) return;
    
    const stepEl = document.getElementById('qd-step');
    const descEl = document.getElementById('qd-desc');
    
    if (stepEl) stepEl.textContent = `Step ${qdCurrentStep + 1}/12`;
    if (descEl) descEl.textContent = step.desc;
    
    console.log(`[Quick Demo] Step ${qdCurrentStep + 1}: ${step.desc}`);
    if (typeof step.action === 'function') {
        step.action().catch(err => console.error('Quick Demo step action failed:', err));
    }
}

// ========================================================
// PROJECT SHOWCASE ROTATION MODE (10s Tabs Kiosk Rotation)
// ========================================================

let showcaseActive = false;
let showcaseInterval = null;
let showcaseTabIdx = 0;
const showcaseTabs = ['command_center', 'dashboard', 'booths', 'security', 'architecture', 'health'];

function toggleProjectShowcase() {
    if (showcaseActive) {
        stopProjectShowcase();
    } else {
        startProjectShowcase();
    }
}

function startProjectShowcase() {
    showcaseActive = true;
    showcaseTabIdx = 0;
    
    const btn = document.getElementById('btn-project-showcase-sidebar');
    if (btn) {
        btn.innerHTML = '<i class="fa-solid fa-stop text-sm w-5 text-dangered"></i> Stop Showcase';
        btn.className = 'w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-xs font-extrabold text-left transition-all text-dangered hover:bg-dangered/10 border border-dangered/25 mt-2 bg-dangered/5';
    }
    
    const elem = document.documentElement;
    if (elem.requestFullscreen) {
        elem.requestFullscreen().catch(err => console.log('Fullscreen error:', err));
    }
    document.body.classList.add('presentation-active');
    
    switchTab(showcaseTabs[0]);
    
    showcaseInterval = setInterval(() => {
        showcaseTabIdx = (showcaseTabIdx + 1) % showcaseTabs.length;
        switchTab(showcaseTabs[showcaseTabIdx]);
    }, 10000);
}

function stopProjectShowcase() {
    showcaseActive = false;
    if (showcaseInterval) {
        clearInterval(showcaseInterval);
        showcaseInterval = null;
    }
    
    const btn = document.getElementById('btn-project-showcase-sidebar');
    if (btn) {
        btn.innerHTML = '<i class="fa-solid fa-play text-sm w-5 text-warningyellow"></i> Project Showcase';
        btn.className = 'w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-xs font-extrabold text-left transition-all text-warningyellow hover:text-white hover:bg-warningyellow/10 border border-warningyellow/20 mt-2 bg-warningyellow/5';
    }
    
    if (document.fullscreenElement) {
        document.exitFullscreen().catch(err => console.log('Exit fullscreen error:', err));
    }
    document.body.classList.remove('presentation-active');
}

// Adjust fullscreenchange listener to cover showcase as well
document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
        if (showcaseActive) {
            stopProjectShowcase();
        }
        if (document.body.classList.contains('presentation-active')) {
            exitPresentationMode();
        }
    }
});

// ========================================================
// COMMAND CENTER DYNAMIC CHART & HELPER ENGINES
// ========================================================

let ccStandingsChart = null;

function initCCChart() {
    const canvas = document.getElementById('cc-standings-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (ccStandingsChart) {
        ccStandingsChart.destroy();
    }
    
    const activeCandidates = candidatesList.filter(c => c.status === 'ACTIVE');
    const labels = activeCandidates.length > 0 
        ? activeCandidates.map(c => c.candidate_name) 
        : ['Candidate A', 'Candidate B', 'Candidate C'];
    
    const getCandidateVoteCount = (candId, candName, counts) => {
        let count = 0;
        const legacyMap = { 1: 'A', 2: 'B', 3: 'C' };
        if (counts[candId] !== undefined) count += counts[candId];
        if (counts[candName] !== undefined) count += counts[candName];
        const legKey = legacyMap[candId];
        if (legKey && counts[legKey] !== undefined) count += counts[legKey];
        return count;
    };
    
    const voteCounts = activeCandidates.length > 0
        ? activeCandidates.map(c => getCandidateVoteCount(c.candidate_id, c.candidate_name, currentCandidateData))
        : [currentCandidateData['A'] || 0, currentCandidateData['B'] || 0, currentCandidateData['C'] || 0];
        
    const chartColors = [
        'rgba(59, 130, 246, 0.85)',
        'rgba(16, 185, 129, 0.85)',
        'rgba(245, 158, 11, 0.85)',
        'rgba(168, 85, 247, 0.85)',
        'rgba(236, 72, 153, 0.85)',
        'rgba(20, 184, 166, 0.85)'
    ];
    const hoverColors = [
        '#3B82F6',
        '#10B981',
        '#F59E0B',
        '#A855F7',
        '#EC4899',
        '#14B8A6'
    ];
    
    const finalColors = labels.map((_, i) => chartColors[i % chartColors.length]);
    const finalHoverColors = labels.map((_, i) => hoverColors[i % hoverColors.length]);

    ccStandingsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Votes Cast',
                data: voteCounts,
                backgroundColor: finalColors,
                borderColor: 'rgba(255, 255, 255, 0.08)',
                borderWidth: 1.5,
                hoverBackgroundColor: finalHoverColors,
                barThickness: 16
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#9CA3AF', font: { family: 'JetBrains Mono', size: 9 }, stepSize: 1 }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#F9FAFB', font: { family: 'Inter', weight: 'bold', size: 10 } }
                }
            }
        }
    });
}

function updateSecurityBar(valId, barId, score) {
    const valEl = document.getElementById(valId);
    const barEl = document.getElementById(barId);
    if (!valEl || !barEl) return;
    valEl.textContent = `${score}/100`;
    barEl.style.width = `${score}%`;
    
    barEl.className = 'h-full rounded-full';
    valEl.className = 'font-bold font-mono';
    
    if (score >= 90) {
        barEl.classList.add('bg-successgreen');
        valEl.classList.add('text-successgreen');
    } else if (score >= 70) {
        barEl.classList.add('bg-warningyellow');
        valEl.classList.add('text-warningyellow');
    } else {
        barEl.classList.add('bg-dangered');
        valEl.classList.add('text-dangered');
    }
}

function updateHeatmapCell(elementId, count) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = `${count} Threat${count === 1 ? '' : 's'}`;
    const rect = el.previousElementSibling.previousElementSibling;
    if (!rect) return;
    if (count === 0) {
        rect.setAttribute('fill', 'rgba(16, 185, 129, 0.05)');
        rect.setAttribute('stroke', 'rgba(16, 185, 129, 0.2)');
        el.setAttribute('fill', '#10B981');
    } else if (count <= 2) {
        rect.setAttribute('fill', 'rgba(245, 158, 11, 0.08)');
        rect.setAttribute('stroke', 'rgba(245, 158, 11, 0.4)');
        el.setAttribute('fill', '#F59E0B');
    } else {
        rect.setAttribute('fill', 'rgba(239, 68, 68, 0.1)');
        rect.setAttribute('stroke', 'rgba(239, 68, 68, 0.5)');
        el.setAttribute('fill', '#EF4444');
    }
}

// ==========================================
// PHASE 6: CANDIDATE REGISTRY CRUD HANDLERS
// ==========================================

async function loadCandidates(page = 1) {
    try {
        const response = await fetch('/api/candidates');
        const data = await response.json();
        candidatesList = data.candidates || [];
        renderCandidatesGrid(page);
    } catch (err) {
        console.error('Failed to load candidates registry:', err);
    }
}

function handleCandidateSearch() {
    candidateSearchQuery = document.getElementById('candidate-search-input').value.toLowerCase();
    candidateCurrentPage = 1;
    renderCandidatesGrid(candidateCurrentPage);
}

function changeCandidatePage(dir) {
    const filtered = candidatesList.filter(cand => 
        cand.candidate_name.toLowerCase().includes(candidateSearchQuery) || 
        cand.party_name.toLowerCase().includes(candidateSearchQuery)
    );
    const totalPages = Math.max(1, Math.ceil(filtered.length / candidatePageSize));
    const nextPage = candidateCurrentPage + dir;
    if (nextPage >= 1 && nextPage <= totalPages) {
        candidateCurrentPage = nextPage;
        renderCandidatesGrid(candidateCurrentPage);
    }
}

function renderCandidatesGrid(page = 1) {
    candidateCurrentPage = page;
    const grid = document.getElementById('candidates-registry-grid');
    if (!grid) return;
    
    const filtered = candidatesList.filter(cand => 
        cand.candidate_name.toLowerCase().includes(candidateSearchQuery) || 
        cand.party_name.toLowerCase().includes(candidateSearchQuery)
    );
    
    const totalEntries = filtered.length;
    const totalPages = Math.max(1, Math.ceil(totalEntries / candidatePageSize));
    candidateCurrentPage = Math.max(1, Math.min(candidateCurrentPage, totalPages));
    
    const startIdx = (candidateCurrentPage - 1) * candidatePageSize;
    const endIdx = Math.min(startIdx + candidatePageSize, totalEntries);
    const paginated = filtered.slice(startIdx, endIdx);
    
    if (paginated.length === 0) {
        grid.innerHTML = `<div class="col-span-full p-8 text-center text-textmuted font-semibold">No candidates found in registry.</div>`;
        document.getElementById('candidate-pagination-indicator').textContent = 'Showing 0 to 0 of 0 entries';
        document.getElementById('btn-candidate-prev').disabled = true;
        document.getElementById('btn-candidate-next').disabled = true;
        return;
    }
    
    let html = '';
    paginated.forEach(cand => {
        const isActive = cand.status === 'ACTIVE';
        const statusBadge = isActive 
            ? '<span class="inline-block text-[10px] bg-successgreen/10 border border-successgreen/20 text-successgreen font-bold px-2 py-0.5 rounded font-mono uppercase">ACTIVE</span>' 
            : '<span class="inline-block text-[10px] bg-gray-700/20 border border-gray-700/30 text-textmuted font-semibold px-2 py-0.5 rounded font-mono uppercase text-gray-500">INACTIVE</span>';
            
        const isActionAllowed = userRole === 'SUPER_ADMIN' || userRole === 'ELECTION_OFFICER';
        const actionsHtml = isActionAllowed ? `
            <div class="flex items-center gap-2">
                <button onclick="editCandidate(${cand.candidate_id})" title="Edit Candidate" class="h-8 px-2.5 rounded-lg bg-accentblue/10 hover:bg-accentblue hover:text-white text-accentblue flex items-center justify-center transition-all gap-1.5 font-semibold text-xs border border-accentblue/25">
                    <i class="fa-solid fa-pen text-[10px]"></i> Edit
                </button>
                <button onclick="deleteCandidate(${cand.candidate_id})" title="Delete Candidate" class="h-8 px-2.5 rounded-lg bg-dangered/10 hover:bg-dangered hover:text-white text-dangered flex items-center justify-center transition-all gap-1.5 font-semibold text-xs border border-dangered/25">
                    <i class="fa-solid fa-trash-can text-[10px]"></i> Delete
                </button>
            </div>
        ` : '';
        
        const symbolHtml = cand.symbol_path 
            ? `<img src="${escapeHTML(cand.symbol_path)}" class="h-full w-full object-cover" />` 
            : `<i class="fa-solid fa-user-tie text-2xl text-textmuted"></i>`;
            
        html += `
        <div class="glass-panel p-4 flex flex-col gap-4 border-accentblue/15 hover:border-accentblue/40 relative">
            <div class="flex items-center gap-4">
                <div class="h-16 w-16 rounded-2xl bg-darkbg border border-darkborder flex items-center justify-center overflow-hidden">
                    ${symbolHtml}
                </div>
                <div class="flex-grow min-w-0">
                    <h4 class="font-bold text-white text-sm truncate">${escapeHTML(cand.candidate_name)}</h4>
                    <p class="text-xs text-textmuted truncate">${escapeHTML(cand.party_name)}</p>
                    <div class="mt-1">${statusBadge}</div>
                </div>
            </div>
            
            <div class="flex items-center justify-between border-t border-darkborder pt-3 mt-1 text-xs">
                <span class="text-textmuted">ID: <span class="font-mono font-bold text-accentblue">${cand.candidate_id}</span></span>
                ${actionsHtml}
            </div>
        </div>`;
    });
    
    grid.innerHTML = html;
    
    document.getElementById('candidate-pagination-indicator').textContent = `Showing ${totalEntries === 0 ? 0 : startIdx + 1} to ${endIdx} of ${totalEntries} entries`;
    document.getElementById('btn-candidate-prev').disabled = candidateCurrentPage === 1;
    document.getElementById('btn-candidate-next').disabled = candidateCurrentPage === totalPages || totalPages === 0;
}

function openAddCandidateModal() {
    document.getElementById('candidate-modal-title').textContent = 'Register New Candidate';
    document.getElementById('candidate-form-id').value = '';
    document.getElementById('candidate-form-name').value = '';
    document.getElementById('candidate-form-party').value = '';
    document.getElementById('candidate-form-symbol-path').value = '';
    document.getElementById('candidate-symbol-preview').innerHTML = '<i class="fa-solid fa-image text-lg"></i>';
    document.getElementById('candidate-form-status').value = 'ACTIVE';
    document.getElementById('candidate-modal').classList.remove('hidden');
}

function closeCandidateModal() {
    document.getElementById('candidate-modal').classList.add('hidden');
}

async function uploadCandidateSymbol(input) {
    if (!input.files || input.files.length === 0) return;
    const file = input.files[0];
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/candidates/upload-symbol', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (response.ok && result.status === 'success') {
            document.getElementById('candidate-form-symbol-path').value = result.symbol_path;
            document.getElementById('candidate-symbol-preview').innerHTML = `<img src="${escapeHTML(result.symbol_path)}" class="h-full w-full object-cover" />`;
        } else {
            alert('Upload failed: ' + (result.message || 'Unknown error'));
        }
    } catch (err) {
        console.error('Symbol upload failed:', err);
        alert('Symbol upload failed: ' + err.message);
    }
}

async function saveCandidateForm(event) {
    event.preventDefault();
    const id = document.getElementById('candidate-form-id').value;
    const name = document.getElementById('candidate-form-name').value;
    const party = document.getElementById('candidate-form-party').value;
    const symbolPath = document.getElementById('candidate-form-symbol-path').value;
    const status = document.getElementById('candidate-form-status').value;
    
    const payload = {
        candidate_name: name,
        party_name: party,
        symbol_path: symbolPath,
        status: status
    };
    
    const url = id ? `/api/candidates/${id}` : '/api/candidates';
    const method = id ? 'PUT' : 'POST';
    
    try {
        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (response.ok && result.status === 'success') {
            closeCandidateModal();
            loadCandidates(candidateCurrentPage);
            // Refresh dashboard stats
            fetch('/api/dashboard/stats')
                .then(res => res.json())
                .then(updateDashboardUI)
                .catch(err => console.error(err));
        } else {
            alert('Save failed: ' + (result.message || 'Unknown error'));
        }
    } catch (err) {
        console.error('Save candidate failed:', err);
        alert('Save candidate failed: ' + err.message);
    }
}

async function editCandidate(id) {
    const cand = candidatesList.find(c => c.candidate_id === id);
    if (!cand) return;
    
    document.getElementById('candidate-modal-title').textContent = 'Edit Candidate Details';
    document.getElementById('candidate-form-id').value = cand.candidate_id;
    document.getElementById('candidate-form-name').value = cand.candidate_name;
    document.getElementById('candidate-form-party').value = cand.party_name;
    document.getElementById('candidate-form-symbol-path').value = cand.symbol_path || '';
    if (cand.symbol_path) {
        document.getElementById('candidate-symbol-preview').innerHTML = `<img src="${escapeHTML(cand.symbol_path)}" class="h-full w-full object-cover" />`;
    } else {
        document.getElementById('candidate-symbol-preview').innerHTML = '<i class="fa-solid fa-image text-lg"></i>';
    }
    document.getElementById('candidate-form-status').value = cand.status || 'ACTIVE';
    document.getElementById('candidate-modal').classList.remove('hidden');
}

async function deleteCandidate(id) {
    if (!confirm('Are you sure you want to delete this candidate from the registry?')) return;
    
    try {
        const response = await fetch(`/api/candidates/${id}`, {
            method: 'DELETE'
        });
        const result = await response.json();
        if (response.ok && result.status === 'success') {
            loadCandidates(candidateCurrentPage);
            // Refresh dashboard stats
            fetch('/api/dashboard/stats')
                .then(res => res.json())
                .then(updateDashboardUI)
                .catch(err => console.error(err));
        } else {
            alert('Delete failed: ' + (result.message || 'Unknown error'));
        }
    } catch (err) {
        console.error('Delete candidate failed:', err);
        alert('Delete candidate failed: ' + err.message);
    }
}

// ==========================================
// PHASE 6: VOTER DIRECTORY CRUD HANDLERS
// ==========================================

function openAddVoterModal() {
    document.getElementById('voter-modal-title').textContent = 'Enroll New Voter';
    document.getElementById('voter-form-old-rfid').value = '';
    document.getElementById('voter-form-rfid').value = '';
    document.getElementById('voter-form-rfid').disabled = false;
    document.getElementById('voter-form-name').value = '';
    document.getElementById('voter-form-fingerprint').value = '';
    document.getElementById('voter-form-voted-container').classList.add('hidden');
    document.getElementById('voter-form-voted').value = '0';
    document.getElementById('voter-modal').classList.remove('hidden');
}

function closeVoterModal() {
    document.getElementById('voter-modal').classList.add('hidden');
}

async function editVoter(rfid_id) {
    const voter = votersList.find(v => v.rfid_id === rfid_id);
    if (!voter) return;
    
    document.getElementById('voter-modal-title').textContent = 'Edit Voter Details';
    document.getElementById('voter-form-old-rfid').value = voter.rfid_id;
    document.getElementById('voter-form-rfid').value = voter.rfid_id;
    document.getElementById('voter-form-rfid').disabled = false;
    document.getElementById('voter-form-name').value = voter.name;
    document.getElementById('voter-form-fingerprint').value = voter.fingerprint_id;
    document.getElementById('voter-form-voted-container').classList.remove('hidden');
    document.getElementById('voter-form-voted').value = voter.has_voted ? '1' : '0';
    document.getElementById('voter-modal').classList.remove('hidden');
}

async function saveVoterForm(event) {
    event.preventDefault();
    const oldRfid = document.getElementById('voter-form-old-rfid').value;
    const rfid = document.getElementById('voter-form-rfid').value;
    const name = document.getElementById('voter-form-name').value;
    const fingerprint = document.getElementById('voter-form-fingerprint').value;
    const voted = document.getElementById('voter-form-voted').value;
    
    const payload = {
        rfid_id: rfid,
        name: name,
        fingerprint_id: parseInt(fingerprint),
        has_voted: parseInt(voted)
    };
    
    const url = oldRfid ? `/api/voters/${encodeURIComponent(oldRfid)}` : '/api/voters';
    const method = oldRfid ? 'PUT' : 'POST';
    
    try {
        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (response.ok && result.status === 'success') {
            closeVoterModal();
            loadVoters();
            // Refresh stats
            fetch('/api/dashboard/stats')
                .then(res => res.json())
                .then(updateDashboardUI)
                .catch(err => console.error(err));
        } else {
            alert('Save failed: ' + (result.message || 'Unknown error'));
        }
    } catch (err) {
        console.error('Save voter failed:', err);
        alert('Save voter failed: ' + err.message);
    }
}

async function deleteVoter(rfid_id) {
    if (!confirm(`Are you sure you want to delete voter RFID ${rfid_id}? This will also remove any votes cast by this voter.`)) return;
    
    try {
        const response = await fetch(`/api/voters/${encodeURIComponent(rfid_id)}`, {
            method: 'DELETE'
        });
        const result = await response.json();
        if (response.ok && result.status === 'success') {
            loadVoters();
            // Refresh stats
            fetch('/api/dashboard/stats')
                .then(res => res.json())
                .then(updateDashboardUI)
                .catch(err => console.error(err));
        } else {
            alert('Delete failed: ' + (result.message || 'Unknown error'));
        }
    } catch (err) {
        console.error('Delete voter failed:', err);
        alert('Delete voter failed: ' + err.message);
    }
}

function openImportVotersModal() {
    document.getElementById('csv-file-input').value = '';
    document.getElementById('csv-filename-label').textContent = 'Drag & drop or browse file';
    document.getElementById('import-voters-modal').classList.remove('hidden');
}

function closeImportVotersModal() {
    document.getElementById('import-voters-modal').classList.add('hidden');
}

function handleCSVFileSelection(input) {
    if (input.files && input.files.length > 0) {
        document.getElementById('csv-filename-label').textContent = input.files[0].name;
    } else {
        document.getElementById('csv-filename-label').textContent = 'Drag & drop or browse file';
    }
}

async function submitImportVoters(event) {
    event.preventDefault();
    const fileInput = document.getElementById('csv-file-input');
    if (!fileInput.files || fileInput.files.length === 0) {
        alert('Please select a CSV file first');
        return;
    }
    
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);
    
    const btn = document.getElementById('btn-import-voters');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Importing...';
    
    try {
        const response = await fetch('/api/voters/bulk-import', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (response.ok && result.status === 'success') {
            closeImportVotersModal();
            loadVoters();
            alert(`Import successful! ${result.inserted} voter records imported.`);
            // Refresh stats
            fetch('/api/dashboard/stats')
                .then(res => res.json())
                .then(updateDashboardUI)
                .catch(err => console.error(err));
        } else {
            alert('Import failed: ' + (result.message || 'Unknown error'));
        }
    } catch (err) {
        console.error('Import voters failed:', err);
        alert('Import voters failed: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-file-import"></i> Upload & Import';
    }
}

// ==========================================
// PHASE 6: ADMIN REGISTRY CRUD HANDLERS
// ==========================================

async function loadAdmins() {
    if (userRole !== 'SUPER_ADMIN') return;
    try {
        const response = await fetch('/api/admins');
        const data = await response.json();
        adminsList = data.admins || [];
        renderAdminsTable();
    } catch (err) {
        console.error('Failed to load admins list:', err);
    }
}

function renderAdminsTable() {
    const tbody = document.getElementById('admin-table-body');
    if (!tbody) return;
    
    if (adminsList.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-textmuted font-semibold">No administrator records found.</td></tr>`;
        return;
    }
    
    let html = '';
    adminsList.forEach(adm => {
        const statusBadge = adm.status === 'ACTIVE'
            ? '<span class="inline-block text-[10px] bg-successgreen/10 border border-successgreen/20 text-successgreen font-bold px-2 py-0.5 rounded font-sans uppercase">ACTIVE</span>'
            : '<span class="inline-block text-[10px] bg-dangered/10 border border-dangered/20 text-dangered font-bold px-2 py-0.5 rounded font-sans uppercase">INACTIVE</span>';
            
        const isSelf = adm.username === username;
        const actionsHtml = `
            <td class="p-4 text-center font-sans">
                <div class="flex items-center justify-center gap-2">
                    <button onclick="editAdmin('${escapeHTML(adm.username)}')" title="Edit Admin" class="h-7 w-7 rounded-lg bg-accentblue/10 hover:bg-accentblue hover:text-white text-accentblue flex items-center justify-center transition-all border border-accentblue/20">
                        <i class="fa-solid fa-pen text-[10px]"></i>
                    </button>
                    ${isSelf ? '' : `
                    <button onclick="deleteAdmin('${escapeHTML(adm.username)}')" title="Delete Admin" class="h-7 w-7 rounded-lg bg-dangered/10 hover:bg-dangered hover:text-white text-dangered flex items-center justify-center transition-all border border-dangered/20">
                        <i class="fa-solid fa-trash-can text-[10px]"></i>
                    </button>
                    `}
                </div>
            </td>
        `;
        
        const createdDate = adm.created_at ? adm.created_at.replace('T', ' ').split('.')[0] : '--';
        
        html += `
        <tr class="hover:bg-white/5 transition-all">
            <td class="p-4 font-bold text-white font-sans">${escapeHTML(adm.username)} ${isSelf ? '<span class="text-[9px] text-accentblue bg-accentblue/10 border border-accentblue/25 px-1 rounded ml-1 font-sans">YOU</span>' : ''}</td>
            <td class="p-4 text-accentblue font-mono font-bold">${escapeHTML(adm.role)}</td>
            <td class="p-4 text-center">${statusBadge}</td>
            <td class="p-4 text-right text-textmuted">${escapeHTML(createdDate)}</td>
            ${actionsHtml}
        </tr>`;
    });
    
    tbody.innerHTML = html;
}

function openAddAdminModal() {
    document.getElementById('admin-modal-title').textContent = 'Create Administrator Account';
    document.getElementById('admin-form-type').value = 'ADD';
    document.getElementById('admin-form-username').value = '';
    document.getElementById('admin-form-username').disabled = false;
    document.getElementById('admin-form-password').value = '';
    document.getElementById('admin-form-password').required = true;
    document.getElementById('admin-form-password').placeholder = 'Enter account password';
    document.getElementById('admin-form-role').value = 'VIEWER';
    document.getElementById('admin-form-status').value = 'ACTIVE';
    document.getElementById('admin-modal').classList.remove('hidden');
}

function closeAdminModal() {
    document.getElementById('admin-modal').classList.add('hidden');
}

function editAdmin(usernameParam) {
    const adm = adminsList.find(a => a.username === usernameParam);
    if (!adm) return;
    
    document.getElementById('admin-modal-title').textContent = 'Modify Administrator Account';
    document.getElementById('admin-form-type').value = 'EDIT';
    document.getElementById('admin-form-username').value = adm.username;
    document.getElementById('admin-form-username').disabled = true;
    document.getElementById('admin-form-password').value = '';
    document.getElementById('admin-form-password').required = false;
    document.getElementById('admin-form-password').placeholder = 'Keep empty to leave password unchanged';
    document.getElementById('admin-form-role').value = adm.role;
    document.getElementById('admin-form-status').value = adm.status || 'ACTIVE';
    document.getElementById('admin-modal').classList.remove('hidden');
}

async function saveAdminForm(event) {
    event.preventDefault();
    const type = document.getElementById('admin-form-type').value;
    const usernameParam = document.getElementById('admin-form-username').value;
    const password = document.getElementById('admin-form-password').value;
    const role = document.getElementById('admin-form-role').value;
    const status = document.getElementById('admin-form-status').value;
    
    const payload = {
        role: role,
        status: status
    };
    if (password) {
        payload.password = password;
    }
    
    let url = '/api/admins';
    let method = 'POST';
    
    if (type === 'EDIT') {
        url = `/api/admins/${encodeURIComponent(usernameParam)}`;
        method = 'PUT';
    } else {
        payload.username = usernameParam;
    }
    
    try {
        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (response.ok && result.status === 'success') {
            closeAdminModal();
            loadAdmins();
        } else {
            alert('Save failed: ' + (result.message || 'Unknown error'));
        }
    } catch (err) {
        console.error('Save admin failed:', err);
        alert('Save admin failed: ' + err.message);
    }
}

async function deleteAdmin(usernameParam) {
    if (!confirm(`Are you sure you want to delete administrator account '${usernameParam}'?`)) return;
    
    try {
        const response = await fetch(`/api/admins/${encodeURIComponent(usernameParam)}`, {
            method: 'DELETE'
        });
        const result = await response.json();
        if (response.ok && result.status === 'success') {
            loadAdmins();
        } else {
            alert('Delete failed: ' + (result.message || 'Unknown error'));
        }
    } catch (err) {
        console.error('Delete admin failed:', err);
        alert('Delete admin failed: ' + err.message);
    }
}

// ========================================================
// LIVE AUTHENTICATION MONITOR & HARDWARE PANEL FUNCTIONS
// ========================================================

function appendLiveAuthEvent(data) {
    const monitor = document.getElementById('live-auth-monitor-log');
    if (!monitor) return;
    
    const placeholder = document.getElementById('auth-monitor-empty');
    if (placeholder) placeholder.remove();
    
    const line = document.createElement('div');
    line.className = 'flex items-start justify-between border-b border-darkborder/35 pb-2 text-[10px]';
    
    const isSuccess = data.is_success;
    const indicatorColor = isSuccess ? 'bg-successgreen' : 'bg-dangered';
    const textColor = isSuccess ? 'text-white font-semibold' : 'text-dangered font-bold';
    
    const ts = data.timestamp ? data.timestamp.split('T')[1] || data.timestamp : '--:--:--';
    const cleanTs = ts.includes('+') ? ts.split('+')[0] : ts;
    
    line.innerHTML = `
        <div class="flex items-center gap-2">
            <span class="h-2 w-2 rounded-full ${indicatorColor} ${isSuccess ? 'animate-pulse' : ''}"></span>
            <span class="${textColor} font-sans">${escapeHTML(data.event_type)}</span>
            <span class="text-textmuted">${escapeHTML(data.details)}</span>
        </div>
        <span class="text-textmuted font-mono text-[9px]">${escapeHTML(cleanTs)}</span>
    `;
    
    monitor.insertBefore(line, monitor.firstChild);
    
    while (monitor.children.length > 30) {
        monitor.removeChild(monitor.lastChild);
    }
}

function updateHardwareStatusPanel(data) {
    if (!data || !data.component.startsWith('booth:')) return;
    
    // ESP32 Status
    const esp32Badge = document.getElementById('hw-status-esp32');
    if (esp32Badge) {
        const isOnline = data.status === 'ONLINE';
        esp32Badge.className = `font-bold flex items-center gap-1.5 ${isOnline ? 'text-successgreen' : 'text-dangered'}`;
        esp32Badge.innerHTML = `<span class="h-2 w-2 rounded-full ${isOnline ? 'bg-successgreen animate-pulse' : 'bg-dangered'}"></span>${isOnline ? 'ONLINE' : 'OFFLINE'}`;
    }
    
    // RFID Reader Status
    const rfidBadge = document.getElementById('hw-status-rfid');
    if (rfidBadge) {
        const rfidState = data.rfid_status || 'IDLE';
        let rfidColor = 'text-textmuted';
        let rfidDot = 'bg-gray-600';
        if (rfidState === 'VALIDATING') { rfidColor = 'text-warningyellow'; rfidDot = 'bg-warningyellow animate-pulse'; }
        else if (rfidState === 'SCANNED') { rfidColor = 'text-successgreen'; rfidDot = 'bg-successgreen'; }
        rfidBadge.className = `font-bold flex items-center gap-1.5 ${rfidColor}`;
        rfidBadge.innerHTML = `<span class="h-2 w-2 rounded-full ${rfidDot}"></span>${rfidState}`;
    }
    
    // Fingerprint Sensor Status
    const fingerBadge = document.getElementById('hw-status-fingerprint');
    if (fingerBadge) {
        const fingerState = data.fingerprint_status || 'IDLE';
        let fingerColor = 'text-textmuted';
        let fingerDot = 'bg-gray-600';
        if (fingerState === 'SCANNING') { fingerColor = 'text-warningyellow'; fingerDot = 'bg-warningyellow animate-pulse'; }
        else if (fingerState === 'VERIFIED') { fingerColor = 'text-successgreen'; fingerDot = 'bg-successgreen'; }
        fingerBadge.className = `font-bold flex items-center gap-1.5 ${fingerColor}`;
        fingerBadge.innerHTML = `<span class="h-2 w-2 rounded-full ${fingerDot}"></span>${fingerState}`;
    }
    
    // LCD Status
    const lcdText = document.getElementById('hw-status-lcd');
    if (lcdText) {
        lcdText.textContent = data.lcd_status || 'Offline';
    }
    
    // Active Booth Count
    const activeCount = document.getElementById('hw-status-active-booths');
    if (activeCount) {
        const count = Object.values(booths).filter(b => b.status === 'ONLINE').length;
        activeCount.textContent = count;
    }
    
    // Last Device Heartbeat Time
    const heartbeatText = document.getElementById('hw-status-heartbeat');
    if (heartbeatText) {
        const now = new Date();
        heartbeatText.textContent = now.toLocaleTimeString();
    }
}

// ========================================================
// DEMO MODE WORKFLOW INTERACTIVE SIMULATOR
// ========================================================

let demoFlowState = {
    step: 0, // 0: IDLE, 1: RFID_SCANNED, 2: RFID_VERIFIED, 3: FINGER_VERIFIED, 4: BALLOT_UNLOCKED, 5: VOTE_SUBMITTED
    voter: null,
    candidate: 'A',
    autoPilotTimer: null,
    isAutoPilot: false
};

function logFlowConsole(msg, isSuccess = true) {
    const text = document.getElementById('flow-console-text');
    if (!text) return;
    const color = isSuccess ? 'text-successgreen' : 'text-dangered font-bold animate-pulse';
    text.className = `text-xs font-mono leading-relaxed ${color}`;
    text.textContent = msg;
}

function updateFlowStateLabels() {
    const voterLabel = document.getElementById('flow-voter-info');
    const stateLabel = document.getElementById('flow-step-indicator');
    
    if (voterLabel) {
        voterLabel.textContent = `Voter: ${demoFlowState.voter ? demoFlowState.voter.name : 'None'}`;
    }
    if (stateLabel) {
        const states = ['IDLE', 'RFID_SCANNED', 'RFID_VERIFIED', 'FINGER_VERIFIED', 'BALLOT_UNLOCKED', 'VOTE_SUBMITTED'];
        stateLabel.textContent = `State: ${states[demoFlowState.step] || 'IDLE'}`;
    }
}

function highlightFlowStep(stepNum, status = 'active') {
    const stepDiv = document.getElementById(`flow-step-${stepNum}`);
    const circleDiv = document.getElementById(`flow-circle-${stepNum}`);
    if (!stepDiv || !circleDiv) return;
    
    if (status === 'active') {
        stepDiv.className = "bg-successgreen/10 p-4 border border-successgreen/50 rounded-2xl flex flex-col justify-between items-center gap-3 transition-all duration-300 shadow-lg shadow-successgreen/5 scale-105";
        circleDiv.className = "h-10 w-10 rounded-full bg-successgreen border border-successgreen flex items-center justify-center text-darkbg text-lg font-bold animate-pulse";
    } else if (status === 'completed') {
        stepDiv.className = "bg-gray-950/40 p-4 border border-successgreen/20 rounded-2xl flex flex-col justify-between items-center gap-3 transition-all duration-300";
        circleDiv.className = "h-10 w-10 rounded-full bg-successgreen/20 border border-successgreen/40 flex items-center justify-center text-successgreen text-lg font-bold";
    } else {
        stepDiv.className = "bg-gray-950/60 p-4 border border-darkborder rounded-2xl flex flex-col justify-between items-center gap-3 transition-all duration-300";
        circleDiv.className = "h-10 w-10 rounded-full bg-gray-800 border border-darkborder flex items-center justify-center text-textmuted text-lg font-bold";
    }
}

async function sendSimulatorHeartbeat(fsmState, lcdStatus, rfidStatus, fingerprintStatus) {
    try {
        await fetch('/api/demo/booth-heartbeat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                booth_id: 'BOOTH001',
                fsm_state: fsmState,
                lcd_status: lcdStatus,
                rfid_status: rfidStatus,
                fingerprint_status: fingerprintStatus,
                current_voter: demoFlowState.voter ? demoFlowState.voter.name : '',
                wifi_status: 'CONNECTED',
                mqtt_status: 'CONNECTED',
                free_heap: 48500,
                buffered_votes: 0,
                firmware_version: 'v1.2.0'
            })
        });
    } catch (err) {
        console.error('Failed to emit simulated heartbeat:', err);
    }
}

async function demoStepRFIDScan() {
    if (demoFlowState.step !== 0) {
        demoStepReset();
    }
    
    // Pick random voter
    let selectedVoter = null;
    if (typeof votersList !== 'undefined' && votersList.length > 0) {
        // filter those who haven't voted for better demo experience
        const eligible = votersList.filter(v => parseInt(v.has_voted) === 0);
        const list = eligible.length > 0 ? eligible : votersList;
        selectedVoter = list[Math.floor(Math.random() * list.length)];
    } else {
        selectedVoter = { rfid_id: "A1:B2:C3:D4", name: "Ravi Kumar", fingerprint_id: 1 };
    }
    
    demoFlowState.voter = selectedVoter;
    demoFlowState.step = 1;
    
    logFlowConsole(`RFID Sensor Triggered: Card detected. Querying backend...`);
    updateFlowStateLabels();
    highlightFlowStep(1, 'active');
    
    // Emit heartbeat: RFID scanning state
    await sendSimulatorHeartbeat('WAITING_RFID_VALIDATION', 'Checking Voter...', 'VALIDATING', 'IDLE');
    
    try {
        const response = await fetch('/api/verify-rfid', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rfid_uid: selectedVoter.rfid_id })
        });
        const result = await response.json();
        
        if (response.ok && result.registered) {
            highlightFlowStep(1, 'completed');
            highlightFlowStep(2, 'active');
            demoFlowState.step = 2;
            logFlowConsole(`Voter identity loaded: [Name: ${result.name}, RFID: ${selectedVoter.rfid_id}]. Please click "Verify RFID" to confirm database registration.`);
            document.getElementById('btn-flow-verify-rfid').disabled = false;
            document.getElementById('btn-flow-verify-rfid').className = "w-full py-1.5 rounded-lg bg-accentblue hover:bg-blue-600 text-white font-bold text-[10px] transition-all";
            updateFlowStateLabels();
            
            // Emit heartbeat: RFID matched and verified
            await sendSimulatorHeartbeat('PROMPT_FINGERPRINT', 'Welcome, ' + result.name, 'SCANNED', 'IDLE');
        } else {
            highlightFlowStep(1, 'active');
            logFlowConsole(`RFID Lookup failed: ${result.message || 'Voter unregistered.'}`, false);
            demoFlowState.step = 0;
            updateFlowStateLabels();
            
            // Emit heartbeat: Rejected card
            await sendSimulatorHeartbeat('REJECTED', 'Voter Not Found', 'IDLE', 'IDLE');
        }
    } catch (err) {
        console.error(err);
        logFlowConsole(`Network error checking RFID: ${err.message}`, false);
        demoFlowState.step = 0;
        updateFlowStateLabels();
        await sendSimulatorHeartbeat('REJECTED', 'System Error', 'IDLE', 'IDLE');
    }
}

async function demoStepRFIDVerify() {
    if (demoFlowState.step !== 2) return;
    
    highlightFlowStep(2, 'completed');
    highlightFlowStep(3, 'active');
    demoFlowState.step = 3;
    
    logFlowConsole(`RFID Confirmed. LCD reads: "Scan Finger". Requesting fingerprint match for Slot #${demoFlowState.voter.fingerprint_id}. Click "Verify Finger" to perform biometric validation.`);
    
    // Disable current button
    const btnVerify = document.getElementById('btn-flow-verify-rfid');
    btnVerify.disabled = true;
    btnVerify.className = "w-full py-1.5 rounded-lg bg-gray-800 text-gray-500 font-bold text-[10px] cursor-not-allowed transition-all";
    
    // Enable finger button
    const btnFinger = document.getElementById('btn-flow-finger');
    btnFinger.disabled = false;
    btnFinger.className = "w-full py-1.5 rounded-lg bg-accentblue hover:bg-blue-600 text-white font-bold text-[10px] transition-all";
    
    updateFlowStateLabels();
    
    // Emit heartbeat: Prompts for fingerprint
    await sendSimulatorHeartbeat('WAITING_FINGERPRINT', 'Scan Finger', 'SCANNED', 'SCANNING');
}

async function demoStepFingerVerify() {
    if (demoFlowState.step !== 3) return;
    
    logFlowConsole(`Processing fingerprint scan...`);
    await sendSimulatorHeartbeat('WAITING_FINGERPRINT', 'Processing...', 'SCANNED', 'SCANNING');
    
    try {
        const response = await fetch('/api/verify-fingerprint', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rfid_uid: demoFlowState.voter.rfid_id,
                fingerprint_id: demoFlowState.voter.fingerprint_id
            })
        });
        const result = await response.json();
        
        if (response.ok && result.verified) {
            highlightFlowStep(3, 'completed');
            highlightFlowStep(4, 'active');
            demoFlowState.step = 4;
            
            logFlowConsole(`Biometric Match Successful. LCD reads: "Select Candidate". Ballot is unlocked. Choose your candidate using the dropdown and click "Submit Vote".`);
            
            // Disable finger button
            const btnFinger = document.getElementById('btn-flow-finger');
            btnFinger.disabled = true;
            btnFinger.className = "w-full py-1.5 rounded-lg bg-gray-800 text-gray-500 font-bold text-[10px] cursor-not-allowed transition-all";
            
            // Enable candidate select & vote button
            const candSelect = document.getElementById('flow-candidate-select');
            candSelect.disabled = false;
            candSelect.className = "w-full bg-darkbg border border-darkborder py-1 px-1.5 text-[10px] rounded text-white focus:outline-none focus:border-accentblue font-bold cursor-pointer";
            
            const btnVote = document.getElementById('btn-flow-vote');
            btnVote.disabled = false;
            btnVote.className = "w-full py-1.5 rounded-lg bg-accentblue hover:bg-blue-600 text-white font-bold text-[10px] transition-all";
            
            updateFlowStateLabels();
            
            // Emit heartbeat: Fingerprint OK
            await sendSimulatorHeartbeat('PROMPT_CANDIDATE', 'Select Candidate', 'SCANNED', 'VERIFIED');
        } else {
            highlightFlowStep(3, 'active');
            logFlowConsole(`Biometric mismatch! Fingerprint verification failed. LCD: "Auth Mismatch".`, false);
            await sendSimulatorHeartbeat('REJECTED', 'Auth Mismatch', 'SCANNED', 'IDLE');
        }
    } catch (err) {
        console.error(err);
        logFlowConsole(`Network error checking fingerprint: ${err.message}`, false);
        await sendSimulatorHeartbeat('REJECTED', 'System Error', 'SCANNED', 'IDLE');
    }
}

async function demoStepVoteSubmit() {
    if (demoFlowState.step !== 4) return;
    
    const candidate = document.getElementById('flow-candidate-select').value;
    demoFlowState.candidate = candidate;
    
    logFlowConsole(`Encrypting ballot and generating signature payload...`);
    await sendSimulatorHeartbeat('SUBMITTING_VOTE', 'Sending Vote...', 'SCANNED', 'VERIFIED');
    
    try {
        const response = await fetch('/api/vote', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rfid_uid: demoFlowState.voter.rfid_id,
                candidate: candidate
            })
        });
        const result = await response.json();
        
        if (response.ok && result.status === 'accepted') {
            highlightFlowStep(4, 'completed');
            highlightFlowStep(5, 'completed');
            highlightFlowStep(6, 'active');
            demoFlowState.step = 5;
            
            logFlowConsole(`Vote cast successfully! Transaction ID: ${result.vote_id}. Marked voter '${demoFlowState.voter.name}' as Voted. LCD reads: "Vote Recorded". Dashboard is syncing...`);
            
            // Disable inputs
            const candSelect = document.getElementById('flow-candidate-select');
            candSelect.disabled = true;
            candSelect.className = "w-full bg-darkbg border border-darkborder py-1 px-1.5 text-[10px] rounded text-white focus:outline-none focus:border-accentblue font-bold cursor-not-allowed";
            
            const btnVote = document.getElementById('btn-flow-vote');
            btnVote.disabled = true;
            btnVote.className = "w-full py-1.5 rounded-lg bg-gray-800 text-gray-500 font-bold text-[10px] cursor-not-allowed transition-all";
            
            updateFlowStateLabels();
            
            // Emit heartbeat: Vote submission complete
            await sendSimulatorHeartbeat('VOTE_CONFIRMED', 'Vote Recorded!', 'SCANNED', 'VERIFIED');
            
            // Trigger visual glow on dashboard sync step
            setTimeout(() => {
                highlightFlowStep(6, 'completed');
            }, 1500);
            
        } else {
            highlightFlowStep(5, 'active');
            logFlowConsole(`Vote rejected: ${result.message || 'Tampering or Replay exploit block.'}`, false);
            await sendSimulatorHeartbeat('REJECTED', 'Vote Rejected', 'SCANNED', 'VERIFIED');
        }
    } catch (err) {
        console.error(err);
        logFlowConsole(`Network error submitting vote: ${err.message}`, false);
        await sendSimulatorHeartbeat('REJECTED', 'System Error', 'SCANNED', 'VERIFIED');
    }
}

async function demoStepReset() {
    // Clear auto-pilot if running
    if (demoFlowState.autoPilotTimer) {
        clearInterval(demoFlowState.autoPilotTimer);
        demoFlowState.autoPilotTimer = null;
    }
    demoFlowState.isAutoPilot = false;
    
    const btnAutopilot = document.getElementById('btn-flow-autopilot');
    if (btnAutopilot) {
        btnAutopilot.innerHTML = '<i class="fa-solid fa-play"></i> Start Auto-Pilot';
        btnAutopilot.className = "w-full py-2.5 rounded-xl bg-gradient-to-r from-warningyellow to-amber-600 hover:from-amber-600 hover:to-warningyellow text-white font-extrabold text-xs uppercase tracking-wider shadow-lg shadow-warningyellow/10 transition-all flex items-center justify-center gap-1.5";
    }
    
    demoFlowState.step = 0;
    demoFlowState.voter = null;
    updateFlowStateLabels();
    
    // Reset highlights
    for (let i = 1; i <= 6; i++) {
        highlightFlowStep(i, 'inactive');
    }
    
    // Reset buttons
    const btnVerify = document.getElementById('btn-flow-verify-rfid');
    btnVerify.disabled = true;
    btnVerify.className = "w-full py-1.5 rounded-lg bg-gray-800 text-gray-500 font-bold text-[10px] cursor-not-allowed transition-all";
    
    const btnFinger = document.getElementById('btn-flow-finger');
    btnFinger.disabled = true;
    btnFinger.className = "w-full py-1.5 rounded-lg bg-gray-800 text-gray-500 font-bold text-[10px] cursor-not-allowed transition-all";
    
    const candSelect = document.getElementById('flow-candidate-select');
    candSelect.disabled = true;
    candSelect.className = "w-full bg-darkbg border border-darkborder py-1 px-1.5 text-[10px] rounded text-white focus:outline-none focus:border-accentblue font-bold cursor-not-allowed";
    
    const btnVote = document.getElementById('btn-flow-vote');
    btnVote.disabled = true;
    btnVote.className = "w-full py-1.5 rounded-lg bg-gray-800 text-gray-500 font-bold text-[10px] cursor-not-allowed transition-all";
    
    logFlowConsole("System ready. Click \"Scan RFID\" to begin the step-by-step voting simulation.");
    
    // Emit heartbeat: Reset to IDLE
    await sendSimulatorHeartbeat('IDLE', 'Ready For Voter', 'IDLE', 'IDLE');
}

function demoAutoPilotStart() {
    const btn = document.getElementById('btn-flow-autopilot');
    if (demoFlowState.isAutoPilot) {
        demoStepReset();
        return;
    }
    
    demoStepReset();
    demoFlowState.isAutoPilot = true;
    btn.innerHTML = '<i class="fa-solid fa-stop"></i> Stop Auto-Pilot';
    btn.className = "w-full py-2.5 rounded-xl bg-dangered hover:bg-red-600 text-white font-extrabold text-xs uppercase tracking-wider shadow-lg shadow-red-500/10 transition-all flex items-center justify-center gap-1.5";
    
    // Auto-pilot sequence
    demoStepRFIDScan();
    
    let subStep = 0;
    demoFlowState.autoPilotTimer = setInterval(() => {
        subStep++;
        if (subStep === 1) {
            demoStepRFIDVerify();
        } else if (subStep === 2) {
            demoStepFingerVerify();
        } else if (subStep === 3) {
            // Select random candidate
            const candidates = ['A', 'B', 'C'];
            const select = document.getElementById('flow-candidate-select');
            if (select) {
                select.value = candidates[Math.floor(Math.random() * candidates.length)];
            }
            demoStepVoteSubmit();
        } else if (subStep === 4) {
            logFlowConsole("Auto-pilot sequence completed successfully. Resetting in 5 seconds...");
        } else if (subStep >= 6) {
            demoStepReset();
        }
    }, 2500);
}
