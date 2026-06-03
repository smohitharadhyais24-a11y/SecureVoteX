"""Dashboard client-side loader for the live vote summary."""

async function loadDashboard() {
    const resultsResponse = await fetch('/api/results');
    const results = await resultsResponse.json();
    const auditResponse = await fetch('/api/audit');
    const audit = await auditResponse.json();

    document.getElementById('total-voters').textContent = results.total_voters ?? 0;
    document.getElementById('total-votes').textContent = results.total_votes ?? 0;
    const auditItems = audit.audit_log ?? [];
    document.getElementById('audit-count').textContent = auditItems.length;

    const candidateList = document.getElementById('candidate-list');
    candidateList.innerHTML = '';
    const candidateCounts = results.candidate_counts ?? {};
    ['A', 'B', 'C'].forEach((candidate) => {
        const item = document.createElement('div');
        item.className = 'tally';
        item.innerHTML = `<span>Candidate ${candidate}</span><strong>${candidateCounts[candidate] ?? 0}</strong>`;
        candidateList.appendChild(item);
    });

    const auditList = document.getElementById('audit-list');
    auditList.innerHTML = '';
    auditItems.slice(0, 10).forEach((entry) => {
        const row = document.createElement('div');
        row.className = `event ${entry.event_type?.includes('REJECTED') || entry.event_type === 'TAMPER_DETECTED' ? 'danger' : ''}`;
        row.innerHTML = `<strong>${entry.event_type}</strong><div>${entry.details}</div><small>${entry.timestamp} | ${entry.rfid_id ?? 'n/a'}</small>`;
        auditList.appendChild(row);
    });
}

loadDashboard().catch((error) => {
    console.error('Failed to load dashboard data:', error);
});
