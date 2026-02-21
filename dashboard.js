async function fetchStats() {
    try {
        const res = await fetch('/api/dashboard_stats');
        const data = await res.json();

        document.getElementById('total-analyses').innerText = data.total_analyses;
        document.getElementById('defendface-count').innerText = data.defendface_count;
        document.getElementById('phishing-count').innerText = data.phishing_count;

        // Update timeline
        const timeline = document.getElementById('activity-timeline');
        timeline.innerHTML = '';
        
        if (data.recent && data.recent.length > 0) {
            data.recent.forEach(item => {
                const itemDiv = document.createElement('div');
                itemDiv.className = 'timeline-item';
                
                let icon = '';
                let color = '';
                if (item.type === 'defendface') {
                    icon = '🧠';
                    color = '#38bdf8';
                } else {
                    icon = '🎣';
                    color = '#facc15';
                }
                
                const resultColor = (item.result === 'fake' || item.result === 'phishing') ? '#ef4444' : '#22c55e';
                
                itemDiv.innerHTML = `
                    <div class="timeline-icon" style="background: rgba(${color},0.1); color: ${color};">${icon}</div>
                    <div class="timeline-content">
                        <div class="timeline-title">${item.type === 'defendface' ? 'DefendFace Scan' : 'Phishing Analysis'}</div>
                        <div class="timeline-meta">
                            <span><i class="fas fa-clock"></i> ${item.timestamp}</span>
                            <span style="color: ${resultColor};">${item.result.toUpperCase()}</span>
                            <span>${item.confidence}% confidence</span>
                        </div>
                    </div>
                    <button class="timeline-badge" onclick="window.location.href='/api/download_report/${item.id}'">
                        <i class="fas fa-download"></i>
                    </button>
                `;
                timeline.appendChild(itemDiv);
            });
        } else {
            timeline.innerHTML = '<p style="text-align:center; color:#94a3b8; padding:30px;">No recent activity</p>';
        }

        // Update chart
        updateChart(data);
    } catch (err) {
        console.error('Failed to fetch stats', err);
    }
}

// Chart initialization
let ctx = document.getElementById('threatChart')?.getContext('2d');
let threatChart;

if (ctx) {
    threatChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
            datasets: [
                {
                    label: 'DefendFace Detections',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: '#38bdf8',
                    backgroundColor: 'rgba(56,189,248,0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Phishing Detections',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: '#facc15',
                    backgroundColor: 'rgba(250,204,21,0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#e5e7eb' }
                }
            },
            scales: {
                x: { ticks: { color: '#94a3b8' } },
                y: { ticks: { color: '#94a3b8' } }
            }
        }
    });
}

function updateChart(stats) {
    if (!threatChart) return;
    // Shift data (simple simulation)
    threatChart.data.datasets[0].data.shift();
    threatChart.data.datasets[0].data.push(stats.defendface_count);
    threatChart.data.datasets[1].data.shift();
    threatChart.data.datasets[1].data.push(stats.phishing_count);
    threatChart.update();
}

// Auto refresh
setInterval(fetchStats, 5000);
fetchStats();