let currentAnalysisId = null;

// ========== HELPER: UPDATE ANALYZE BUTTON STATE ==========
function updateAnalyzeButton(inputId, btnId) {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);
    btn.disabled = !input.files.length;
}

// ========== PREVIEW GENERATION ==========
function setupPreview(inputId, previewId, fileType) {
    const input = document.getElementById(inputId);
    const preview = document.getElementById(previewId);

    input.addEventListener('change', function() {
        preview.innerHTML = '';
        if (this.files && this.files[0]) {
            const file = this.files[0];
            const reader = new FileReader();

            reader.onload = function(e) {
                const previewItem = document.createElement('div');
                previewItem.className = 'preview-item';

                if (fileType === 'image') {
                    const img = document.createElement('img');
                    img.src = e.target.result;
                    previewItem.appendChild(img);
                } else if (fileType === 'video') {
                    const video = document.createElement('video');
                    video.src = e.target.result;
                    video.controls = true;
                    video.muted = true;
                    previewItem.appendChild(video);
                }

                const removeBtn = document.createElement('button');
                removeBtn.className = 'remove-btn';
                removeBtn.innerHTML = '✕';
                removeBtn.addEventListener('click', function(ev) {
                    ev.stopPropagation();
                    input.value = '';
                    preview.innerHTML = '';
                    updateAnalyzeButton(inputId, inputId === 'imageInput' ? 'analyzeImageBtn' : 'analyzeVideoBtn');
                });
                previewItem.appendChild(removeBtn);
                preview.appendChild(previewItem);
            };

            reader.readAsDataURL(file);
        }
        updateAnalyzeButton(inputId, inputId === 'imageInput' ? 'analyzeImageBtn' : 'analyzeVideoBtn');
    });
}

// Initialize previews
setupPreview('imageInput', 'imagePreview', 'image');
setupPreview('videoInput', 'videoPreview', 'video');

// ========== IMAGE ANALYSIS ==========
async function analyzeImage() {
    const input = document.getElementById('imageInput');
    if (!input.files.length) {
        alert('Please select an image');
        return;
    }
    showLoading('image');

    const formData = new FormData();
    formData.append('file', input.files[0]);
    formData.append('type', 'image');

    try {
        const response = await fetch('/api/defendface/analyze', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.error) {
            alert('Error: ' + result.error);
            return;
        }
        currentAnalysisId = result.analysis_id;
        displayResult(result);
    } catch (error) {
        alert('Network error. Please try again.');
    }
}

// ========== VIDEO ANALYSIS ==========
async function analyzeVideo() {
    const input = document.getElementById('videoInput');
    if (!input.files.length) {
        alert('Please select a video');
        return;
    }
    showLoading('video');

    const formData = new FormData();
    formData.append('file', input.files[0]);
    formData.append('type', 'video');

    try {
        const response = await fetch('/api/defendface/analyze', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        if (result.error) {
            alert('Error: ' + result.error);
            return;
        }
        currentAnalysisId = result.analysis_id;
        displayResult(result);
    } catch (error) {
        alert('Network error. Please try again.');
    }
}

// ========== LIVE CAMERA ==========
async function captureAndAnalyze() {
    const video = document.getElementById('camera');
    if (!video.srcObject) {
        alert('Start camera first');
        return;
    }
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    canvas.toBlob(async (blob) => {
        const formData = new FormData();
        formData.append('file', blob, 'capture.jpg');
        formData.append('type', 'image');
        showLoading('camera');
        try {
            const response = await fetch('/api/defendface/analyze', { 
                method: 'POST', 
                body: formData 
            });
            const result = await response.json();
            currentAnalysisId = result.analysis_id;
            displayResult(result);
        } catch (e) {
            alert('Analysis failed');
        }
    }, 'image/jpeg');
}

// ========== START CAMERA ==========
async function startCamera() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        const video = document.getElementById('camera');
        video.srcObject = stream;
    } catch (err) {
        alert('Camera access denied or not available');
    }
}

// ========== DISPLAY RESULT ==========
function displayResult(result) {
    const panel = document.getElementById('resultPanel');
    const content = document.getElementById('resultContent');
    const badge = document.getElementById('resultBadge');
    
    const isDeepfake = result.is_deepfake;
    badge.innerText = isDeepfake ? '⚠ DEEPFAKE DETECTED' : '✓ AUTHENTIC';
    badge.style.background = isDeepfake ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)';
    badge.style.color = isDeepfake ? '#ef4444' : '#22c55e';
    badge.style.borderColor = isDeepfake ? '#ef4444' : '#22c55e';

    const prob = result.deepfake_probability;
    let meterClass = 'low';
    if (prob > 70) meterClass = 'high';
    else if (prob > 40) meterClass = 'medium';

    // Build extra info for video if frame_count exists
    let extraInfo = '';
    if (result.frame_count) {
        extraInfo = `
            <div style="margin-top:20px; background:#0f172a; padding:15px; border-radius:12px;">
                <h4 style="margin-bottom:8px;">🎬 Video Analysis Details</h4>
                <p>Frames analyzed: ${result.frame_count}</p>
                <p>Average confidence across frames: ${result.confidence}%</p>
            </div>
        `;
    }

    // Main result HTML (gauge + meter bar)
    content.innerHTML = `
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 30px;">
            <div>
                <h4 style="color:#94a3b8; margin-bottom:15px;">Deepfake Probability</h4>
                <div class="gauge-container">
                    <div class="gauge">
                        <div class="gauge-fill" style="height: ${prob}%;"></div>
                    </div>
                </div>
                <p class="probability-value" style="color:${isDeepfake ? '#ef4444' : '#22c55e'};">${prob}%</p>
            </div>
            <div>
                <h4 style="color:#94a3b8; margin-bottom:15px;">Confidence Level</h4>
                <div style="font-size: 48px; font-weight:700; color:${isDeepfake ? '#ef4444' : '#22c55e'};">${result.confidence}%</div>
                <div class="confidence-meter">
                    <div class="meter-bar">
                        <div class="meter-fill ${meterClass}" style="width: ${result.confidence}%;"></div>
                    </div>
                    <p style="color:#94a3b8; margin-top:10px;">AI confidence score</p>
                </div>
            </div>
        </div>
        ${extraInfo}
        <div style="margin-top:30px; background:#0f172a; padding:20px; border-radius:16px;">
            <h4 style="margin-bottom:12px; display:flex; align-items:center; gap:8px;">
                <i class="fas fa-microchip" style="color:#38bdf8;"></i> Analysis Details
            </h4>
            <p><strong>Model:</strong> CNN + LSTM (FaceForensics++)</p>
            <p><strong>Decision threshold:</strong> 50%</p>
            <p><strong>Analysis ID:</strong> ${result.analysis_id}</p>
        </div>
    `;
    panel.style.display = 'block';
}

// ========== LOADING ==========
function showLoading(source = 'image') {
    const panel = document.getElementById('resultPanel');
    panel.style.display = 'block';
    document.getElementById('resultBadge').innerText = 'ANALYZING';
    
    let message = '🧠 CNN + LSTM analyzing spatial-temporal features...';
    if (source === 'video') {
        message = '🎬 Processing video frames with CNN + LSTM...';
    } else if (source === 'camera') {
        message = '📸 Capturing and analyzing live frame...';
    }
    
    document.getElementById('resultContent').innerHTML = `
        <div style="text-align:center; padding:40px;">
            <div class="spinner"></div>
            <p style="margin-top:20px; color:#38bdf8;">${message}</p>
        </div>
    `;
}

// ========== REPORTS ==========
async function downloadReport() {
    if (!currentAnalysisId) return;
    window.location.href = `/api/download_report/${currentAnalysisId}`;
}

async function emailReport() {
    if (!currentAnalysisId) return;
    const response = await fetch('/api/send_report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analysis_id: currentAnalysisId })
    });
    const result = await response.json();
    if (result.success) {
        alert('📧 Report sent to your email!');
    } else {
        alert('Error: ' + result.error);
    }
}

// ========== INITIAL BUTTON STATES ==========
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('analyzeImageBtn').disabled = true;
    document.getElementById('analyzeVideoBtn').disabled = true;
});