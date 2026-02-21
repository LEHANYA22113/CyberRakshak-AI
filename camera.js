// static/js/camera.js
let cameraStream = null;

function startCamera() {
    const video = document.getElementById('camera');
    
    // Check if browser supports getUserMedia
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert('❌ Your browser does not support camera access. Try Chrome, Edge, or Firefox.');
        return;
    }

    // Check if page is served over HTTPS or localhost
    if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
        alert('⚠️ Camera requires HTTPS or localhost.\n\nOpen this page using:\nhttp://127.0.0.1:5000/defendface');
        return;
    }

    // Stop any existing stream
    if (cameraStream) {
        cameraStream.getTracks().forEach(track => track.stop());
        cameraStream = null;
    }

    // Request camera access
    navigator.mediaDevices.getUserMedia({ video: true, audio: false })
        .then(stream => {
            cameraStream = stream;
            video.srcObject = stream;
            video.play();
            console.log('✅ Camera started');
        })
        .catch(err => {
            console.error('Camera error:', err);
            if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
                alert('❌ Camera access denied. Please allow camera permissions in your browser settings.');
            } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
                alert('❌ No camera found on this device.');
            } else if (err.name === 'NotReadableError' || err.name === 'TrackStartError') {
                alert('❌ Camera is already in use by another application.');
            } else {
                alert('❌ Could not access camera: ' + err.message);
            }
        });
}

// Optional: Stop camera when leaving the page (good practice)
window.addEventListener('beforeunload', function() {
    if (cameraStream) {
        cameraStream.getTracks().forEach(track => track.stop());
    }
});