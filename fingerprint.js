// static/js/fingerprint.js
class CyberFingerprint {
    constructor() {
        this.fingerprint = null;
        this.fingerprintId = null;
    }

    async generateFingerprint() {
        const components = {
            ua: navigator.userAgent,
            lang: navigator.language,
            screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            cores: navigator.hardwareConcurrency || 'unknown',
            touch: navigator.maxTouchPoints || 0,
            canvas: this.getCanvasFingerprint(),
            timestamp: Date.now(),
            rand: Math.random()
        };
        const str = JSON.stringify(components);
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash = hash & hash;
        }
        this.fingerprint = Math.abs(hash).toString(36);
        this.fingerprintId = this.fingerprint.substring(0, 8);
        return this.fingerprint;
    }

    getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 100;
            canvas.height = 30;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#38bdf8';
            ctx.fillRect(0, 0, 50, 30);
            ctx.fillStyle = '#ef4444';
            ctx.fillRect(50, 0, 50, 30);
            return canvas.toDataURL().slice(-20);
        } catch (e) {
            return 'canvas-error';
        }
    }

    async trackEvent(eventType, eventData = {}) {
        if (!this.fingerprint) await this.generateFingerprint();
        try {
            const response = await fetch('/api/track-event', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    fingerprint: this.fingerprint,
                    fingerprintId: this.fingerprintId,
                    eventType: eventType,
                    eventData: eventData,
                    url: window.location.href,
                    userEmail: window.currentUserEmail || 'anonymous'
                })
            });
            return await response.json();
        } catch (e) {
            console.error('Tracking error:', e);
            return null;
        }
    }
}

window.cyberFingerprint = new CyberFingerprint();

document.addEventListener('DOMContentLoaded', async () => {
    await window.cyberFingerprint.generateFingerprint();
    // Override fetch to include fingerprint headers automatically
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        options.headers = options.headers || {};
        options.headers['X-Fingerprint'] = window.cyberFingerprint.fingerprint;
        options.headers['X-Fingerprint-ID'] = window.cyberFingerprint.fingerprintId;
        return originalFetch(url, options);
    };
    window.cyberFingerprint.trackEvent('page_view');
});