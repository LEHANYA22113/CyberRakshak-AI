// ============================================
// CyberRakshak AI - Voice Enabled Chatbot
// Client-side with server communication
// ============================================

class CyberChatbot {
    constructor() {
        this.isListening = false;
        this.recognition = null;
        this.synthesis = window.speechSynthesis;
        this.conversationHistory = [];
        this.messageCount = 0;
        
        this.initSpeechRecognition();
        this.initEventListeners();
    }

    // Initialize speech recognition
    initSpeechRecognition() {
        if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
            const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
            this.recognition = new SpeechRecognition();
            this.recognition.continuous = false;
            this.recognition.interimResults = false;
            this.recognition.lang = 'en-US'; // We'll keep English for voice, but backend handles other languages via text
            
            this.recognition.onstart = () => {
                this.isListening = true;
                this.updateMicButton(true);
                this.addMessage("🎤 Listening... Speak now", 'bot');
            };
            
            this.recognition.onend = () => {
                this.isListening = false;
                this.updateMicButton(false);
            };
            
            this.recognition.onresult = (event) => {
                const transcript = event.results[0][0].transcript;
                this.handleVoiceInput(transcript);
            };
            
            this.recognition.onerror = (event) => {
                console.error('Speech error:', event.error);
                this.isListening = false;
                this.updateMicButton(false);
                this.addMessage("❌ Sorry, I couldn't hear you. Please try typing.", 'bot');
            };
        } else {
            console.warn('Speech recognition not supported');
        }
    }

    // Handle voice input
    handleVoiceInput(transcript) {
        console.log('Voice input:', transcript);
        this.addMessage(transcript, 'user');
        this.getBotResponse(transcript);
    }

    // Get bot response from server
    async getBotResponse(userMsg) {
        // Show typing indicator
        const typingId = this.showTypingIndicator();
        
        try {
            const response = await fetch('/api/chatbot', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: userMsg })
            });
            const data = await response.json();
            
            this.removeTypingIndicator(typingId);
            
            if (data.success) {
                this.addMessage(data.response, 'bot');
            } else {
                this.addMessage("Sorry, I couldn't process that. Please try again.", 'bot');
            }
        } catch (error) {
            console.error('Chatbot error:', error);
            this.removeTypingIndicator(typingId);
            this.addMessage("Network error. Please check your connection.", 'bot');
        }
    }

    // Add message to chat (supports HTML)
    addMessage(text, sender) {
        const messagesDiv = document.getElementById('chatMessages');
        const msgDiv = document.createElement('div');
        msgDiv.className = `message ${sender}`;
        
        // Add timestamp
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        // Use innerHTML to render HTML links from server
        msgDiv.innerHTML = `
            <span>${text}</span>
            <small style="display: block; font-size: 10px; opacity: 0.5; margin-top: 4px;">${time}</small>
        `;
        
        messagesDiv.appendChild(msgDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
        
        // Store in history
        this.conversationHistory.push({ sender, text, time });
    }

    // Show typing indicator
    showTypingIndicator() {
        const id = 'typing-' + Date.now();
        const messagesDiv = document.getElementById('chatMessages');
        const typingDiv = document.createElement('div');
        typingDiv.id = id;
        typingDiv.className = 'message bot typing';
        typingDiv.innerHTML = `<span>typing...</span>`;
        messagesDiv.appendChild(typingDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
        return id;
    }

    // Remove typing indicator
    removeTypingIndicator(id) {
        const el = document.getElementById(id);
        if (el) el.remove();
    }

    // Update microphone button UI
    updateMicButton(isListening) {
        const micBtn = document.getElementById('micButton');
        if (micBtn) {
            if (isListening) {
                micBtn.innerHTML = '🎤 🔴';
                micBtn.classList.add('listening');
            } else {
                micBtn.innerHTML = '🎤';
                micBtn.classList.remove('listening');
            }
        }
    }

    // Initialize event listeners
    initEventListeners() {
        // Handle Enter key
        document.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });
    }

    // Send text message
    sendMessage() {
        const input = document.getElementById('chatInput');
        const msg = input.value.trim();
        
        if (!msg) return;
        
        // Clear input
        input.value = '';
        
        // Add user message
        this.addMessage(msg, 'user');
        
        // Get bot response
        this.getBotResponse(msg);
    }

    // Start voice recognition
    startListening() {
        if (this.recognition && !this.isListening) {
            try {
                this.recognition.start();
            } catch (error) {
                console.error('Recognition error:', error);
            }
        } else {
            alert('Voice recognition is not supported in your browser. Please use Chrome or Edge.');
        }
    }

    // Stop voice recognition
    stopListening() {
        if (this.recognition && this.isListening) {
            this.recognition.stop();
        }
    }

    // Toggle chat window
    toggleChat() {
        const container = document.getElementById('chatbotContainer');
        if (container) {
            const isVisible = container.style.display === 'flex';
            container.style.display = isVisible ? 'none' : 'flex';
            
            // Add welcome message if first time
            if (!isVisible && this.conversationHistory.length === 0) {
                setTimeout(() => {
                    this.addMessage("👋 Hello! I'm your CyberRakshak AI assistant. You can type or click the 🎤 button to speak. How can I help you stay safe online today?", 'bot');
                }, 300);
            }
        }
    }
}

// Initialize chatbot when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.chatbot = new CyberChatbot();
});

// Global functions for HTML buttons
function toggleChatbot() {
    if (window.chatbot) {
        window.chatbot.toggleChat();
    }
}

function sendMessage() {
    if (window.chatbot) {
        window.chatbot.sendMessage();
    }
}

function startVoiceInput() {
    if (window.chatbot) {
        window.chatbot.startListening();
    }
}