CyberRakshak AI is an intelligent, multi‑layered cybersecurity platform designed to protect citizens from modern digital threats like deepfakes, phishing scams, and cyber harassment. With a special focus on women safety and rural accessibility, it combines cutting‑edge machine learning with a user‑centric design to create a safer digital India.

✨ Features
🧠 DefendFace – Detect deepfake images and videos using a hybrid CNN+LSTM model (94.7% accuracy). Supports image upload, video analysis, and live camera capture.

🎣 Phishing Analyzer – Scan URLs, emails, and messages for phishing attempts using TF‑IDF + Random Forest (96% accuracy). Real‑time risk scoring and threat indicators.

🆔 Threat Tracking & NCRP Reporting – Uniquely identify repeat attackers via browser fingerprinting. Calculate risk scores and automatically file mock reports with the National Cybercrime Reporting Portal (NCRP).

🚺 Narishakthi Initiative (Women Safety Hub) – Dedicated page with:

Emergency helplines (clickable phone numbers)

SOS alert simulator

Women‑specific incident reporting (flagged as #WomenSafety)

Inspiring quotes carousel

🤖 Multilingual AI Chatbot – Understands English, Hindi, Tamil, and Telugu. Answers cyber queries, explains features, and navigates users to any page (e.g., "go to defendface").

📱 PWA & QR Code Access – Progressive Web App works offline, installable on phones. QR code provides instant access – perfect for rural areas with limited connectivity.

📊 Threat Intelligence Dashboard – View tracked devices, risk scores, and all filed NCRP reports. Block suspicious sources manually.

📧 Automated Email Reports – Receive detailed analysis reports via email after each scan.

🏗️ Technology Stack
Component	Technology
Backend	Python, Flask, Flask‑SQLAlchemy, Flask‑Login, Flask‑Mail
Frontend	HTML5, CSS3 (custom cyber‑theme), JavaScript, Chart.js
Machine Learning	TensorFlow (CNN), scikit‑learn (TF‑IDF + Random Forest)
Database	SQLite (with automatic schema migrations)
PWA	Service Worker, Web App Manifest
Deployment	Docker, Gunicorn
🚀 Quick Start
Prerequisites
Python 3.10 or higher

pip (Python package manager)

Git (optional, for cloning)

Installation
Clone the repository

bash
git clone https://github.com/yourusername/CyberRakshak-AI.git
cd CyberRakshak-AI
Create a virtual environment (recommended)

bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
Install dependencies

bash
pip install -r requirements.txt
Run the application

bash
python app.py
The app will be available at http://127.0.0.1:5000.

Login with a test account
Register a new user via the web interface, or use:

Email: test@example.com

Password: password123 (if you create it manually – registration is open)

🧪 Testing the Features
DefendFace: Upload any image/video (or use live camera). Mock predictions are deterministic – different files give different results.

Phishing Analyzer: Paste a message. Safe phrases like "hello" give low risk; urgent keywords trigger high risk.

Simulate Threat: On the dashboard, click the red "Simulate Threat" card – it will create a fake deepfake event, increment your device's threat score, and file an NCRP report.

Threat Sources: Visit /threat-sources to see all tracked devices and filed reports. Download NCRP reports as PDF.

Women Safety Hub: Go to /women-safety (or click the Narishakthi card) to explore helplines, SOS demo, and report form.

Chatbot: Click the robot icon, type or speak. Try "go to defendface" in English, Hindi, Tamil, or Telugu.

📁 Project Structure
text
CyberRakshak-AI/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── .gitignore              # Files to exclude from Git
├── Dockerfile              # Docker build instructions
├── docker-compose.yml      # Docker Compose config
├── models/                 # Trained ML models (excluded from Git)
├── static/
│   ├── css/                # Stylesheets
│   ├── js/                 # JavaScript (chatbot, fingerprint, etc.)
│   ├── icons/              # PWA icons
│   └── manifest.json       # PWA manifest
├── templates/              # HTML templates
│   ├── index.html
│   ├── dashboard.html
│   ├── defendface.html
│   ├── phishing.html
│   ├── threat_sources.html
│   ├── women_safety.html
│   ├── login.html
│   ├── register.html
│   ├── report.html
│   └── offline.html
└── temp/                   # Temporary upload folder (excluded)
🌐 Deployment
Using Docker
bash
docker build -t cyberrakshak-ai .
docker run -d -p 5000:5000 -v $(pwd)/instance:/app/instance cyberrakshak-ai
Using Docker Compose
bash
docker-compose up -d --build
🤝 Team
R V Lehanya – Frontend & Integration

Rakstha Reddy S – Backend & ML

Rakshitha N – Dataset Collection

Pavani S – Research & Testing

CyberRakshak AI – Built for a Safer Digital India

📄 License
This project is licensed under the MIT License – see the LICENSE file for details.

🏆 Hackathon
This project was created for the Narishakthi Hackathon to promote women safety, digital inclusion, and AI for social good. We hope it inspires more innovations in cybersecurity and gender equality.

Made with ❤️ by Team CyberRakshak


