🛡️ PhishNet Security Platform & J.A.R.V.I.S. AI

PhishNet is an advanced, Real-Time AI/ML-Based Cybersecurity and Phishing Prevention System. It is designed as an autonomous, multi-vector forensics web platform that allows operators to seamlessly investigate network traffic, analyze malicious files, decode cryptography, and gather threat intelligence.

At the core of the platform is J.A.R.V.I.S., a fully integrated Natural Language Processing (NLP) AI Assistant. J.A.R.V.I.S. features dynamic voice synthesis, multi-language translation, and local memory, allowing operators to execute complex cybersecurity tools using simple conversational commands.

🖥️ System Dashboard

<p align="center">
<img src="/assets/dashboard.png" width="800" alt="PhishNet Autonomous Operations Dashboard">
</p>

✨ Core Features & Modules

The platform is divided into four primary cybersecurity modules, all accessible through a sleek, cyberpunk-inspired graphical user interface.

1. 🌐 Phishing & Threat Intelligence

Real-Time URL Scanning: Analyzes suspicious links for phishing signatures.

Deep IP Forensics: Conducts global threat scans to determine if an IP address is malicious.

Domain Reputation OSINT: Gathers open-source intelligence on target domains.

Secure QR Decoder: Safely extracts payloads from QR codes without executing them.

2. 🖧 Network Utilities

PCAP Packet Forensics: Upload network capture files (.pcap) for Deep Packet Inspection to uncover plaintext credentials and malicious traffic.

Subnet & CIDR Operations: Instant network mapping and subnet calculations.

<p align="center">
<img src="Screenshot 2026-03-07 at 19.47.32.jpg" width="800" alt="PCAP Packet Forensics">
</p>

3. 🔐 Cryptography & Passwords

RSA & AES-256 Engine: Industry-standard encryption and decryption tools.

Base64 & Hex Converters: Rapidly encode or decode hidden payloads.

HIBP Breach Verification: Check if specific passwords have been compromised in global data breaches.

4. 🔬 Forensics Analysis

LSB Image Steganography: Hide or reveal secret text payloads inside image files.

EXIF Metadata Forge: Extract or strip invisible metadata from photographs.

Binary String Extraction: Run a background web-worker to pull human-readable ASCII strings from raw binary malware.

🤖 J.A.R.V.I.S. Artificial Intelligence Node

<p align="center">
<img src="Screenshot 2026-03-14 at 18.34.56.jpg" width="800" alt="J.A.R.V.I.S AI Interface">
</p>

Instead of clicking through menus, operators can launch the J.A.R.V.I.S. Master Intelligence Node.

Conversational Execution: Type commands like "Scan IP 8.8.8.8" or "Check this URL" and J.A.R.V.I.S. will automatically route the payload to the Python backend.

Smart Autodetect: Upload a file to the chat, and J.A.R.V.I.S. will automatically determine the correct forensic protocol (e.g., recognizing a .pcap and running network analysis).

Persistent Voice Memory: Select a custom TTS (Text-to-Speech) voice engine. The platform uses Local Storage to remember your preference for future sessions.

Dynamic Translation: Integrates with Google Translate to dynamically translate terminal output and speak in your native language.

🔒 Secure SOC Authentication

Access to the platform is restricted via a Secure SQLite Database Integration. Operators must register and authenticate through the Python backend before establishing a session.

<p align="center">
<img src="Screenshot 2026-03-15 at 15.13.00.jpg" width="400" alt="Secure SOC Login">
<img src="Screenshot 2026-03-15 at 15.13.24.jpg" width="400" alt="Database Registration">
</p>

🏗️ System Architecture

This project utilizes a modern Edge-to-Microservice Architecture:

The Frontend (UI/UX): Built entirely with HTML5, JavaScript, and Tailwind CSS. It features a dynamic HTML5 Canvas matrix background and glass-morphism panels. It is fully static and designed to be hosted on GitHub Pages.

The Backend (API & Brain): Powered by Python 3 and Flask. The backend handles database routing, natural language intent recognition, and API requests to external threat databases. It utilizes gunicorn for production deployment and is designed to be hosted on cloud services like Render.

👨‍💻 Developer Communications

Engineered & Developed by Girish Wadhwani

If you have questions, encounter roadblocks, or wish to initiate a secure handshake regarding this project, feel free to reach out:

✉️ Email: girishwadhwani1000@gmail.com

📱 WhatsApp: +91 9664380661
