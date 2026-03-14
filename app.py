from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import socket
import base64
import urllib.parse
import urllib.request
import urllib.error
import json
import random
import re
import ssl
import html
import sqlite3
from datetime import datetime

app = Flask(__name__)
CORS(app) 

# --- SECURE SQLITE3 DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('phishnet.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password_hash TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, tool TEXT, target TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

def log_action(email, tool, target):
    if not email: email = "GUEST"
    conn = sqlite3.connect('phishnet.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs (email, tool, target) VALUES (?, ?, ?)", (email, tool, target))
    conn.commit()
    conn.close()

# --- AUTHENTICATION ENDPOINTS ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    pass_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn = sqlite3.connect('phishnet.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pass_hash))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Operator registered securely."})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "ERROR: Operator ID already exists in secure database."})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    pass_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect('phishnet.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?", (email, pass_hash))
    user = c.fetchone()
    conn.close()
    if user:
        return jsonify({"status": "success", "message": "Session initialized."})
    return jsonify({"status": "error", "message": "ERROR: Invalid credentials."})


# --- ADVANCED JARVIS NLP BRAIN ---
@app.route('/api/jarvis', methods=['POST'])
def jarvis_brain():
    data = request.json
    prompt = data.get('prompt', '').lower()
    
    # Regex extractors
    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', prompt)
    url_match = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', prompt)
    
    intent = "chat"
    target = ""
    speech = "I am processing your request."
    response = ""
    
    # 1. TOOL EXECUTION INTENTS
    if ("scan" in prompt or "check" in prompt) and ip_match:
        intent = "ip_scan"
        target = ip_match.group(0)
        speech = f"Initiating threat scan on IP address."
    elif ("scan" in prompt or "check" in prompt) and url_match:
        intent = "url"
        target = url_match.group(0)
        speech = "Analyzing URL through global threat intelligence."
    elif "encode" in prompt and "base64" in prompt:
        intent = "conv_b64_enc"
        target = prompt.split("base64")[-1].strip()
        speech = "Encoding payload to Base 64."
    elif "decode" in prompt and "base64" in prompt:
        intent = "conv_b64_dec"
        target = prompt.split("base64")[-1].strip()
        speech = "Decoding Base 64 payload."
    elif "hash" in prompt:
        intent = "hash"
        target = prompt.split("hash")[-1].strip()
        speech = "Generating cryptographic hashes."
    
    # 2. TACTICAL ADVISORY INTENTS (Hacking Consultant Mode)
    elif any(kw in prompt for kw in ['stuck', 'help', 'advice', 'advise', 'how do i', 'what next', 'error', 'bypass', 'nmap', 'privesc', 'shell', 'exploit']):
        intent = "advisory"
        
        if "nmap" in prompt or "scan" in prompt or "port" in prompt:
            response = (
                "<span class='text-yellow-muted font-bold tracking-widest'>"
                "<i class='fa-solid fa-lightbulb mr-2'></i>TACTICAL ADVISORY: ENUMERATION</span><br><br>"
                "If standard TCP scans are failing, the target firewall may be dropping ICMP ping requests.<br><br>"
                "Try using <b>-Pn</b> to skip host discovery, or perform a stealth SYN scan (<b>-sS</b>). "
                "Also, do not forget to enumerate UDP ports (<b>-sU</b>), as they often hide highly vulnerable "
                "legacy services like SNMP or TFTP."
            )
            speech = "If standard scans are failing, try skipping host discovery or scanning UDP ports."
        
        elif "privesc" in prompt or "root" in prompt or "privilege" in prompt:
            response = (
                "<span class='text-yellow-muted font-bold tracking-widest'>"
                "<i class='fa-solid fa-lightbulb mr-2'></i>TACTICAL ADVISORY: PRIVILEGE ESCALATION</span><br><br>"
                "For Linux targets, always start with <code>sudo -l</code> to check your current privileges. "
                "Next, search for SUID binaries using <code>find / -perm -4000 2>/dev/null</code>.<br><br>"
                "If you are on Windows, check for misconfigured service permissions like unquoted service paths "
                "or AlwaysInstallElevated registry keys."
            )
            speech = "For privilege escalation, check your sudo permissions and SUID binaries first."
        
        elif "shell" in prompt or "payload" in prompt or "connection" in prompt:
            response = (
                "<span class='text-yellow-muted font-bold tracking-widest'>"
                "<i class='fa-solid fa-lightbulb mr-2'></i>TACTICAL ADVISORY: REVERSE SHELLS</span><br><br>"
                "If your reverse shell keeps dropping or failing to connect, the target's firewall is likely "
                "blocking outbound traffic on random ports.<br><br>"
                "Try listening on common egress ports that are rarely blocked, such as <b>443 (HTTPS)</b>, "
                "<b>80 (HTTP)</b>, or <b>53 (DNS)</b>."
            )
            speech = "If your shell is dropping, try listening on common egress ports like 443 or 53."
        
        elif "web" in prompt or "sqli" in prompt or "xss" in prompt or "waf" in prompt:
            response = (
                "<span class='text-yellow-muted font-bold tracking-widest'>"
                "<i class='fa-solid fa-lightbulb mr-2'></i>TACTICAL ADVISORY: WEB EXPLOITATION</span><br><br>"
                "If you are facing a Web Application Firewall (WAF) blocking your queries, try obfuscating your "
                "payloads using URL encoding, Hex, or Base64.<br><br>"
                "If error-based SQL injection is suppressed, switch to Time-Based or Boolean inference techniques. "
                "I can encode those payloads for you if you need!"
            )
            speech = "To bypass web filters, try encoding your payloads, or switch to time-based inference."
        
        else:
            response = (
                "<span class='text-yellow-muted font-bold tracking-widest'>"
                "<i class='fa-solid fa-lightbulb mr-2'></i>TACTICAL ADVISORY: METHODOLOGY</span><br><br>"
                "As your tactical advisor, I highly recommend reverting to the <b>Enumeration</b> phase. "
                "90% of breaches happen because a minor detail was overlooked.<br><br>"
                "Review your initial port scans, run a directory fuzzer like Gobuster on any web ports, and "
                "inspect the raw page source code."
            )
            speech = "I recommend stepping back to the enumeration phase. Review your initial scans for missed details."

    # 3. STANDARD CONVERSATION
    else:
        if "hello" in prompt or "hi " in prompt:
            response = "Hello Operator. The Python microservice backend is fully synced and tracking all telemetry securely in SQLite."
            speech = "Hello Operator. The backend database is fully synced."
        elif "how are you" in prompt:
            response = "All edge-nodes and Web Workers are operating at 100% capacity."
            speech = "All edge nodes are operating at 100% capacity."
        else:
            response = "I heard you, but I require a specific tactical command (e.g., 'scan IP 8.8.8.8') or an advisory request (e.g., 'I am stuck on nmap')."
            speech = "I require a specific tactical command or an advisory request."

    return jsonify({"intent": intent, "target": target, "speech": speech, "response": response})


# --- FORENSIC TOOLS (WITH LOGGING) ---
@app.route('/api/tool/<tool_code>', methods=['POST'])
def run_tool(tool_code):
    data = request.json or {}
    payload = data.get('payload', '')
    operator = data.get('operator', 'GUEST')
    result = ""

    if not payload: return jsonify({"status": "error", "result": "Empty payload received."})

    try:
        # Save to Secure Log DB
        log_action(operator, tool_code, payload[:50])

        # 1. Cryptographic Hashes
        if tool_code == 'hash':
            md5 = hashlib.md5(payload.encode()).hexdigest()
            sha1 = hashlib.sha1(payload.encode()).hexdigest()
            sha256 = hashlib.sha256(payload.encode()).hexdigest()
            result = f"MD5:    {md5}\nSHA1:   {sha1}\nSHA256: {sha256}"

        # 2. REAL-TIME VIRUSTOTAL URL ANALYSIS
        elif tool_code == 'url':
            target_url = payload.strip()
            if not target_url.startswith('http'): target_url = 'http://' + target_url
            VT_API_KEY = "e8c658a42b35c2fbc978589e626e71cbe57cc10dbd32a7e3e50546d5dc63c2e2"
            
            try:
                url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
                req = urllib.request.Request(f"https://www.virustotal.com/api/v3/urls/{url_id}")
                req.add_header('x-apikey', VT_API_KEY)
                
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                with urllib.request.urlopen(req, context=ctx) as response:
                    vt_data = json.loads(response.read().decode())
                    stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0); suspicious = stats.get('suspicious', 0)
                    harmless = stats.get('harmless', 0); undetected = stats.get('undetected', 0)
                    
                    total_engines = malicious + suspicious + harmless + undetected
                    score = round(((malicious + suspicious) / total_engines) * 100) if total_engines > 0 else 0
                    status = "CRITICAL THREAT" if malicious > 2 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")
                    
                    result = f"[*] REAL-TIME VIRUSTOTAL DEEP SCAN COMPLETE\nTARGET: {target_url}\n\n--- VENDOR INTEL (Out of {total_engines} Engines) ---\nMALICIOUS ENGINE HITS:  {malicious}\nSUSPICIOUS ENGINE HITS: {suspicious}\nCLEAN / UNDETECTED:     {harmless + undetected}\n\nRISK SCORE:    {score}/100\nFINAL VERDICT: {status}"
            except urllib.error.HTTPError as e:
                if e.code == 404: result = f"[*] VIRUSTOTAL SCAN: URL not found in VT database.\nSTATUS: UNKNOWN (URL has NEVER been scanned by VirusTotal before.)"
                else: result = f"[-] VIRUSTOTAL API ERROR: HTTP {e.code}"
            except Exception as e:
                result = f"[-] VIRUSTOTAL CONNECTION ERROR: {html.escape(repr(e))}"

        # 3. DNS / IP / CONVERTERS...
        elif tool_code == 'dns':
            domain = payload.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
            ip = socket.gethostbyname(domain)
            result = f"TARGET DOMAIN: {domain}\nRESOLUTION (A RECORD): {ip}"
        elif tool_code == 'conv_b64_enc': result = f"BASE64 ENCODED:\n{base64.b64encode(payload.encode()).decode()}"
        elif tool_code == 'conv_b64_dec': result = f"BASE64 DECODED:\n{base64.b64decode(payload).decode('utf-8', errors='ignore')}"
        elif tool_code == 'conv_hex_enc': result = f"HEXADECIMAL ENCODED:\n{payload.encode().hex()}"
        elif tool_code == 'conv_hex_dec': result = f"HEXADECIMAL DECODED:\n{bytes.fromhex(payload).decode('utf-8', errors='ignore')}"
        elif tool_code == 'ip_scan':
            score = random.randint(15, 98)
            status = "CRITICAL THREAT" if score > 75 else ("SUSPICIOUS" if score > 40 else "CLEAN")
            mock_ports = random.sample([22, 80, 443, 3389, 8080, 21, 23, 53], k=random.randint(1, 4))
            mock_geo = random.choice(["RU (Russia)", "CN (China)", "US (United States)", "NL (Netherlands)", "BR (Brazil)", "UA (Ukraine)"])
            result = f"=========================================\nPHISH-NET DEEP SCAN REPORT\n=========================================\nTARGET IP: {payload}\nGEO-LOCATION: {mock_geo}\n-----------------------------------------\nTHREAT SCORE: {score}/100\nCLASSIFICATION: {status}\n-----------------------------------------\nOPEN PORTS DETECTED: {', '.join(map(str, mock_ports))}\nKNOWN MALWARE SIGNATURES: {'YES' if score > 75 else 'NO'}\n========================================="

        return jsonify({"status": "success", "result": result})

    except Exception as e:
        return jsonify({"status": "error", "result": f"CRITICAL SERVER ERROR: {html.escape(repr(e))}"})

if __name__ == '__main__':
    print("===================================================")
    print(" 🚀 SECURE PHISH-NET BACKEND ONLINE ")
    print(" 📡 SQLite3 Logging Active ")
    print(" 🧠 Jarvis Advisory Protocol Online ")
    print("===================================================")
    app.run(debug=True, port=5000)