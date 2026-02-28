from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import re
import socket
import math

app = Flask(__name__)
CORS(app) # Crucial to allow the HTML file to talk to Python

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "online"})

# A unified endpoint to handle all tool requests from the frontend
@app.route('/api/tool/<tool_code>', methods=['POST'])
def run_tool(tool_code):
    data = request.json
    payload = data.get('payload', '')
    result = ""

    try:
        if tool_code == 'hash':
            md5 = hashlib.md5(payload.encode()).hexdigest()
            sha1 = hashlib.sha1(payload.encode()).hexdigest()
            sha256 = hashlib.sha256(payload.encode()).hexdigest()
            result = f"MD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}"

        elif tool_code == 'url':
            # Phish-Net ML Mock Logic
            score = 5
            if not payload.startswith('https'): score += 20
            if re.search(r'\d+\.\d+\.\d+\.\d+', payload): score += 50
            if len(payload) > 75: score += 15
            score = min(score, 99)
            status = "MALICIOUS" if score > 50 else "CLEAN"
            result = f"URL ANALYZED: {payload}\nTHREAT SCORE: {score}%\nAI CLASSIFICATION: {status}"

        elif tool_code == 'text':
            # Cyber Suite String/IOC extractor
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', payload)
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', payload)
            result = f"FOUND IPs: {', '.join(ips) if ips else 'None'}\nFOUND URLs: {', '.join(urls) if urls else 'None'}"

        elif tool_code == 'pwd_chk':
            # Cyber Suite Password Entropy
            pool = 0
            if any(c.islower() for c in payload): pool += 26
            if any(c.isupper() for c in payload): pool += 26
            if any(c.isdigit() for c in payload): pool += 10
            if any(not c.isalnum() for c in payload): pool += 32
            
            entropy = len(payload) * math.log2(pool) if pool > 0 else 0
            strength = "SECURE" if entropy > 60 else ("MODERATE" if entropy > 40 else "WEAK")
            result = f"ENTROPY: {round(entropy, 2)} Bits\nSTRENGTH: {strength}"

        elif tool_code == 'dns':
            # Cyber Suite DNS Fetcher
            try:
                ip = socket.gethostbyname(payload.replace('https://','').replace('http://','').split('/')[0])
                result = f"A RECORD RESOLVED:\nHOST: {payload}\nIP: {ip}"
            except Exception as e:
                result = f"DNS Resolution Failed: {str(e)}"

        elif tool_code == 'conv_b64':
            import base64
            result = f"BASE64 ENCODED:\n{base64.b64encode(payload.encode()).decode()}"
            
        elif tool_code == 'conv_hex':
            result = f"HEXADECIMAL ENCODED:\n{payload.encode().hex()}"

        else:
            # Fallback for tools that require actual files/heavy processing (PCAP, Stego, EXIF)
            result = f"[BACKEND STUB]\nTool '{tool_code}' endpoint hit successfully.\nPayload received: {payload[:20]}...\nIntegration of heavy external libraries (like scapy or exifread) required for full output."

    except Exception as e:
        result = f"[SERVER ERROR] {str(e)}"

    return jsonify({"status": "success", "result": result})

if __name__ == '__main__':
    print("🚀 Phish-Net x Cyber Suite Backend running on port 5000")
    app.run(debug=True, port=5000)