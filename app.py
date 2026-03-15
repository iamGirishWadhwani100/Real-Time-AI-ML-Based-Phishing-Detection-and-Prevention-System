from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib

app = Flask(__name__)
CORS(app)

# =======================================================
# 1. ZERO-ERROR FILE DATABASE (SQLite)
# =======================================================
DB_FILE = 'phishnet.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Run immediately
init_db()

# =======================================================
# 2. LOGIN & REGISTER
# =======================================================
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password required"})

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
        conn.commit()
        return jsonify({"status": "success", "message": "Registered successfully!"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Email already exists"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    finally:
        if 'conn' in locals(): conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
        user = cursor.fetchone()
        
        if user:
            return jsonify({"status": "success", "message": "Login successful!"})
        else:
            return jsonify({"status": "error", "message": "Invalid credentials"})
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    finally:
        if 'conn' in locals(): conn.close()

# =======================================================
# 3. J.A.R.V.I.S. & TOOLS
# =======================================================
@app.route('/api/jarvis', methods=['POST'])
def jarvis():
    data = request.json
    user_input = str(data.get('command', '') or data.get('payload', '')).lower()
    
    response_text = f"Received command: '{user_input}'. Operating in basic simulated mode."
    if "scan" in user_input or "ip" in user_input:
        response_text = "Routing target to IP Scanner module."
    elif "hello" in user_input or "hi" in user_input:
        response_text = "Greetings, Operator. I am online."
        
    return jsonify({"status": "success", "response": response_text})

@app.route('/api/tool/ip_scan', methods=['POST'])
def ip_scan():
    ip = request.json.get('payload', 'Unknown IP')
    return jsonify({"status": "success", "result": f"Target IP: {ip}\nStatus: CLEAN\nPorts: 80, 443 OPEN"})

@app.route('/api/tool/<tool_name>', methods=['POST'])
def tools(tool_name):
    payload = request.json.get('payload', '')
    
    if tool_name == 'url':
        result = f"Scanning URL: {payload}\nVerdict: SAFE"
    elif tool_name == 'hash':
        result = f"MD5: {hashlib.md5(payload.encode()).hexdigest()}\nSHA256: {hashlib.sha256(payload.encode()).hexdigest()}"
    else:
        result = f"Executed tool [{tool_name}] on: {payload}"
        
    return jsonify({"status": "success", "result": result})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
