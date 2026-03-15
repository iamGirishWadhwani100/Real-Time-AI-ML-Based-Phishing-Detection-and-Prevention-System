import os
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2

app = Flask(__name__)
CORS(app)

# =======================================================
# 1. VERCEL & NEON POSTGRES DATABASE SETUP
# =======================================================
def get_db_connection():
    # Vercel and Neon automatically inject DATABASE_URL in the background
    db_url = os.environ.get('DATABASE_URL')
    
    if not db_url:
        raise Exception("Database URL not found! Make sure Neon is connected to the Vercel project.")
    
    # Python's database drivers require 'postgresql://' instead of 'postgres://'
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
        
    return psycopg2.connect(db_url)

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Create the users table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            )
        ''')
        conn.commit()
        cursor.close()
        conn.close()
        print("Neon Database initialized successfully!")
    except Exception as e:
        print("Database error during initialization:", e)

# Run initialization
init_db()

# =======================================================
# 2. AUTHENTICATION ROUTES (Login & Sign Up)
# =======================================================
@app.route('/api/register', methods=['POST'])
def register():
    # Double-checking the table exists just in case
    init_db() 
    
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password required"})

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, password))
        conn.commit()
        return jsonify({"status": "success", "message": "Registered successfully!"})
    except psycopg2.errors.UniqueViolation:
        return jsonify({"status": "error", "message": "Email already exists"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s AND password=%s", (email, password))
        user = cursor.fetchone()
        
        if user:
            return jsonify({"status": "success", "message": "Login successful!"})
        else:
            return jsonify({"status": "error", "message": "Invalid credentials"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# =======================================================
# 3. J.A.R.V.I.S. & CYBERSECURITY TOOLS
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

# Used for local testing, Vercel ignores this
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
