from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import hashlib

# Initialize Flask App at the very top
app = Flask(__name__)
CORS(app)

# =======================================================
# 1. CLOUD DATABASE SETUP (SUPABASE)
# =======================================================

# Using your new alphanumeric password
DB_URL = "postgresql://postgres:PhishNet2026@db.chzaiuezgmarwjbraobe.supabase.co:6543/postgres"

def get_db_connection():
    return psycopg2.connect(DB_URL)

# This creates your users table in the cloud automatically
def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
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
        print("Database initialized successfully!")
    except Exception as e:
        print("Database error:", e)

# Run the initialization when the server starts
init_db()

# =======================================================
# 2. AUTHENTICATION ROUTES (Login & Sign Up)
# =======================================================

@app.route('/api/register', methods=['POST'])
def register():
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
# 3. J.A.R.V.I.S. AI CHAT ROUTE
# =======================================================

@app.route('/api/jarvis', methods=['POST'])
def jarvis():
    data = request.json
    # Look for either 'command' or 'payload' depending on how jarvis.html sends it
    user_input = data.get('command', '') or data.get('payload', '')
    user_input = str(user_input).lower()
    
    # A basic simulated AI response logic
    response_text = f"I received your command: '{user_input}'. Unfortunately, my advanced NLP modules were reset, so I am operating in basic simulated mode."
    
    if "scan" in user_input or "ip" in user_input:
        response_text = "Routing target to IP Scanner module. Please use the dashboard for deep packet forensics."
    elif "hello" in user_input or "hi" in user_input:
        response_text = "Greetings, Operator. I am online and ready to assist with network forensics."
    elif "help" in user_input:
        response_text = "I can currently process basic commands. Try using the Dashboard modules for advanced analysis."
        
    return jsonify({"status": "success", "response": response_text})

# =======================================================
# 4. CYBERSECURITY TOOL ROUTES
# =======================================================

@app.route('/api/tool/ip_scan', methods=['POST'])
def ip_scan():
    data = request.json
    ip = data.get('payload', 'Unknown IP')
    
    # Simulated IP Scan Response
    result = f"Target IP: {ip}\nLocation: UNKNOWN\nStatus: CLEAN\nPorts: 80, 443 OPEN"
    return jsonify({"status": "success", "result": result})

@app.route('/api/tool/<tool_name>', methods=['POST'])
def tools(tool_name):
    data = request.json
    payload = data.get('payload', '')
    
    # Simulated responses for your different dashboard tools
    if tool_name == 'url':
        result = f"Scanning URL: {payload}\nVerdict: SAFE (No malicious signatures detected)."
    elif tool_name == 'hash':
        result = f"MD5: {hashlib.md5(payload.encode()).hexdigest()}\nSHA256: {hashlib.sha256(payload.encode()).hexdigest()}"
    elif tool_name == 'domain':
        result = f"Querying domain: {payload}\nStatus: Registered. No blacklisting detected."
    elif tool_name == 'dns':
        result = f"Fetching DNS for {payload}...\nA Record: 192.168.1.1\nMX Record: mail.{payload}"
    else:
        result = f"Executed tool [{tool_name}] on payload: {payload}"
        
    return jsonify({"status": "success", "result": result})

# Start the local server if testing on computer
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
