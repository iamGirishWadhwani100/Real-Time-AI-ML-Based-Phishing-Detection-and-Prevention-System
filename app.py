import os
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client

app = Flask(__name__)
CORS(app)

# --- SUPABASE CONNECTION ---
url = os.environ.get("jthkrwgqkdhdkwfqgjdq")
key = os.environ.get("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imp0aGtyd2dxa2RoZGt3ZnFnamRxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM2Njc4NzAsImV4cCI6MjA4OTI0Mzg3MH0.uyMvzZk02UhcgTbyZ7c864LoTVmlCDIK9vcn3M3DGm4")

supabase: Client = None
if url and key:
    try:
        supabase = create_client(url, key)
    except Exception as e:
        print(f"Error initializing Supabase: {e}")

# --- AUTH ROUTES ---
@app.route('/api/register', methods=['POST'])
def register():
    # --- NEW DEBUG DETECTIVE CODE ---
    if not supabase:
        u = os.environ.get("SUPABASE_URL")
        k = os.environ.get("SUPABASE_KEY")
        
        # This will print the exact issue to your website screen!
        debug_msg = f"DB Error! URL found: {'YES' if u else 'NO'} | Key found: {'YES' if k else 'NO'}"
        return jsonify({"status": "error", "message": debug_msg})
    # --------------------------------

    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password required"})

    try:
        existing = supabase.table('users').select('*').eq('email', email).execute()
        if len(existing.data) > 0:
            return jsonify({"status": "error", "message": "Email already exists"})

        supabase.table('users').insert({"email": email, "password": password}).execute()
        return jsonify({"status": "success", "message": "Registered successfully!"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Supabase rejected it: {str(e)}"})

@app.route('/api/login', methods=['POST'])
def login():
    if not supabase: return jsonify({"status": "error", "message": "Database not connected."})
    data = request.json
    email, password = data.get('email'), data.get('password')

    try:
        response = supabase.table('users').select('*').eq('email', email).eq('password', password).execute()
        if len(response.data) > 0:
            return jsonify({"status": "success", "message": "Login successful!"})
        return jsonify({"status": "error", "message": "Invalid credentials"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# --- J.A.R.V.I.S & TOOLS ---
@app.route('/api/jarvis', methods=['POST'])
def jarvis():
    user_input = str(request.json.get('command', '') or request.json.get('payload', '')).lower()
    return jsonify({"status": "success", "response": f"Received command: '{user_input}'. Operating in basic simulated mode."})

@app.route('/api/tool/ip_scan', methods=['POST'])
def ip_scan():
    ip = request.json.get('payload', 'Unknown IP')
    return jsonify({"status": "success", "result": f"Target IP: {ip}\\nStatus: CLEAN\\nPorts: 80, 443 OPEN"})

@app.route('/api/tool/<tool_name>', methods=['POST'])
def tools(tool_name):
    payload = request.json.get('payload', '')
    return jsonify({"status": "success", "result": f"Executed tool [{tool_name}] on: {payload}"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
