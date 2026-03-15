from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2

# This is the line your editor is looking for!
app = Flask(__name__)
CORS(app)

# =======================================================
# CLOUD DATABASE SETUP (SUPABASE)
# =======================================================
DB_URL = "postgresql://postgres.chzaiuezgmarwjbraobe:Devil100123%21%25@aws-1-ap-northeast-1.pooler.supabase.com:5432/postgres"
def get_db_connection():
    return psycopg2.connect(DB_URL)

# This creates your users table in the cloud automatically
def init_db():
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

# Run the initialization when the server starts
init_db()

# =======================================================
# AUTHENTICATION ROUTES
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
        # Insert the new user into Supabase
        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, password))
        conn.commit()
        return jsonify({"status": "success", "message": "Registered successfully!"})
    
    except psycopg2.errors.UniqueViolation:
        return jsonify({"status": "error", "message": "Email already exists"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Check if the email and password match in Supabase
        cursor.execute("SELECT * FROM users WHERE email=%s AND password=%s", (email, password))
        user = cursor.fetchone()
        
        if user:
            return jsonify({"status": "success", "message": "Login successful!"})
        else:
            return jsonify({"status": "error", "message": "Invalid credentials"})
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    finally:
        cursor.close()
        conn.close()
