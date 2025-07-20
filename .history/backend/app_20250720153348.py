import cx_Oracle
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random
import smtplib
from email.mime.text import MIMEText
import traceback
import requests

# Flask setup
app = Flask(__name__)
CORS(app)

# Oracle DB config
ORACLE_USER = 'punith'
ORACLE_PASSWORD = 'punith123'
ORACLE_DSN = 'localhost/XE'  # Format: hostname/service_name (or SID)

def get_connection():
    return cx_Oracle.connect(ORACLE_USER, ORACLE_PASSWORD, ORACLE_DSN)

# Email config (replace these with your credentials)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465  # SSL port
SMTP_USERNAME = 'chatbotcustomerservice2025@gmail.com'         # Replace with your Gmail
SMTP_PASSWORD = 'gizocbozpzdpvkts'           # Replace with your Gmail App Password

def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_USERNAME
        msg['To'] = to_email

        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, [to_email], msg.as_string())

        print("Email successfully sent.")
        return True
    except Exception as e:
        print("Email sending error:", e)
        traceback.print_exc()
        return False

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        required_fields = ['name', 'dob', 'gender', 'email', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"success": False, "message": f"Missing required field: {field}"}), 400

        name = data['name']
        dob = data['dob']
        gender = data['gender']
        email = data['email']
        password = data['password']
        created_at = datetime.now()

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT email FROM users WHERE email = :email", {'email': email})
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Email already exists"}), 409

        cursor.execute("""
            INSERT INTO users (name, dob, gender, email, password, created_at)
            VALUES (:name, TO_DATE(:dob, 'YYYY-MM-DD'), :gender, :email, :password, :created_at)
        """, {
            'name': name,
            'dob': dob,
            'gender': gender,
            'email': email,
            'password': hashed_password,
            'created_at': created_at
        })
        conn.commit()

        cursor.execute("SELECT id FROM users WHERE email = :email", {'email': email})
        user_id = cursor.fetchone()[0]
        conn.close()

        return jsonify({"success": True, "message": "User registered successfully", "user_id": user_id}), 201
    except Exception:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error occurred"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if 'email' not in data or 'password' not in data:
            return jsonify({"success": False, "message": "Email and password required"}), 400

        email = data['email']
        password = data['password']

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, name, password, role FROM users WHERE email = :email", {'email': email})
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            # role is user[3]
            return jsonify({
                "success": True,
                "message": "Login successful",
                "user": {
                    "id": user[0],
                    "name": user[1],
                    "role": user[3]  # return role in the response
                }
            }), 200
        else:
            return jsonify({"success": False, "message": "Invalid credentials"}), 401
    except Exception:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error occurred"}), 500


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        if 'email' not in data:
            return jsonify({"success": False, "message": "Email required"}), 400

        email = data['email']

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT email FROM users WHERE email = :email", {'email': email})
        user = cursor.fetchone()

        if not user:
            conn.close()
            return jsonify({"success": False, "message": "Email not found"}), 404

        code = f"{random.randint(100000, 999999)}"
        created_at = datetime.now()

        cursor.execute("SELECT email FROM forgot_password_codes WHERE email = :email", {'email': email})
        code_row = cursor.fetchone()

        if code_row:
            cursor.execute("""
                UPDATE forgot_password_codes SET code = :code, created_at = :created_at WHERE email = :email
            """, {'code': code, 'created_at': created_at, 'email': email})
        else:
            cursor.execute("""
                INSERT INTO forgot_password_codes (email, code, created_at) VALUES (:email, :code, :created_at)
            """, {'email': email, 'code': code, 'created_at': created_at})

        conn.commit()
        conn.close()

        # Custom message
        message = f"""
        Hello,

        We received a request to reset your password for the ChatBot account associated with this email.

        🔐 Your reset code is: {code}

        If you didn’t request this, you can safely ignore this email.

        Thanks,
        ChatBot Support Team
        """

        email_sent = send_email(email, "Your Password Reset Code", message)
        if email_sent:
            return jsonify({"success": True, "message": "Reset code sent"}), 200
        else:
            return jsonify({"success": False, "message": "Failed to send email"}), 500

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error occurred"}), 500


@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        required_fields = ['email', 'code', 'new_password']
        for field in required_fields:
            if field not in data or not str(data[field]).strip():
                return jsonify({"success": False, "message": f"Missing field: {field}"}), 400

        email = data['email']
        code = data['code']
        new_password = data['new_password']

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT code FROM forgot_password_codes WHERE email = :email", {'email': email})
        row = cursor.fetchone()

        if not row or row[0] != code:
            conn.close()
            return jsonify({"success": False, "message": "Invalid code"}), 400

        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)

        cursor.execute("UPDATE users SET password = :password WHERE email = :email", {
            'password': hashed_password,
            'email': email
        })

        cursor.execute("DELETE FROM forgot_password_codes WHERE email = :email", {'email': email})

        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Password reset successful"}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error occurred"}), 500
    
@app.route('/api/admin/data', methods=['GET'])
def get_admin_data():
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT email, role, login_time, logout_time FROM users")
        users = [
            {
                "email": row[0],
                "role": row[1],
                "login_time": row[2].strftime('%Y-%m-%d %H:%M:%S') if row[2] else None,
                "logout_time": row[3].strftime('%Y-%m-%d %H:%M:%S') if row[3] else None
            }
            for row in cursor.fetchall()
        ]

        cursor.execute("SELECT email, code, created_at FROM forgot_password_codes")
        codes = [
            {
                "email": row[0],
                "code": row[1],
                "generated_at": row[2] if row[2] else None
            }
            for row in cursor.fetchall()
        ]

        reset_requests = [
            {
                "email": c["email"],
                "requested_at": c["generated_at"]
            }
            for c in codes
        ]

        return jsonify({
            "users": users,
            "reset_requests": reset_requests,
            "codes": codes
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to fetch admin data"}), 500

    

@app.route('/api/admin/delete_user', methods=['POST'])
def delete_user():
    data = request.json
    email = data.get('email')
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE email = :email", {'email': email})
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error'}), 500


@app.route('/api/admin/reset_code', methods=['POST'])
def reset_code():
    data = request.json
    email = data.get('email')
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM forgot_password_codes WHERE email = :email", {'email': email})
        conn.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error'}), 500


@app.route('/api/admin/resend_code', methods=['POST'])
def resend_code():
    data = request.json
    email = data.get('email')
    try:
        code = f"{random.randint(100000, 999999)}"
        created_at = datetime.now()

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            MERGE INTO forgot_password_codes f
            USING (SELECT :email AS email FROM dual) s
            ON (f.email = s.email)
            WHEN MATCHED THEN
              UPDATE SET code = :code, created_at = :created_at
            WHEN NOT MATCHED THEN
              INSERT (email, code, created_at) VALUES (:email, :code, :created_at)
        """, {'email': email, 'code': code, 'created_at': created_at})

        conn.commit()
        conn.close()

        # HTML email message
        message = f"""
        <html>
          <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px; color: #333;">
            <div style="max-width: 600px; margin: auto; background-color: #fff; border-radius: 8px; padding: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
              <h2 style="color: #7c3aed;">Password Reset Code</h2>
              <p>Hi there,</p>
              <p>You recently requested to reset your password. Please use the verification code below to proceed:</p>
              <p style="font-size: 22px; font-weight: bold; color: #10b981; margin: 20px 0;">🔐 {code}</p>
              <p>If you didn’t request this code, you can safely ignore this email.</p>
              <p>Thanks,<br><strong>ChatBot Support Team</strong></p>
            </div>
          </body>
        </html>
        """

        send_email(email, "Your Password Reset Code", message, is_html=True)
        return jsonify({'status': 'resent'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'status': 'error'}), 500


@app.route('/api/chatbot/gemini', methods=['POST'])
def gemini_chatbot():
    try:
        print("Request received")
        data = request.get_json()
        print("Request JSON:", data)

        prompt = data.get('prompt', '').strip()
        if not prompt:
            return jsonify({"success": False, "message": "Prompt is required"}), 400

        GEMINI_API_KEY = "AIzaSyCFkfYSSuCozAuzU9UH70zgVfw4z4QUOUY"
        GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"

        payload = {
            "contents": [
                {
                    "parts": [
                        { "text": prompt }
                    ]
                }
            ]
        }

        headers = {
            "Content-Type": "application/json"
        }

        response = requests.post(GEMINI_URL, json=payload, headers=headers)
        print("Gemini API status code:", response.status_code)
        result = response.json()
        print("Gemini API response:", result)

        try:
            answer = result["candidates"][0]["content"]["parts"][0]["text"]
            return jsonify({"success": True, "response": answer}), 200
        except (KeyError, IndexError) as e:
            print("Failed to parse Gemini response:", e)
            return jsonify({"success": False, "message": "Failed to parse Gemini response"}), 500

    except Exception as e:
        print("Server error:", e)
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error occurred"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
  