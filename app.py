from flask import Flask, render_template, request, redirect, url_for, jsonify
from dotenv import load_dotenv
import os
import imaplib
import email
from email.header import decode_header
from openai import OpenAI
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time
import json
from datetime import datetime

#login
# Step 1: Add necessary imports at the top of app.py
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import re
from cryptography.fernet import Fernet
import base64




# Load environment variables
load_dotenv()

# Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "generate-a-secure-random-key")  # Use environment variable in production

# Email credentials
EMAIL = os.getenv("EMAIL_ADDRESS")
PASSWORD = os.getenv("EMAIL_PASSWORD")
IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")  # Default to Gmail
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")  # Default to Gmail
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))  # Default port for TLS
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# OpenAI client setup
client = OpenAI(api_key=OPENAI_API_KEY)

# Email logs storage
LOG_FILE = "email_logs.json"

# Keep track of emails we've already processed
processed_emails = set()


# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Step 3: Create a User model
class User(UserMixin):
    def __init__(self, id, username, password_hash, email, role):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.role = role  # 'admin' or 'viewer'
        
# Step 4: Create a user database (in a real app, you'd use a database)
# Add this after the User class
users = {
    '1': User('1', 'admin', generate_password_hash('admin_password'), os.getenv("ADMIN_EMAIL", "admin@example.com"), 'admin'),
    '2': User('2', 'viewer', generate_password_hash('viewer_password'), "viewer@example.com", 'viewer')
}

# Step 5: User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Step 6: Setup encryption for sensitive data
# Generate a key for encryption (in production, store this securely)
def generate_key():
    return base64.urlsafe_b64encode(os.urandom(32))

# In production, load this from environment or secure storage
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """Encrypt sensitive data"""
    if not data:
        return ""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    if not encrypted_data:
        return ""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        return "[Decryption failed]"
    
# Step 7: Add spam detection function
def is_spam(subject, body, sender):
    """Detect potential spam emails"""
    # Check for common spam keywords
    spam_keywords = ["viagra", "lottery", "winner", "millions", "prince", "inheritance", 
                     "bitcoin", "cryptocurrency", "urgent payment", "money transfer"]
    
    # Convert to lowercase for case-insensitive matching
    subject_lower = subject.lower()
    body_lower = body.lower()
    
    # Check for spam keywords
    if any(keyword in subject_lower or keyword in body_lower for keyword in spam_keywords):
        return True
    
    # Check for excessive capitalization (spam indicator)
    if len(subject) > 10:  # Only check if subject is long enough
        caps_ratio = sum(1 for c in subject if c.isupper()) / len(subject)
        if caps_ratio > 0.5:  # If more than 50% is uppercase
            return True
    
    # Check for excessive exclamation marks or question marks
    if subject.count('!') > 3 or subject.count('?') > 3:
        return True
    
    # Check for suspicious sender patterns
    suspicious_domains = ["xyz.com", "temp-mail.org", "guerrillamail.com", "mailinator.com"]
    if any(domain in sender.lower() for domain in suspicious_domains):
        return True
        
    # Check for suspicious URL patterns
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', body)
    suspicious_url_patterns = ["bit.ly", "goo.gl", "tinyurl", "click.here", "free", "offer"]
    if any(pattern in url.lower() for url in urls for pattern in suspicious_url_patterns):
        return True
    
    return False


# Step 8: Add login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Simple brute force protection
        if not hasattr(app, 'login_attempts'):
            app.login_attempts = {}
        
        # Get client IP
        ip = request.remote_addr
        current_time = time.time()
        
        # Check if IP is blocked
        if ip in app.login_attempts:
            attempts, last_attempt_time = app.login_attempts[ip]
            
            # Reset attempts if more than 30 minutes have passed
            if current_time - last_attempt_time > 1800:
                app.login_attempts[ip] = (0, current_time)
            elif attempts >= 5:
                return render_template('login.html', error='Too many failed attempts. Try again later.')
        
        # Check credentials
        user_found = False
        for user_id, user in users.items():
            if user.username == username and check_password_hash(user.password_hash, password):
                login_user(user)
                
                # Reset login attempts on successful login
                if ip in app.login_attempts:
                    app.login_attempts[ip] = (0, current_time)
                
                return redirect(url_for('index'))
        
        # Increment failed attempts
        if ip in app.login_attempts:
            attempts, _ = app.login_attempts[ip]
            app.login_attempts[ip] = (attempts + 1, current_time)
        else:
            app.login_attempts[ip] = (1, current_time)
        
        return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')


# Step 9: Add logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Step 10: Add role-based access control
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Load existing logs from file if it exists
def load_logs():
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
                # Load processed emails from the logs
                global processed_emails
                for log in logs:
                    if 'message_id' in log:
                        processed_emails.add(log['message_id'])
                return logs
        return []
    except Exception as e:
        print(f"Error loading logs: {e}")
        return []

# Save logs to file
def save_logs(logs):
    try:
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"Error saving logs: {e}")

# Global variable to store email logs
email_logs = load_logs()

# Flag to control the background thread
running = True

def extract_email_address(from_header):
    """Extract email address from From header"""
    import re
    match = re.search(r'<(.+?)>', from_header)
    if match:
        return match.group(1)
    return from_header

def decode_email_body(msg):
    """Extract the email body from a message"""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            # Skip attachments
            if "attachment" in content_disposition:
                continue
                
            if content_type == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode()
                    return body
                except:
                    pass
            elif content_type == "text/html":
                try:
                    body = part.get_payload(decode=True).decode()
                    return body
                except:
                    pass
    else:
        # Not multipart - get payload directly
        try:
            body = msg.get_payload(decode=True).decode()
            return body
        except:
            return "Could not decode email body"
    
    return "No readable content found"

def fetch_and_reply_emails():
    global email_logs
    global running
    global processed_emails
    
    while running:
        try:
            print(f"[{datetime.now()}] Connecting to the email server...")
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL, PASSWORD)
            print(f"[{datetime.now()}] Logged in successfully.")
            mail.select("inbox")  # Select the inbox folder
            
            # Search for unread emails
            status, messages = mail.search(None, "UNSEEN")
            email_ids = messages[0].split()
            print(f"[{datetime.now()}] Found {len(email_ids)} unread emails.")

            for email_id in email_ids:
                try:
                    print(f"[{datetime.now()}] Processing email ID: {email_id.decode()}")
                    status, msg_data = mail.fetch(email_id, "(RFC822)")
                    
                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            
                            # Get the Message-ID to track if we've already processed this email
                            message_id = msg.get("Message-ID", "")
                            
                            # Skip if we've already processed this email
                            if message_id in processed_emails:
                                print(f"[{datetime.now()}] Skipping already processed email: {message_id}")
                                continue
                                
                            # Add to processed emails set
                            processed_emails.add(message_id)
                            
                            subject = decode_header(msg["Subject"])[0][0]
                            if isinstance(subject, bytes):
                                subject = subject.decode()
                            from_header = msg["From"]
                            from_email = extract_email_address(from_header)
                            
                            # Skip if the email is from ourselves
                            if EMAIL.lower() in from_email.lower():
                                print(f"[{datetime.now()}] Skipping email from ourselves: {from_email}")
                                continue
                            
                            # Extract the email body
                            email_body = decode_email_body(msg)
                            
                            print(f"[{datetime.now()}] Email from: {from_header}, Subject: {subject}")
                            
                                # Check if the email is spam


                            # Generate reply using OpenAI
                            print(f"[{datetime.now()}] Generating reply using OpenAI...")
                            response = client.chat.completions.create(
                                model="gpt-3.5-turbo",
                                messages=[
                                    {"role": "system", "content": "You are a helpful assistant that replies to emails in a professional and concise manner. Keep your responses friendly but brief."},
                                    {"role": "user", "content": f"Reply to this email professionally. Subject: {subject}\n\nEmail content: {email_body}\n\nSign as 'AI Assistant'"}
                                ]
                            )
                            reply = response.choices[0].message.content
                            print(f"[{datetime.now()}] Generated reply: {reply[:100]}...")

                            # Send the reply
                            print(f"[{datetime.now()}] Sending reply to: {from_email}")
                            msg_reply = MIMEMultipart()
                            msg_reply["Subject"] = f"Re: {subject}"
                            msg_reply["From"] = EMAIL
                            msg_reply["To"] = from_email
                            msg_reply["In-Reply-To"] = message_id
                            msg_reply["References"] = message_id
                            
                            msg_reply.attach(MIMEText(reply, "plain"))

                            try:
                                with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                                    server.starttls()
                                    server.login(EMAIL, PASSWORD)
                                    server.sendmail(EMAIL, [from_email], msg_reply.as_string())
                                    print(f"[{datetime.now()}] Reply sent successfully.")
                                    
                                    # Log the email and reply with timestamp
                                    log_entry = {
                                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                        "from": from_header,
                                        "subject": subject,
                                        "message_id": message_id,  # Store the message ID for deduplication
                                        "body": email_body[:500] + ("..." if len(email_body) > 500 else ""),  # Truncate long emails
                                        "reply": reply
                                    }
                                    email_logs.append(log_entry)
                                    save_logs(email_logs)  # Save logs after each successful reply
                                    print(f"[{datetime.now()}] Email logged successfully.")
                            except Exception as e:
                                print(f"[{datetime.now()}] Error sending email: {e}")
                except Exception as e:
                    print(f"[{datetime.now()}] Error processing email: {e}")
            
            # Close the connection
            mail.close()
            mail.logout()
                
        except Exception as e:
            print(f"[{datetime.now()}] An error occurred in email fetching loop: {e}")

        # Wait before checking again
        print(f"[{datetime.now()}] Waiting 60 seconds before next check...")
        time.sleep(60)  # Check every minute

# Routes
@app.route('/')
@login_required
def index():
    # Sort logs by timestamp (newest first)
    sorted_logs = sorted(email_logs, key=lambda x: x.get("timestamp", ""), reverse=True)
    # Pass the current datetime to the template
    return render_template('index.html', email_logs=sorted_logs, current_year=datetime.now().year)
    # Decrypt sensitive data for display
    decrypted_logs = []
    for log in email_logs:
        decrypted_log = log.copy()
        if 'body' in log:
            try:
                decrypted_log['body'] = decrypt_data(log['body'])
            except:
                decrypted_log['body'] = "[Encrypted]"
        if 'reply' in log:
            try:
                decrypted_log['reply'] = decrypt_data(log['reply'])
            except:
                decrypted_log['reply'] = "[Encrypted]"
        decrypted_logs.append(decrypted_log)
    
    return render_template('index.html', email_logs=decrypted_logs, current_year=datetime.now().year)


@app.route('/clear_logs', methods=['POST'])
# @admin_required  # Only admins can clear logs
def clear_logs():
    global email_logs
    global processed_emails
    email_logs = []
    processed_emails = set()  # Reset processed emails too
    save_logs(email_logs)
    return redirect(url_for('index'))

@app.route('/status')
def status():
    return jsonify({
        "status": "running",
        "email_count": len(email_logs),
        "processed_count": len(processed_emails),
        "last_check": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
#Step 13: Add a new route for changing passwords
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not old_password or not new_password or not confirm_password:
            return render_template('change_password.html', error='All fields are required')
        
        if new_password != confirm_password:
            return render_template('change_password.html', error='New passwords do not match')
        
        # Check password strength
        if len(new_password) < 8:
            return render_template('change_password.html', error='Password must be at least 8 characters')
        
        if not re.search(r'[A-Z]', new_password) or not re.search(r'[a-z]', new_password) or not re.search(r'[0-9]', new_password):
            return render_template('change_password.html', error='Password must contain uppercase, lowercase, and numbers')
        
        # Verify old password
        if not check_password_hash(current_user.password_hash, old_password):
            return render_template('change_password.html', error='Current password is incorrect')
        
        # Update password
        current_user.password_hash = generate_password_hash(new_password)
        users[current_user.id] = current_user
        
        return redirect(url_for('index'))
    
    return render_template('change_password.html')

if __name__ == '__main__':
    # Start the email checking thread
    email_thread = threading.Thread(target=fetch_and_reply_emails)
    email_thread.daemon = True
    email_thread.start()
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)