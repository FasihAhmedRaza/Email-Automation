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

# Load environment variables
load_dotenv()

# Flask app
app = Flask(__name__)

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
def index():
    # Sort logs by timestamp (newest first)
    sorted_logs = sorted(email_logs, key=lambda x: x.get("timestamp", ""), reverse=True)
    # Pass the current datetime to the template
    return render_template('index.html', email_logs=sorted_logs, current_year=datetime.now().year)

@app.route('/clear_logs', methods=['POST'])
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

if __name__ == '__main__':
    # Start the email checking thread
    email_thread = threading.Thread(target=fetch_and_reply_emails)
    email_thread.daemon = True
    email_thread.start()
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)