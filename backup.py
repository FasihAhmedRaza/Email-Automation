import streamlit as st
import imaplib
import email
from email.header import decode_header
from dotenv import load_dotenv
import os
from openai import OpenAI
import smtplib
from email.mime.text import MIMEText
import pandas as pd
import time

# Load environment variables
load_dotenv()

# Streamlit app ka title
st.title("Auto Email Reply Bot")

# Email credentials
EMAIL = os.getenv("EMAIL_ADDRESS")
PASSWORD = os.getenv("EMAIL_PASSWORD")
IMAP_SERVER = "imap.gmail.com"  # Change if using a different provider
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# OpenAI client setup
openai = OpenAI(api_key=OPENAI_API_KEY)

# Initialize session state for email logs
if "email_logs" not in st.session_state:
    st.session_state.email_logs = []

# Function to fetch and process emails
def fetch_and_reply_emails():
    try:
        # Connect to the email server
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL, PASSWORD)
        mail.select("inbox")  # Select the inbox folder

        # Search for unread emails
        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()

        for email_id in email_ids:
            # Fetch the email
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject = decode_header(msg["Subject"])[0][0]
                    if isinstance(subject, bytes):
                        subject = subject.decode()
                    from_ = msg["From"]
                    email_body = ""

                    # Extract the email body
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == "text/plain":
                                email_body = part.get_payload(decode=True).decode()
                    else:
                        email_body = msg.get_payload(decode=True).decode()

                    # Generate reply using OpenAI
                    def generate_reply(email_body):
                        response = openai.chat.completions.create(
                            model="gpt-3.5-turbo",
                            messages=[
                                {"role": "system", "content": "You are a helpful assistant that replies to emails in a professional and concise manner."},
                                {"role": "user", "content": f"Reply to this email: {email_body}"}
                            ]
                        )
                        return response.choices[0].message.content

                    reply = generate_reply(email_body)

                    # Send the reply
                    def send_reply(to_email, subject, body):
                        msg = MIMEText(body)
                        msg["Subject"] = f"Re: {subject}"
                        msg["From"] = EMAIL
                        msg["To"] = to_email

                        with smtplib.SMTP("smtp.gmail.com", 587) as server:
                            server.starttls()
                            server.login(EMAIL, PASSWORD)
                            server.sendmail(EMAIL, [to_email], msg.as_string())

                    send_reply(from_, subject, reply)

                    # Log the email and reply
                    st.session_state.email_logs.append({
                        "From": from_,
                        "Subject": subject,
                        "Body": email_body,
                        "Reply": reply
                    })

    except Exception as e:
        st.error(f"An error occurred: {e}")

# Streamlit UI to display email logs
st.header("Email Logs")

# Button to manually fetch and process emails
if st.button("Fetch and Process Emails"):
    fetch_and_reply_emails()
    st.success("Emails fetched and processed successfully!")

# Display email logs
if st.session_state.email_logs:
    st.subheader("All Email Logs")
    logs_df = pd.DataFrame(st.session_state.email_logs)
    st.table(logs_df)  # Display logs in a table format
else:
    st.write("No emails processed yet.")

# Automatically rerun the app every 5 minutes
time.sleep(300)  # 5 minutes (300 seconds)
st.rerun()


# # 
# <!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">
#     <meta name="viewport" content="width=device-width, initial-scale=1.0">
#     <title>Email Automation Bot</title>
#     <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
#     <meta http-equiv="refresh" content="60">
# </head>
# <body>
#     <div class="container">
#         <header>
#             <h1>Email Automation Bot</h1>
#             <div class="status-bar">
#                 Auto-refreshes every minute
#             </div>
#         </header>
        
#         <section class="controls">
#             <h2>Email Logs</h2>
#             <div class="actions">
#                 <form action="{{ url_for('clear_logs') }}" method="post">
#                     <button type="submit" class="btn danger">Clear All Logs</button>
#                 </form>
#             </div>
#         </section>
        
#         <section class="logs">
#             {% if email_logs %}
#             <p class="log-count">Showing {{ email_logs|length }} email(s)</p>
#             <div class="table-container">
#                 <table>
#                     <thead>
#                         <tr>
#                             <th>Time</th>
#                             <th>From</th>
#                             <th>Subject</th>
#                             <th>Email Content</th>
#                             <th>AI Reply</th>
#                         </tr>
#                     </thead>
#                     <tbody>
#                         {% for log in email_logs %}
#                         <tr>
#                             <td>{{ log.get('timestamp', 'N/A') }}</td>
#                             <td>{{ log.get('from', 'N/A') }}</td>
#                             <td>{{ log.get('subject', 'N/A') }}</td>
#                             <td class="email-content">
#                                 <div class="content-wrapper">
#                                     {{ log.get('body', 'N/A') }}
#                                 </div>
#                             </td>
#                             <td class="reply-content">
#                                 <div class="content-wrapper">
#                                     {{ log.get('reply', 'N/A') }}
#                                 </div>
#                             </td>
#                         </tr>
#                         {% endfor %}
#                     </tbody>
#                 </table>
#             </div>
#             {% else %}
#             <div class="empty-state">
#                 <p>No emails processed yet.</p>
#                 <p class="info">The bot is running in the background and checking for new emails every minute.</p>
#             </div>
#             {% endif %}
#         </section>
        
#         <footer>
#             <p>Email Automation Bot &copy; {{ current_year }}</p>
#         </footer>
#     </div>
# </body>
# </html>


# 