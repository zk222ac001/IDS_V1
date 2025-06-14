# alerting.py:  Send alerts via Slack, email, and HTTP API when suspicious activity is detected.
import requests #  Used for HTTP POST (to Slack and API endpoint).
import smtplib # Sends email using an SMTP server.
from email.mime.text import MIMEText # Formats the email message body.
import json #Formats payloads for Slack/API as JSON.
import time

# Customize
# Slack Incoming Webhook URL (needs to be created in Slack).
SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/XXXX/YYYY/ZZZZ'
EMAIL_FROM = 'ids@yourdomain.com' # Sender address for IDS alert emails.
EMAIL_TO = ['you@example.com'] # List of recipients for email alerts.
SMTP_SERVER = 'smtp.yourdomain.com' # Your organization's SMTP server hostname or IP.
API_ALERT_ENDPOINT = 'http://localhost:8000/api/alert' # HTTP endpoint that receives alert JSON (useful for integration with dashboards, SIEMs, etc.).

# Sends a plain text message to a Slack channel via Webhook.
def send_slack_alert(message):
    try:
        payload = {'text': message}
        requests.post(SLACK_WEBHOOK_URL, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
    except Exception as e:
        print(f"Slack alert error: {e}")

# Email Alert Function
def send_email_alert(subject, message):
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = ", ".join(EMAIL_TO)
        with smtplib.SMTP(SMTP_SERVER) as server:
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
    except Exception as e:
        print(f"Email alert error: {e}")

# 🌐 API Alert Function
def send_api_alert(data):
    try:
        requests.post(API_ALERT_ENDPOINT, json=data)
    except Exception as e:
        print(f"API alert error: {e}")

# 🚨 Main Alert Dispatcher
def alert(flow):
    # Build message
    message = (
    f"🚨 Suspicious Flow Detected 🚨\n"
    f"Source IP: {flow['src_ip']}\n"
    f"Destination IP: {flow['dst_ip']}\n"
    f"Protocol: {flow['protocol']}\n"
    f"Packet Count: {flow['packet_count']}\n"
    f"Total Size: {flow['total_size']} bytes\n"
    f"Timestamp: {time.ctime(flow['timestamp'])}"
)
    
   # Slack & Email -- Enable later on ----------------------------------------------   
    send_slack_alert(message)
    send_email_alert("IDS ALERT: Suspicious Flow", message)
    send_api_alert(flow)
