# Email & Slack alert logic

import requests
import streamlit as st

def send_email_alert(ip, tags):
    try:
        requests.post("https://your-mail-service/send", json={"ip": ip, "tags": tags})
    except Exception as e:
        st.error(f"Email alert failed: {e}")

def send_slack_alert(ip, tags):
    try:
        requests.post("https://hooks.slack.com/services/your/slack/hook", json={"text": f"🚨 Alert for {ip}: {', '.join(tags)}"})
    except Exception as e:
        st.error(f"Slack alert failed: {e}")
