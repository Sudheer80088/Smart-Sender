from flask import Flask, request, jsonify, session, redirect
from flask_session import Session
import os
import datetime
import json
import google.auth.transport.requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import uuid

app = Flask(__name__)
app.secret_key = "smartemailappsecret"
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Load client_secret.json
GOOGLE_CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri="https://smart-backend.onrender.com/oauth2callback"
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    session['flow'] = flow.credentials_to_dict()
    return jsonify({"auth_url": auth_url})

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri="https://smart-backend.onrender.com/oauth2callback"
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    return "✅ Login successful! You can now close this tab and return to the app."

@app.route("/send_emails", methods=["POST"])
def send_emails():
    if 'credentials' not in session:
        return jsonify({"error": "User not authenticated"}), 401

    creds = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)

    data = request.json
    emails = data.get("emails", [])
    message = data.get("message", "")
    subject = data.get("subject", "Smart Campaign")
    schedule = data.get("schedule", "")

    for e in emails:
        body = message.replace("{First Name}", e["name"])
        email_message = f"To: {e['email']}\r\nSubject: {subject}\r\n\r\n{body}"
        raw_message = {'raw': base64url_encode(email_message)}

        try:
            service.users().messages().send(userId="me", body=raw_message).execute()
        except Exception as err:
            print(f"❌ Failed to send to {e['email']}: {err}")

    return jsonify({"status": "success", "emails_sent": len(emails)})

def credentials_to_dict(creds):
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

def base64url_encode(message):
    import base64
    return base64.urlsafe_b64encode(message.encode("utf-8")).decode("utf-8")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=10000)
